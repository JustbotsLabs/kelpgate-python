"""A stand-in for the Kelpgate API and its token endpoint, plus helpers to run each test with both clients.

The marker ``MOCK-MALWARE`` inside a file makes the mock answer "infected". The real EICAR string is never
written into this repository.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import inspect
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

import httpx
import pytest

from kelpgate import AsyncKelpgateClient, KelpgateClient

API = "https://api.example.test"
TOKEN = "https://auth.example.test/oauth2/token"


class MockApi:
    def __init__(self, token_ttl: int = 3600) -> None:
        self.token_ttl = token_ttl
        self.token_calls = 0
        self.api_calls = 0
        self.valid_token: Optional[str] = None
        self.requests: List[httpx.Request] = []
        #: items are (status, body, headers) or an exception to raise
        self.fail_next: List[Union[tuple, Exception]] = []
        self.async_polls = 0
        self.poll_until = 3

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    @staticmethod
    def json(status: int, body: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> httpx.Response:
        return httpx.Response(status, json=body, headers={"x-request-id": "req-test", **(headers or {})})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        auth = request.headers.get("authorization", "")
        if str(request.url) == TOKEN:
            self.token_calls += 1
            want = "Basic " + base64.b64encode(b"id1:secret1").decode()
            if auth != want:
                return self.json(401, {"error": "invalid_client"})
            self.valid_token = f"tok-{self.token_calls}"
            return self.json(
                200, {"access_token": self.valid_token, "token_type": "bearer", "expires_in": self.token_ttl}
            )
        if path == "/api/v1/health":
            return self.json(200, {"status": "ok", "signature_version": "v-test"})

        self.api_calls += 1
        if self.fail_next:
            item = self.fail_next.pop(0)
            if isinstance(item, Exception):
                raise item
            status, body, headers = item
            return self.json(status, body, headers)
        if auth not in (f"Bearer {self.valid_token}", "Bearer static"):
            return self.json(401, {"error": "unauthorized"})

        body = request.content
        infected = b"MOCK-MALWARE" in body

        def verdict(filename: str) -> httpx.Response:
            return self.json(
                406 if infected else 200,
                {
                    "av-status": "INFECTED" if infected else "CLEAN",
                    "av-signature": "Mock.Test.Signature" if infected else "OK",
                    "av-timestamp": "2026-01-01T00:00:00Z",
                    "sha256": "abc123",
                    "scan_id": "scan-1",
                    "filename": filename,
                    "rule_authors": ["Example Author"] if infected else [],
                },
            )

        if path in ("/api/v1/scan/file", "/api/v1/async-scan/file") and request.method == "POST":
            m = re.search(rb'filename="([^"]*)"', body)
            name = m.group(1).decode() if m else ""
            if "async" in path:
                return self.json(202, {"scan_id": "scan-1", "filename": name})
            return verdict(name)
        if path in ("/api/v1/scan/url", "/api/v1/async-scan/url") and request.method == "POST":
            if "async" in path:
                return self.json(202, {"scan_id": "scan-2"})
            return verdict("remote.bin")
        if path.startswith("/api/v1/async-scan/") and request.method == "GET":
            self.async_polls += 1
            if self.async_polls < self.poll_until:
                return self.json(202, {"av-status": "PROCESSING", "scan_id": "scan-1"})
            return verdict("a.txt")
        return self.json(404, {"error": "not found"})


@pytest.fixture
def api() -> MockApi:
    return MockApi()


def options(**extra: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "token_url": TOKEN,
        "client_id": "id1",
        "client_secret": "secret1",
        "retry_delay": 0.001,
    }
    base.update(extra)
    return base


async def call(value: Any) -> Any:
    """Await ``value`` if it is awaitable (the async client), otherwise return it (the sync client)."""
    return await value if inspect.isawaitable(value) else value


def both(fn: Callable[..., Awaitable[None]]) -> Callable[..., None]:
    """Run a test once with the sync client and once with the async client.

    The test is ``async def test(make, api)``. ``make(**options)`` builds a client; every call on it goes
    through ``await call(...)``.
    """

    @pytest.mark.parametrize("kind", ["sync", "async"])
    @functools.wraps(fn)
    def wrapper(kind: str, api: MockApi) -> None:
        async def main() -> None:
            made: List[Any] = []

            def make(url: str = API, **kw: Any) -> Any:
                kw.setdefault("transport", api.transport())
                client = (KelpgateClient if kind == "sync" else AsyncKelpgateClient)(url, **kw)
                made.append(client)
                return client

            try:
                await fn(make, api)
            finally:
                for c in made:
                    await call(c.close() if kind == "sync" else c.aclose())

        asyncio.run(main())

    # pytest must not try to inject fn's own parameters
    wrapper.__signature__ = inspect.Signature(  # type: ignore[attr-defined]
        [
            inspect.Parameter("kind", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            inspect.Parameter("api", inspect.Parameter.POSITIONAL_OR_KEYWORD),
        ]
    )
    return wrapper
