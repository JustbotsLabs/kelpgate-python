"""The asyncio client. Same behavior as :class:`kelpgate.KelpgateClient`, with ``await``."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, Mapping, Optional, Union
from urllib.parse import quote

import httpx

from ._common import (
    REFRESH_AHEAD,
    RETRY_STATUSES,
    Config,
    PreparedUpload,
    Source,
    accepted_outcome,
    backoff_delay,
    basic_auth_header,
    build_config,
    env_options,
    health_outcome,
    parse_json,
    parse_token,
    poll_outcome,
    prepare_upload,
    request_id_of,
    resolve_idempotency_key,
    scan_outcome,
)
from ._errors import KelpgateError, NetworkError, RequestTimeout
from ._models import AcceptedScan, Health, PendingScan, ScanResult


class AsyncKelpgateClient:
    """Asyncio client for the Kelpgate malware-scanning API.

    Arguments are the same as :class:`kelpgate.KelpgateClient`.

    Use it as ``async with AsyncKelpgateClient(...) as kg:`` or call :meth:`aclose` when you are done.
    """

    def __init__(
        self,
        api_url: str,
        *,
        token_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        bearer_token: Optional[str] = None,
        scope: str = "scan",
        timeout: float = 60.0,
        max_retries: int = 2,
        retry_delay: float = 0.5,
        max_bytes: Optional[int] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        opts: Dict[str, Any] = {}
        if max_bytes is not None:
            opts["max_bytes"] = max_bytes
        self._cfg: Config = build_config(
            api_url=api_url,
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            bearer_token=bearer_token,
            scope=scope,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            **opts,
        )
        self._http = httpx.AsyncClient(timeout=timeout, transport=transport, follow_redirects=False)
        self._lock: Optional[asyncio.Lock] = None  # created on first use, inside the running loop
        self._token: Optional[str] = None
        self._expires_at = 0.0

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, **overrides: Any) -> AsyncKelpgateClient:
        """Build a client from ``KELPGATE_*`` environment variables, like ``KelpgateClient.from_env``."""
        opts = env_options(env)
        opts.update(overrides)
        return cls(**opts)

    def __repr__(self) -> str:
        return f"AsyncKelpgateClient(api_url={self._cfg.api_url!r})"

    async def __aenter__(self) -> AsyncKelpgateClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Release the underlying connections."""
        await self._http.aclose()

    # ---- authentication

    async def _access_token(self, force: bool = False) -> str:
        if self._cfg.bearer_token:
            return self._cfg.bearer_token
        if not force and self._token and self._expires_at - time.monotonic() > REFRESH_AHEAD:
            return self._token
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:  # one renewal at a time; concurrent callers wait, then reuse the result
            now = time.monotonic()
            if not force and self._token and self._expires_at - now > REFRESH_AHEAD:
                return self._token
            try:
                token, ttl = await self._fetch_token()
            except KelpgateError:
                if not force and self._token and self._expires_at > now:
                    return self._token  # renewing early failed, the old token is still good
                raise
            self._token, self._expires_at = token, time.monotonic() + ttl
            return token

    async def _fetch_token(self) -> tuple[str, float]:
        cfg = self._cfg
        assert cfg.token_url and cfg.client_id and cfg.client_secret
        try:
            res = await self._http.post(
                cfg.token_url,
                headers={
                    "Authorization": basic_auth_header(cfg.client_id, cfg.client_secret),
                    "User-Agent": cfg.user_agent,
                },
                data={"grant_type": "client_credentials", "scope": cfg.scope},
            )
        except httpx.TimeoutException as exc:
            raise RequestTimeout(f"The token request timed out after {cfg.timeout:g} s") from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"The token request failed: {exc}") from exc
        return parse_token(res.status_code, parse_json(res.content), request_id_of(res.headers))

    # ---- HTTP

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        upload: Optional[PreparedUpload] = None,
        form: Optional[Dict[str, str]] = None,
        auth: bool = True,
        idempotency_key: Optional[str] = None,
    ) -> tuple[int, Dict[str, Any], httpx.Headers]:
        cfg = self._cfg
        token_retried = False
        attempt = 0
        while True:
            headers = {"User-Agent": cfg.user_agent, "Accept": "application/json"}
            if idempotency_key:
                headers["Idempotency-Key"] = idempotency_key
            opened: Any = None
            must_close = False
            try:
                if auth:
                    headers["Authorization"] = f"Bearer {await self._access_token()}"
                kwargs: Dict[str, Any] = {}
                if upload is not None:
                    opened, must_close = upload.open()
                    kwargs["files"] = {"file": (upload.filename, opened, "application/octet-stream")}
                    if form:
                        kwargs["data"] = form
                elif json_body is not None:
                    kwargs["content"] = json.dumps(json_body).encode()
                    headers["Content-Type"] = "application/json"
                res = await self._http.request(method, cfg.api_url + path, headers=headers, **kwargs)
            except KelpgateError:
                raise
            except httpx.HTTPError as exc:
                err: KelpgateError = (
                    RequestTimeout(f"The request timed out after {cfg.timeout:g} s")
                    if isinstance(exc, httpx.TimeoutException)
                    else NetworkError(f"The request failed: {exc}")
                )
                if attempt >= cfg.max_retries:
                    raise err from exc
                await asyncio.sleep(backoff_delay(attempt, cfg.retry_delay))
                attempt += 1
                continue
            finally:
                if must_close and opened is not None:
                    opened.close()

            data = parse_json(res.content)
            if res.status_code == 401 and auth and not cfg.bearer_token and not token_retried:
                token_retried = True  # the token may have been revoked or rotated: renew once
                self._token = None
                continue
            if res.status_code in RETRY_STATUSES and attempt < cfg.max_retries:
                await asyncio.sleep(backoff_delay(attempt, cfg.retry_delay, res.headers.get("retry-after")))
                attempt += 1
                continue
            return res.status_code, data, res.headers

    # ---- scanning

    async def scan_file(
        self, source: Source, *, filename: Optional[str] = None, idempotency_key: Optional[str] = None
    ) -> ScanResult:
        """Scan a file given as a path, ``bytes`` or a binary file object, and return the verdict.

        ``idempotency_key`` makes retries safe: the service counts a request repeated under the same key only
        once. By default a random key is used for each call and reused by the client's own retries.
        """
        key = resolve_idempotency_key(idempotency_key)
        upload = prepare_upload(source, filename, self._cfg.max_bytes)
        return scan_outcome(
            *await self._request("POST", "/api/v1/scan/file", upload=upload, idempotency_key=key)
        )

    async def scan_bytes(
        self,
        data: Union[bytes, bytearray, memoryview],
        *,
        filename: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> ScanResult:
        """Scan bytes you already have in memory."""
        return await self.scan_file(data, filename=filename, idempotency_key=idempotency_key)

    async def scan_url(self, url: str, *, idempotency_key: Optional[str] = None) -> ScanResult:
        """Ask the service to fetch and scan a remote file."""
        key = resolve_idempotency_key(idempotency_key)
        return scan_outcome(
            *await self._request("POST", "/api/v1/scan/url", json_body={"url": str(url)}, idempotency_key=key)
        )

    async def scan_file_async(
        self,
        source: Source,
        *,
        filename: Optional[str] = None,
        webhook_url: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> AcceptedScan:
        """Start an asynchronous scan. Collect it with :meth:`get_async_result` or :meth:`wait_for_result`."""
        key = resolve_idempotency_key(idempotency_key)
        upload = prepare_upload(source, filename, self._cfg.max_bytes)
        form = {"webhook_url": webhook_url} if webhook_url else None
        return accepted_outcome(
            *await self._request(
                "POST", "/api/v1/async-scan/file", upload=upload, form=form, idempotency_key=key
            )
        )

    async def scan_url_async(
        self, url: str, *, webhook_url: Optional[str] = None, idempotency_key: Optional[str] = None
    ) -> AcceptedScan:
        """Start an asynchronous scan of a remote file."""
        key = resolve_idempotency_key(idempotency_key)
        body: Dict[str, str] = {"url": str(url)}
        if webhook_url:
            body["webhook_url"] = webhook_url
        return accepted_outcome(
            *await self._request("POST", "/api/v1/async-scan/url", json_body=body, idempotency_key=key)
        )

    async def get_async_result(self, scan_id: str, *, kind: str = "file") -> Union[ScanResult, PendingScan]:
        """Read an asynchronous result. Returns a :class:`PendingScan` until the verdict is ready."""
        which = "url" if kind == "url" else "file"
        status, data, headers = await self._request(
            "GET", f"/api/v1/async-scan/{which}?scan_id={quote(scan_id, safe='')}"
        )
        return poll_outcome(scan_id, status, data, headers)

    async def wait_for_result(
        self, scan_id: str, *, kind: str = "file", interval: float = 1.0, timeout: float = 120.0
    ) -> ScanResult:
        """Poll until an asynchronous scan finishes. Raises :class:`RequestTimeout` if it takes too long."""
        deadline = time.monotonic() + timeout
        while True:
            result = await self.get_async_result(scan_id, kind=kind)
            if isinstance(result, ScanResult):
                return result
            if time.monotonic() + interval > deadline:
                raise RequestTimeout(f"Scan {scan_id} was not finished after {timeout:g} s")
            await asyncio.sleep(interval)

    async def health(self) -> Health:
        """Check that the service is up. Needs no credentials."""
        return health_outcome(*await self._request("GET", "/api/v1/health", auth=False))

    # Names used before 0.2.0, kept so existing code keeps working.
    submit_file = scan_file_async
    submit_url = scan_url_async
    get_result = get_async_result
    wait = wait_for_result
