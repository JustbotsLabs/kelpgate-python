"""The synchronous client."""

from __future__ import annotations

import json
import threading
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
    scan_outcome,
)
from ._errors import KelpgateError, NetworkError, RequestTimeout
from ._models import AcceptedScan, Health, PendingScan, ScanResult


class Kelpgate:
    """Client for the Kelpgate malware-scanning API. Safe to share between threads.

    Args:
        api_url: Base URL of the API, for example ``https://api.kelpgate.cloud`` (https only; plain
            http is accepted for localhost).
        token_url: OAuth 2 token endpoint. Needed unless ``bearer_token`` is given.
        client_id, client_secret: OAuth client credentials. The access token is fetched, cached and
            renewed for you.
        bearer_token: A static bearer token, instead of client credentials.
        scope: OAuth scope. Defaults to ``"scan"``.
        timeout: Seconds allowed for each connect, read and write. Defaults to 60.
        max_retries: Retries for network errors, 429, 502, 503 and 504. Defaults to 2.
        retry_delay: Base delay between retries, in seconds.
        max_bytes: Largest file the client will send. Defaults to 128 MiB.
        transport: An ``httpx`` transport, for tests or proxies.
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
        transport: Optional[httpx.BaseTransport] = None,
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
        self._http = httpx.Client(timeout=timeout, transport=transport, follow_redirects=False)
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._expires_at = 0.0

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, **overrides: Any) -> Kelpgate:
        """Build a client from ``KELPGATE_CLIENT_ID``, ``KELPGATE_CLIENT_SECRET`` (or ``KELPGATE_TOKEN``)
        and the optional ``KELPGATE_API_URL`` and ``KELPGATE_TOKEN_URL``."""
        opts = env_options(env)
        opts.update(overrides)
        return cls(**opts)

    def __repr__(self) -> str:
        return f"Kelpgate(api_url={self._cfg.api_url!r})"

    def __enter__(self) -> Kelpgate:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying connections."""
        self._http.close()

    # ---- authentication

    def _access_token(self, force: bool = False) -> str:
        if self._cfg.bearer_token:
            return self._cfg.bearer_token
        if not force and self._token and self._expires_at - time.monotonic() > REFRESH_AHEAD:
            return self._token
        with self._lock:  # one renewal at a time; concurrent callers wait, then reuse the result
            now = time.monotonic()
            if not force and self._token and self._expires_at - now > REFRESH_AHEAD:
                return self._token
            try:
                token, ttl = self._fetch_token()
            except KelpgateError:
                if not force and self._token and self._expires_at > now:
                    return self._token  # renewing early failed, the old token is still good
                raise
            self._token, self._expires_at = token, time.monotonic() + ttl
            return token

    def _fetch_token(self) -> tuple[str, float]:
        cfg = self._cfg
        assert cfg.token_url and cfg.client_id and cfg.client_secret
        try:
            res = self._http.post(
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

    def _invalidate_token(self) -> None:
        with self._lock:
            self._token = None

    # ---- HTTP

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        upload: Optional[PreparedUpload] = None,
        form: Optional[Dict[str, str]] = None,
        auth: bool = True,
    ) -> tuple[int, Dict[str, Any], httpx.Headers]:
        cfg = self._cfg
        token_retried = False
        attempt = 0
        while True:
            headers = {"User-Agent": cfg.user_agent, "Accept": "application/json"}
            opened: Any = None
            must_close = False
            try:
                if auth:
                    headers["Authorization"] = f"Bearer {self._access_token()}"
                kwargs: Dict[str, Any] = {}
                if upload is not None:
                    opened, must_close = upload.open()
                    kwargs["files"] = {"file": (upload.filename, opened, "application/octet-stream")}
                    if form:
                        kwargs["data"] = form
                elif json_body is not None:
                    kwargs["content"] = json.dumps(json_body).encode()
                    headers["Content-Type"] = "application/json"
                res = self._http.request(method, cfg.api_url + path, headers=headers, **kwargs)
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
                time.sleep(backoff_delay(attempt, cfg.retry_delay))
                attempt += 1
                continue
            finally:
                if must_close and opened is not None:
                    opened.close()

            data = parse_json(res.content)
            if res.status_code == 401 and auth and not cfg.bearer_token and not token_retried:
                token_retried = True  # the token may have been revoked or rotated: renew once
                self._invalidate_token()
                continue
            if res.status_code in RETRY_STATUSES and attempt < cfg.max_retries:
                time.sleep(backoff_delay(attempt, cfg.retry_delay, res.headers.get("retry-after")))
                attempt += 1
                continue
            return res.status_code, data, res.headers

    # ---- scanning

    def scan_file(self, source: Source, *, filename: Optional[str] = None) -> ScanResult:
        """Scan a file given as a path, ``bytes`` or a binary file object, and return the verdict."""
        upload = prepare_upload(source, filename, self._cfg.max_bytes)
        return scan_outcome(*self._request("POST", "/api/v1/scan/file", upload=upload))

    def scan_bytes(
        self, data: Union[bytes, bytearray, memoryview], *, filename: Optional[str] = None
    ) -> ScanResult:
        """Scan bytes you already have in memory."""
        return self.scan_file(data, filename=filename)

    def scan_url(self, url: str) -> ScanResult:
        """Ask the service to fetch and scan a remote file."""
        return scan_outcome(*self._request("POST", "/api/v1/scan/url", json_body={"url": str(url)}))

    def submit_file(
        self, source: Source, *, filename: Optional[str] = None, webhook_url: Optional[str] = None
    ) -> AcceptedScan:
        """Start an asynchronous scan. Collect the result with :meth:`get_result` or :meth:`wait`."""
        upload = prepare_upload(source, filename, self._cfg.max_bytes)
        form = {"webhook_url": webhook_url} if webhook_url else None
        return accepted_outcome(*self._request("POST", "/api/v1/async-scan/file", upload=upload, form=form))

    def submit_url(self, url: str, *, webhook_url: Optional[str] = None) -> AcceptedScan:
        """Start an asynchronous scan of a remote file."""
        body: Dict[str, str] = {"url": str(url)}
        if webhook_url:
            body["webhook_url"] = webhook_url
        return accepted_outcome(*self._request("POST", "/api/v1/async-scan/url", json_body=body))

    def get_result(self, scan_id: str, *, kind: str = "file") -> Union[ScanResult, PendingScan]:
        """Read an asynchronous result. Returns a :class:`PendingScan` until the verdict is ready."""
        which = "url" if kind == "url" else "file"
        status, data, headers = self._request(
            "GET", f"/api/v1/async-scan/{which}?scan_id={quote(scan_id, safe='')}"
        )
        return poll_outcome(scan_id, status, data, headers)

    def wait(
        self, scan_id: str, *, kind: str = "file", interval: float = 1.0, timeout: float = 120.0
    ) -> ScanResult:
        """Poll until an asynchronous scan finishes. Raises :class:`RequestTimeout` if it takes too long."""
        deadline = time.monotonic() + timeout
        while True:
            result = self.get_result(scan_id, kind=kind)
            if isinstance(result, ScanResult):
                return result
            if time.monotonic() + interval > deadline:
                raise RequestTimeout(f"Scan {scan_id} was not finished after {timeout:g} s")
            time.sleep(interval)

    def health(self) -> Health:
        """Check that the service is up. Needs no credentials."""
        return health_outcome(*self._request("GET", "/api/v1/health", auth=False))
