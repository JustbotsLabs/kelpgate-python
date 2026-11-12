"""Logic shared by the synchronous and asynchronous clients: no I/O happens here."""

from __future__ import annotations

import base64
import json
import os
import random
import re
import urllib.parse
from dataclasses import dataclass
from io import BytesIO
from typing import Any, BinaryIO, Dict, Mapping, Optional, Tuple, Union

from ._errors import (
    AuthError,
    ConfigError,
    KelpgateError,
    PayloadTooLargeError,
    QuotaExceededError,
    RateLimitedError,
    ScanError,
    ServerError,
    UnsupportedFileError,
)
from ._models import AcceptedScan, Health, PendingScan, ScanResult
from ._version import __version__

DEFAULT_MAX_BYTES = 128 * 1024 * 1024  # a little above the largest plan limit
REFRESH_AHEAD = 120.0  # renew a token this many seconds before it expires
RETRY_AFTER_CAP = 30.0
RETRY_STATUSES = frozenset({429, 502, 503, 504})
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
# RFC 6749 asks for form-urlencoding of the client id and secret in Basic auth.
_SAFE = "!~*'()"

Source = Union[str, "os.PathLike[str]", bytes, bytearray, memoryview, BinaryIO]


def check_url(name: str, value: Optional[str]) -> str:
    """Return ``value`` without a trailing slash, or raise ConfigError. Plain http is only for localhost."""
    parts = urllib.parse.urlsplit(value or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"{name} is not a valid URL")
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK:
        raise ConfigError(f"{name} must use https (plain http is only allowed for localhost)")
    return (value or "").rstrip("/")


@dataclass
class Config:
    api_url: str
    token_url: Optional[str]
    client_id: Optional[str]
    client_secret: Optional[str]
    bearer_token: Optional[str]
    scope: str
    timeout: float
    max_retries: int
    retry_delay: float
    max_bytes: int
    user_agent: str

    def __repr__(self) -> str:  # never show the secret or token
        return f"Config(api_url={self.api_url!r}, scope={self.scope!r})"


def build_config(
    *,
    api_url: Optional[str],
    token_url: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    bearer_token: Optional[str] = None,
    scope: str = "scan",
    timeout: float = 60.0,
    max_retries: int = 2,
    retry_delay: float = 0.5,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Config:
    checked_api = check_url("api_url", api_url)
    checked_token: Optional[str] = None
    if not bearer_token:
        checked_token = check_url("token_url", token_url)
        if not client_id or not client_secret:
            raise ConfigError("client_id and client_secret are required (or pass bearer_token)")
    return Config(
        api_url=checked_api,
        token_url=checked_token,
        client_id=client_id,
        client_secret=client_secret,
        bearer_token=bearer_token or None,
        scope=scope,
        timeout=float(timeout),
        max_retries=max(0, int(max_retries)),
        retry_delay=float(retry_delay),
        max_bytes=int(max_bytes),
        user_agent=f"kelpgate-python/{__version__}",
    )


def env_options(env: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Client options from ``KELPGATE_*`` environment variables, with the production endpoints as defaults."""
    e = os.environ if env is None else env
    return {
        "api_url": e.get("KELPGATE_API_URL") or "https://api.kelpgate.cloud",
        "token_url": e.get("KELPGATE_TOKEN_URL") or "https://auth.kelpgate.cloud/oauth2/token",
        "client_id": e.get("KELPGATE_CLIENT_ID"),
        "client_secret": e.get("KELPGATE_CLIENT_SECRET"),
        "bearer_token": e.get("KELPGATE_TOKEN"),
    }


def basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{urllib.parse.quote(client_id, safe=_SAFE)}:{urllib.parse.quote(client_secret, safe=_SAFE)}"
    return "Basic " + base64.b64encode(raw.encode()).decode()


def parse_json(content: bytes) -> Dict[str, Any]:
    if not content:
        return {}
    try:
        data = json.loads(content)
    except ValueError:
        return {"error": content[:200].decode("utf-8", "replace")}
    return data if isinstance(data, dict) else {"value": data}


def parse_token(status: int, data: Dict[str, Any], request_id: Optional[str]) -> Tuple[str, float]:
    """Return ``(access_token, lifetime_seconds)`` or raise AuthError."""
    token = data.get("access_token")
    if status != 200 or not isinstance(token, str) or not token:
        why = data.get("error_description") or data.get("error") or f"HTTP {status}"
        safe_body = {k: v for k, v in data.items() if k not in ("access_token", "refresh_token")}
        raise AuthError(
            f"Could not get an access token: {why}",
            code="TOKEN_REQUEST_FAILED",
            status=status,
            request_id=request_id,
            body=safe_body,
        )
    try:
        ttl = float(data.get("expires_in") or 0)
    except (TypeError, ValueError):
        ttl = 0.0
    return token, ttl if ttl > 0 else 300.0


def backoff_delay(attempt: int, base: float, retry_after: Optional[str] = None) -> float:
    if retry_after is not None:
        try:
            seconds = float(retry_after)
        except ValueError:
            seconds = -1.0
        if seconds >= 0:
            return min(seconds, RETRY_AFTER_CAP)
    return base * (2.0**attempt) + random.uniform(0, min(0.1, base))  # noqa: S311 - retry jitter, not security


def _basename(name: str) -> str:
    return re.split(r"[\\/]", name)[-1] or "upload.bin"


class PreparedUpload:
    """A file ready to send. :meth:`open` gives a fresh file object for each attempt, so retries work."""

    def __init__(
        self,
        filename: str,
        size: int,
        *,
        data: Optional[bytes] = None,
        path: Optional[str] = None,
        stream: Optional[BinaryIO] = None,
    ) -> None:
        self.filename = filename
        self.size = size
        self._data = data
        self._path = path
        self._stream = stream
        self._start = stream.tell() if stream is not None else 0

    def open(self) -> Tuple[Any, bool]:
        """Return ``(content, must_close)``."""
        if self._data is not None:
            return self._data, False
        if self._path is not None:
            return open(self._path, "rb"), True
        assert self._stream is not None
        self._stream.seek(self._start)
        return self._stream, False


def prepare_upload(source: Source, filename: Optional[str], max_bytes: int) -> PreparedUpload:
    """Turn a path, bytes, or binary file object into something we can send, enforcing ``max_bytes``."""

    def too_big(size: int) -> PayloadTooLargeError:
        return PayloadTooLargeError(
            f"The file is {size} bytes, over this client's limit of {max_bytes} bytes", status=413
        )

    upload: PreparedUpload
    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        try:
            size = os.path.getsize(path)
            with open(path, "rb"):
                pass
        except OSError as exc:
            raise ScanError(f"Cannot read {path}: {exc.strerror or exc}", code="FILE_UNREADABLE") from exc
        upload = PreparedUpload(filename or _basename(path), size, path=path)
    elif isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        upload = PreparedUpload(filename or "upload.bin", len(data), data=data)
    elif hasattr(source, "read"):
        stream: BinaryIO = source
        name = filename
        if not name:
            attr = getattr(stream, "name", None)
            name = _basename(attr) if isinstance(attr, str) else "upload.bin"
        seekable = False
        try:
            seekable = bool(stream.seekable())
        except (AttributeError, ValueError):
            seekable = False
        if seekable:
            start = stream.tell()
            end = stream.seek(0, os.SEEK_END)
            stream.seek(start)
            if end - start > max_bytes:
                raise too_big(end - start)
            upload = PreparedUpload(name, end - start, stream=stream)
        else:  # a pipe or socket: buffer it, but never more than the limit
            buf = BytesIO()
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                buf.write(chunk)
                if buf.tell() > max_bytes:
                    raise too_big(buf.tell())
            data = buf.getvalue()
            upload = PreparedUpload(name, len(data), data=data)
    else:
        raise ConfigError("source must be a file path, bytes, or a binary file object")
    if upload.size > max_bytes:
        raise too_big(upload.size)
    return upload


def request_id_of(headers: Mapping[str, str]) -> Optional[str]:
    return headers.get("x-request-id")


def to_error(status: int, data: Dict[str, Any], headers: Mapping[str, str]) -> KelpgateError:
    """Map a failed response to the right exception."""
    message = str(data.get("error") or data.get("message") or f"Kelpgate returned HTTP {status}")
    kw: Dict[str, Any] = {"status": status, "request_id": request_id_of(headers), "body": data}
    if status in (401, 403):
        return AuthError(message, code="UNAUTHORIZED" if status == 401 else "FORBIDDEN", **kw)
    if status == 402:
        return QuotaExceededError(message, **kw)
    if status == 413:
        return PayloadTooLargeError(message, **kw)
    if status == 415:
        return UnsupportedFileError(message, **kw)
    if status == 429:
        try:
            retry_after: Optional[float] = float(headers.get("retry-after", ""))
        except ValueError:
            retry_after = None
        return RateLimitedError(message, retry_after=retry_after, **kw)
    if status == 404:
        return KelpgateError(message, code="NOT_FOUND", **kw)
    if status in (400, 412):
        return ScanError(message, **kw)
    if status >= 500:
        return ServerError(message, **kw)
    return KelpgateError(message, **kw)


def to_result(data: Dict[str, Any], headers: Mapping[str, str]) -> ScanResult:
    signature = str(data.get("av-signature") or "")
    authors = data.get("rule_authors")
    return ScanResult(
        infected=data.get("av-status") == "INFECTED",
        status=str(data.get("av-status")),
        signature=signature,
        sha256=data.get("sha256"),
        rule_authors=tuple(str(a) for a in authors) if isinstance(authors, list) else (),
        filename=data.get("filename"),
        scan_id=data.get("scan_id"),
        timestamp=data.get("av-timestamp"),
        s3_path=data.get("s3_path"),
        download_url=data.get("download_url"),
        request_id=request_id_of(headers),
        policy_rejected=signature.startswith("POLICY:"),
        degraded="scan coverage reduced" in signature,
        raw=data,
    )


def scan_outcome(status: int, data: Dict[str, Any], headers: Mapping[str, str]) -> ScanResult:
    """A scan answers 200 (clean) or 406 (infected). Both are verdicts. Anything else is an error."""
    if status in (200, 406) and data.get("av-status"):
        return to_result(data, headers)
    raise to_error(status, data, headers)


def accepted_outcome(status: int, data: Dict[str, Any], headers: Mapping[str, str]) -> AcceptedScan:
    if status == 202 and data.get("scan_id"):
        return AcceptedScan(
            scan_id=str(data["scan_id"]),
            filename=data.get("filename"),
            message=data.get("message"),
            request_id=request_id_of(headers),
        )
    raise to_error(status, data, headers)


def poll_outcome(
    scan_id: str, status: int, data: Dict[str, Any], headers: Mapping[str, str]
) -> Union[ScanResult, PendingScan]:
    if status == 202 or data.get("av-status") == "PROCESSING":
        return PendingScan(scan_id=scan_id, request_id=request_id_of(headers))
    return scan_outcome(status, data, headers)


def health_outcome(status: int, data: Dict[str, Any], headers: Mapping[str, str]) -> Health:
    return Health(
        ok=status == 200,
        status=status,
        signature_version=data.get("signature_version"),
        request_id=request_id_of(headers),
    )
