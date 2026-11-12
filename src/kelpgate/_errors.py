"""Exceptions raised by the Kelpgate client. All of them derive from :class:`KelpgateError`."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:  # pragma: no cover
    from ._models import ScanResult


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


class KelpgateError(Exception):
    """Base class for every error this package raises on purpose.

    Attributes:
        code: A short machine-readable code such as ``"QUOTA_EXCEEDED"``.
        status: The HTTP status, when the error came from a response.
        request_id: The ``X-Request-Id`` of the response. Quote it when you contact support.
        body: The decoded response body, if there was one.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str = "KELPGATE_ERROR",
        status: Optional[int] = None,
        request_id: Optional[str] = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.request_id = request_id
        self.body = body


class ConfigError(KelpgateError):
    """The options passed to the client are wrong. Raised before any request is sent."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="CONFIG")


class AuthError(KelpgateError):
    """The API refused the credentials (401), or the organisation may not use it (403)."""


class QuotaExceededError(KelpgateError):
    """The plan's scan quota is used up (402)."""

    def __init__(self, message: str, **kw: Any) -> None:
        super().__init__(message, code="QUOTA_EXCEEDED", **kw)
        body = _as_dict(kw.get("body"))
        self.quota: Optional[int] = body.get("quota")
        self.usage: Optional[int] = body.get("usage")
        self.upgrade_url: Optional[str] = body.get("upgrade_url")


class PayloadTooLargeError(KelpgateError):
    """The file is over the plan limit (413), or over the client's own ``max_bytes``."""

    def __init__(self, message: str, **kw: Any) -> None:
        super().__init__(message, code="PAYLOAD_TOO_LARGE", **kw)
        self.upgrade_url: Optional[str] = _as_dict(kw.get("body")).get("upgrade_url")


class UnsupportedFileError(KelpgateError):
    """The file type is not allowed, or it is an encrypted archive (415)."""

    def __init__(self, message: str, **kw: Any) -> None:
        super().__init__(message, code="UNSUPPORTED_FILE", **kw)


class RateLimitedError(KelpgateError):
    """Too many scans at once for this organisation (429)."""

    def __init__(self, message: str, *, retry_after: Optional[float] = None, **kw: Any) -> None:
        super().__init__(message, code="RATE_LIMITED", **kw)
        self.retry_after = retry_after


class ScanError(KelpgateError):
    """The request was rejected as invalid (400), or the file could not be parsed (412)."""

    def __init__(self, message: str, *, code: str = "SCAN_ERROR", **kw: Any) -> None:
        super().__init__(message, code=code, **kw)


class ServerError(KelpgateError):
    """The service failed (5xx)."""

    def __init__(self, message: str, **kw: Any) -> None:
        super().__init__(message, code="SERVER_ERROR", **kw)


class NetworkError(KelpgateError):
    """The service could not be reached, or the connection broke."""

    def __init__(self, message: str, *, code: str = "NETWORK", **kw: Any) -> None:
        super().__init__(message, code=code, **kw)


class RequestTimeout(NetworkError):
    """The request took longer than the configured timeout, or a wait for a result ran out."""

    def __init__(self, message: str, **kw: Any) -> None:
        super().__init__(message, code="TIMEOUT", **kw)


class InfectedError(KelpgateError):
    """Raised by :func:`kelpgate.assert_clean` when a scan found malware."""

    def __init__(self, result: ScanResult) -> None:
        super().__init__(
            f"File rejected: {result.signature or 'infected'}",
            code="INFECTED",
            status=406,
            request_id=result.request_id,
        )
        self.result = result
        self.signature = result.signature
