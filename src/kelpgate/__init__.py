"""Python client for the Kelpgate malware-scanning API.

    from kelpgate import Kelpgate

    with Kelpgate.from_env() as kg:
        result = kg.scan_file("upload.pdf")
        if result.infected:
            print("Rejected:", result.signature)

Use :class:`AsyncKelpgate` from asyncio code.
"""

from ._async import AsyncKelpgate
from ._errors import (
    AuthError,
    ConfigError,
    InfectedError,
    KelpgateError,
    NetworkError,
    PayloadTooLargeError,
    QuotaExceededError,
    RateLimitedError,
    RequestTimeout,
    ScanError,
    ServerError,
    UnsupportedFileError,
)
from ._models import AcceptedScan, Health, PendingScan, ScanResult
from ._sync import Kelpgate
from ._version import __version__


def assert_clean(result: ScanResult) -> ScanResult:
    """Return ``result`` if it is clean. Raise :class:`InfectedError` if it is infected."""
    if result.infected:
        raise InfectedError(result)
    return result


__all__ = [
    "AcceptedScan",
    "AsyncKelpgate",
    "AuthError",
    "ConfigError",
    "Health",
    "InfectedError",
    "Kelpgate",
    "KelpgateError",
    "NetworkError",
    "PayloadTooLargeError",
    "PendingScan",
    "QuotaExceededError",
    "RateLimitedError",
    "RequestTimeout",
    "ScanError",
    "ScanResult",
    "ServerError",
    "UnsupportedFileError",
    "__version__",
    "assert_clean",
]
