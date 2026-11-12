"""Python client for the Kelpgate malware-scanning API.

    from kelpgate import KelpgateClient

    with KelpgateClient.from_env() as kg:
        result = kg.scan_file("upload.pdf")
        if result.infected:
            print("Rejected:", result.signature)

Use :class:`AsyncKelpgateClient` from asyncio code.
"""

from ._async import AsyncKelpgateClient
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
from ._sync import KelpgateClient
from ._version import __version__


def assert_clean(result: ScanResult) -> ScanResult:
    """Return ``result`` if it is clean. Raise :class:`InfectedError` if it is infected."""
    if result.infected:
        raise InfectedError(result)
    return result


__all__ = [
    "AcceptedScan",
    "AsyncKelpgateClient",
    "AuthError",
    "ConfigError",
    "Health",
    "InfectedError",
    "KelpgateClient",
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
