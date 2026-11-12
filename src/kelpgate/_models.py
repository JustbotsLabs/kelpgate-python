"""Result types returned by the client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class ScanResult:
    """The verdict for one scan.

    An infected file is a normal result (``infected`` is ``True``), not an exception.
    Use :func:`kelpgate.assert_clean` if you would rather have an exception.
    """

    infected: bool
    #: ``"CLEAN"`` or ``"INFECTED"``.
    status: str
    #: Detection name, or ``"OK"`` for a clean file.
    signature: str
    sha256: Optional[str] = None
    #: Authors of the rules that matched, for rule-license attribution.
    rule_authors: Tuple[str, ...] = ()
    filename: Optional[str] = None
    scan_id: Optional[str] = None
    timestamp: Optional[str] = None
    s3_path: Optional[str] = None
    download_url: Optional[str] = None
    #: The ``X-Request-Id`` of the response.
    request_id: Optional[str] = None
    #: The file was refused by policy (type or content rules), not detected as malware.
    policy_rejected: bool = False
    #: An engine did not finish, so coverage was reduced for this scan.
    degraded: bool = False
    #: The response body as received.
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(frozen=True)
class PendingScan:
    """Returned by :meth:`KelpgateClient.get_async_result` while an asynchronous scan is still running."""

    scan_id: str
    request_id: Optional[str] = None


@dataclass(frozen=True)
class AcceptedScan:
    """Returned when an asynchronous scan has been accepted. Use ``scan_id`` to collect the result."""

    scan_id: str
    filename: Optional[str] = None
    message: Optional[str] = None
    request_id: Optional[str] = None


@dataclass(frozen=True)
class Health:
    """Service status from the health endpoint."""

    ok: bool
    status: int
    signature_version: Optional[str] = None
    request_id: Optional[str] = None
