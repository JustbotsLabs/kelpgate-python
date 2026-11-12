"""Scan uploads in FastAPI (or Starlette) before your handler sees them.

    from fastapi import Depends, FastAPI, UploadFile
    from kelpgate import AsyncKelpgateClient
    from kelpgate.integrations.fastapi import scan_dependency

    app = FastAPI()
    kelpgate = AsyncKelpgateClient.from_env()

    @app.post("/upload")
    async def upload(file: UploadFile = Depends(scan_dependency(kelpgate))):
        ...  # only reached for files that scanned clean

An infected file gets a 422. If the scan cannot run, the request gets a 503 (``on_error="block"``,
the default) or goes through (``on_error="allow"``).
"""

from __future__ import annotations

from typing import Awaitable, Callable, Optional

from fastapi import HTTPException, UploadFile

from .. import (
    AsyncKelpgateClient,
    KelpgateError,
    PayloadTooLargeError,
    QuotaExceededError,
    ScanResult,
    UnsupportedFileError,
)


async def scan_upload(
    client: AsyncKelpgateClient, upload: UploadFile, *, on_error: str = "block"
) -> Optional[ScanResult]:
    """Scan one uploaded file. Returns the result, or ``None`` if the scan failed and ``on_error="allow"``.

    Raises :class:`fastapi.HTTPException` (422) for an infected file, and (503, 402, 413 or 415) when
    the scan fails and ``on_error="block"``. The upload is rewound afterwards so your handler can read it.
    """
    try:
        await upload.seek(0)
        result = await client.scan_file(upload.file, filename=upload.filename or None)
    except KelpgateError as exc:
        if on_error == "allow":
            return None
        if isinstance(exc, QuotaExceededError):
            raise HTTPException(status_code=402, detail="Scan quota exceeded") from exc
        if isinstance(exc, PayloadTooLargeError):
            raise HTTPException(status_code=413, detail="File too large to scan") from exc
        if isinstance(exc, UnsupportedFileError):
            raise HTTPException(status_code=415, detail="File type not allowed") from exc
        raise HTTPException(status_code=503, detail="File could not be scanned, try again later") from exc
    finally:
        await upload.seek(0)
    if result.infected:
        raise HTTPException(
            status_code=422, detail={"error": "File rejected by malware scan", "signature": result.signature}
        )
    return result


def scan_dependency(
    client: AsyncKelpgateClient, *, on_error: str = "block"
) -> Callable[[UploadFile], Awaitable[UploadFile]]:
    """A FastAPI dependency for a form field named ``file``.

    For other field names call :func:`scan_upload` yourself.
    """

    async def dependency(file: UploadFile) -> UploadFile:
        await scan_upload(client, file, on_error=on_error)
        return file

    return dependency
