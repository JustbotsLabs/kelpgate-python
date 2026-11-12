"""Scan uploads in Django, as a form or model field validator.

    # settings.py
    KELPGATE = {"CLIENT_ID": "...", "CLIENT_SECRET": "..."}   # or the KELPGATE_* environment variables

    # models.py
    from kelpgate.integrations.django import KelpgateValidator

    class Document(models.Model):
        file = models.FileField(upload_to="docs/", validators=[KelpgateValidator()])

An infected file fails validation (code ``"infected"``). If the scan cannot run, validation fails
(``on_error="block"``, the default) or passes (``on_error="allow"``).
"""

from __future__ import annotations

from typing import Any, Optional

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.deconstruct import deconstructible

from .. import KelpgateClient, KelpgateError

_client: Optional[KelpgateClient] = None


def get_client() -> KelpgateClient:
    """The shared client, built from ``settings.KELPGATE`` or the ``KELPGATE_*`` environment variables."""
    global _client
    if _client is None:
        conf = getattr(settings, "KELPGATE", None) or {}
        overrides = {k.lower(): v for k, v in conf.items()}
        _client = KelpgateClient.from_env(**overrides)
    return _client


@deconstructible
class KelpgateValidator:
    """Validator for ``FileField`` and ``forms.FileField``."""

    def __init__(self, on_error: str = "block") -> None:
        self.on_error = on_error

    def __call__(self, value: Any) -> None:
        file = getattr(value, "file", value)
        try:
            file.seek(0)
            result = get_client().scan_file(file, filename=getattr(value, "name", None))
        except KelpgateError as exc:
            if self.on_error == "allow":
                return
            raise ValidationError(
                "This file could not be scanned. Please try again later.", code="scan_unavailable"
            ) from exc
        finally:
            try:
                file.seek(0)
            except (AttributeError, ValueError, OSError):
                pass
        if result.infected:
            raise ValidationError("This file was rejected by the malware scan.", code="infected")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, KelpgateValidator) and other.on_error == self.on_error

    def __hash__(self) -> int:
        return hash(("KelpgateValidator", self.on_error))
