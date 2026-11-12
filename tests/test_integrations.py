from __future__ import annotations

from typing import Any, Tuple

import django
import pytest
from django.conf import settings
from fastapi import Depends, FastAPI, UploadFile
from fastapi.testclient import TestClient

import kelpgate.integrations.django as kdjango
from conftest import API, MockApi, options
from kelpgate import AsyncKelpgate, Kelpgate
from kelpgate.integrations.fastapi import scan_dependency, scan_upload

# ---- FastAPI


def make_app(api: MockApi, on_error: str = "block") -> Tuple[FastAPI, AsyncKelpgate]:
    client = AsyncKelpgate(API, **options(max_retries=0, transport=api.transport()))
    app = FastAPI()

    @app.post("/upload")
    async def upload(file: UploadFile = Depends(scan_dependency(client, on_error=on_error))) -> Any:
        return {"name": file.filename, "bytes": len(await file.read())}  # the upload was rewound

    @app.post("/other")
    async def other(doc: UploadFile) -> Any:
        result = await scan_upload(client, doc, on_error=on_error)
        return {"scanned": result is not None}

    return app, client


def post(app: FastAPI, path: str, field: str, content: bytes) -> Any:
    with TestClient(app) as c:
        return c.post(path, files={field: ("a.txt", content)})


def test_fastapi_clean_upload_passes_and_is_still_readable(api: MockApi) -> None:
    app, _ = make_app(api)
    r = post(app, "/upload", "file", b"hello world")
    assert r.status_code == 200 and r.json() == {"name": "a.txt", "bytes": 11}


def test_fastapi_infected_upload_is_422_with_the_signature(api: MockApi) -> None:
    app, _ = make_app(api)
    r = post(app, "/upload", "file", b"MOCK-MALWARE")
    assert r.status_code == 422 and r.json()["detail"]["signature"] == "Mock.Test.Signature"


def test_fastapi_scan_failure_blocks_by_default_and_can_be_allowed(api: MockApi) -> None:
    app, _ = make_app(api)
    api.fail_next.append((500, {}, {}))
    assert post(app, "/upload", "file", b"x").status_code == 503
    api.fail_next.append((402, {}, {}))
    assert post(app, "/upload", "file", b"x").status_code == 402
    app2, _ = make_app(api, on_error="allow")
    api.fail_next.append((500, {}, {}))
    assert post(app2, "/upload", "file", b"x").status_code == 200


def test_fastapi_scan_upload_works_for_any_field_name(api: MockApi) -> None:
    app, _ = make_app(api)
    assert post(app, "/other", "doc", b"fine").json() == {"scanned": True}
    assert post(app, "/other", "doc", b"MOCK-MALWARE").status_code == 422


# ---- Django

if not settings.configured:
    settings.configure(DEBUG=True, SECRET_KEY="test", USE_TZ=True, INSTALLED_APPS=[])
    django.setup()

from django.core.exceptions import ValidationError  # noqa: E402
from django.core.files.uploadedfile import SimpleUploadedFile  # noqa: E402


@pytest.fixture
def dj(api: MockApi, monkeypatch: pytest.MonkeyPatch) -> kdjango.KelpgateValidator:
    monkeypatch.setattr(
        kdjango, "_client", Kelpgate(API, **options(max_retries=0, transport=api.transport()))
    )
    return kdjango.KelpgateValidator()


def test_django_clean_file_passes_and_is_rewound(dj: Any) -> None:
    f = SimpleUploadedFile("a.txt", b"hello")
    dj(f)
    assert f.read() == b"hello"


def test_django_infected_file_fails_validation(dj: Any) -> None:
    with pytest.raises(ValidationError) as e:
        dj(SimpleUploadedFile("bad.txt", b"MOCK-MALWARE"))
    assert e.value.code == "infected"


def test_django_scan_failure_blocks_or_allows(api: MockApi, dj: Any) -> None:
    api.fail_next.append((500, {}, {}))
    with pytest.raises(ValidationError) as e:
        dj(SimpleUploadedFile("a.txt", b"x"))
    assert e.value.code == "scan_unavailable"
    api.fail_next.append((500, {}, {}))
    kdjango.KelpgateValidator(on_error="allow")(SimpleUploadedFile("a.txt", b"x"))


def test_django_validator_can_be_serialised_for_migrations() -> None:
    v = kdjango.KelpgateValidator(on_error="allow")
    path, args, kwargs = v.deconstruct()
    assert path.endswith("KelpgateValidator") and kwargs == {"on_error": "allow"}
    assert v == kdjango.KelpgateValidator(on_error="allow") and v != kdjango.KelpgateValidator()
