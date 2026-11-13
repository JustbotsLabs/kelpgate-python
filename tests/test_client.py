from __future__ import annotations

import asyncio
import io
import threading
import uuid
from typing import Any

import httpx
import pytest

import kelpgate as K
from conftest import API, TOKEN, MockApi, both, call, options

# ---- configuration (no network)


def test_rejects_plain_http_to_a_remote_host_and_missing_credentials() -> None:
    with pytest.raises(K.ConfigError):
        K.KelpgateClient("http://example.com", **options())
    with pytest.raises(K.ConfigError):
        K.KelpgateClient(API, token_url=TOKEN)
    with pytest.raises(K.ConfigError):
        K.KelpgateClient("not a url", **options())
    K.KelpgateClient("http://127.0.0.1:9", **options()).close()  # localhost may use http


def test_secrets_never_appear_in_repr_or_str() -> None:
    kg = K.KelpgateClient(API, **options())
    assert "secret1" not in repr(kg) and "secret1" not in repr(kg._cfg)
    kg.close()


def test_from_env_uses_production_defaults() -> None:
    kg = K.KelpgateClient.from_env({"KELPGATE_CLIENT_ID": "a", "KELPGATE_CLIENT_SECRET": "b"})
    assert kg._cfg.api_url == "https://api.kelpgate.cloud"
    assert kg._cfg.token_url == "https://auth.kelpgate.cloud/oauth2/token"
    kg.close()


# ---- scanning


@both
async def test_clean_bytes(make: Any, api: MockApi) -> None:
    r = await call(make(**options()).scan_bytes(b"hello", filename="a.txt"))
    assert (r.infected, r.status, r.signature) == (False, "CLEAN", "OK")
    assert r.filename == "a.txt" and r.request_id == "req-test" and r.sha256 == "abc123"


@both
async def test_infected_file_from_path(make: Any, api: MockApi, tmp_path: Any = None) -> None:
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "bad.bin")
        with open(p, "wb") as fh:
            fh.write(b"xx MOCK-MALWARE xx")
        r = await call(make(**options()).scan_file(p))
    assert r.infected and r.signature == "Mock.Test.Signature" and r.filename == "bad.bin"
    assert r.rule_authors == ("Example Author",)
    with pytest.raises(K.InfectedError) as info:
        K.assert_clean(r)
    assert info.value.result is r and info.value.status == 406


@both
async def test_file_objects_seekable_and_not(make: Any, api: MockApi) -> None:
    class Pipe(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._b = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def seekable(self) -> bool:
            return False

        def read(self, size: int = -1) -> bytes:
            return self._b.read(size)

    kg = make(**options())
    assert (await call(kg.scan_file(io.BytesIO(b"MOCK-MALWARE"), filename="s.bin"))).infected
    assert (await call(kg.scan_file(Pipe(b"MOCK-MALWARE"), filename="p.bin"))).infected
    assert not (await call(kg.scan_file(io.BytesIO(b"fine"), filename="b.txt"))).infected


@both
async def test_max_bytes_is_enforced_before_sending(make: Any, api: MockApi) -> None:
    kg = make(**options(max_bytes=3))
    with pytest.raises(K.PayloadTooLargeError):
        await call(kg.scan_bytes(b"toolong"))
    with pytest.raises(K.PayloadTooLargeError):
        await call(kg.scan_file(io.BytesIO(b"toolong")))
    assert api.api_calls == 0


@both
async def test_unreadable_path_is_a_scan_error(make: Any, api: MockApi) -> None:
    with pytest.raises(K.ScanError) as info:
        await call(make(**options()).scan_file("/definitely/not/here.bin"))
    assert info.value.code == "FILE_UNREADABLE"


@both
async def test_policy_and_degraded_flags(make: Any, api: MockApi) -> None:
    api.fail_next.append(
        (
            406,
            {
                "av-status": "INFECTED",
                "av-signature": "POLICY: macro | WARNING: yara did not complete - scan coverage reduced",
            },
            {},
        )
    )
    r = await call(make(**options(bearer_token="static", max_retries=0)).scan_bytes(b"x"))
    assert r.policy_rejected and r.degraded


@both
async def test_scan_url(make: Any, api: MockApi) -> None:
    r = await call(make(**options()).scan_url("https://example.com/file.pdf"))
    assert r.status == "CLEAN" and r.filename == "remote.bin"


# ---- authentication


@both
async def test_token_cached_across_calls(make: Any, api: MockApi) -> None:
    kg = make(**options())
    for _ in range(4):
        await call(kg.scan_bytes(b"x"))
    assert api.token_calls == 1


def test_concurrent_callers_share_one_token_request_sync() -> None:
    api = MockApi()
    kg = K.KelpgateClient(API, **options(transport=api.transport()))
    threads = [threading.Thread(target=lambda: kg.scan_bytes(b"x")) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert api.token_calls == 1
    kg.close()


def test_concurrent_callers_share_one_token_request_async() -> None:
    api = MockApi()

    async def main() -> None:
        kg = K.AsyncKelpgateClient(API, **options(transport=api.transport()))
        await asyncio.gather(*(kg.scan_bytes(b"x") for _ in range(8)))
        await kg.aclose()

    asyncio.run(main())
    assert api.token_calls == 1


@both
async def test_token_is_renewed_before_it_expires(make: Any, api: MockApi) -> None:
    api.token_ttl = 60  # inside the 120 s refresh-ahead window
    kg = make(**options())
    await call(kg.scan_bytes(b"a"))
    await call(kg.scan_bytes(b"b"))
    assert api.token_calls == 2


@both
async def test_a_revoked_token_is_replaced_once_after_a_401(make: Any, api: MockApi) -> None:
    kg = make(**options())
    await call(kg.scan_bytes(b"warm"))
    api.valid_token = "something-else"  # the server no longer accepts the cached token
    before = api.token_calls
    r = await call(kg.scan_bytes(b"again"))
    assert not r.infected and api.token_calls == before + 1


@both
async def test_wrong_secret_is_an_auth_error_that_hides_the_secret(make: Any, api: MockApi) -> None:
    kg = make(**options(client_secret="wrong-secret"))
    with pytest.raises(K.AuthError) as info:
        await call(kg.scan_bytes(b"x"))
    assert info.value.code == "TOKEN_REQUEST_FAILED" and "wrong-secret" not in str(info.value)


@both
async def test_bearer_token_skips_the_token_endpoint(make: Any, api: MockApi) -> None:
    kg = make(bearer_token="static")
    await call(kg.scan_bytes(b"x"))
    assert api.token_calls == 0


@both
async def test_credentials_are_not_sent_across_a_redirect(make: Any, api: MockApi) -> None:
    api.fail_next.append((302, {}, {"location": "https://evil.example.test/steal"}))
    kg = make(bearer_token="static", max_retries=0)
    with pytest.raises(K.KelpgateError):
        await call(kg.scan_bytes(b"x"))
    assert all(r.url.host != "evil.example.test" for r in api.requests)


# ---- errors and retries


@both
async def test_error_mapping(make: Any, api: MockApi) -> None:
    kg = make(**options(max_retries=0))
    cases = [
        (402, {"error": "q", "quota": 10, "usage": 10, "upgrade_url": "https://u"}, K.QuotaExceededError),
        (413, {"error": "big", "upgrade_url": "https://u"}, K.PayloadTooLargeError),
        (415, {"error": "type"}, K.UnsupportedFileError),
        (429, {"error": "busy"}, K.RateLimitedError),
        (412, {"error": "bad"}, K.ScanError),
        (500, {"error": "boom"}, K.ServerError),
        (403, {"error": "suspended"}, K.AuthError),
    ]
    for status, body, cls in cases:
        api.fail_next.append((status, body, {}))
        with pytest.raises(cls) as info:
            await call(kg.scan_bytes(b"x"))
        assert info.value.status == status and info.value.request_id == "req-test", status
    api.fail_next.append((402, {"quota": 5, "usage": 6, "upgrade_url": "https://u"}, {}))
    with pytest.raises(K.QuotaExceededError) as q:
        await call(kg.scan_bytes(b"x"))
    assert (q.value.quota, q.value.usage, q.value.upgrade_url) == (5, 6, "https://u")


@both
async def test_retries_503_and_429_then_succeeds(make: Any, api: MockApi) -> None:
    api.fail_next.extend([(503, {}, {}), (429, {}, {"retry-after": "0"})])
    r = await call(make(**options(max_retries=2)).scan_bytes(b"ok"))
    assert not r.infected


@both
async def test_gives_up_after_max_retries(make: Any, api: MockApi) -> None:
    api.fail_next.extend([(503, {}, {})] * 3)
    with pytest.raises(K.ServerError):
        await call(make(**options(max_retries=1)).scan_bytes(b"x"))


@both
async def test_a_retry_sends_the_whole_file_again(make: Any, api: MockApi) -> None:
    api.fail_next.append((503, {}, {}))
    kg = make(**options(max_retries=2))
    r = await call(kg.scan_file(io.BytesIO(b"xx MOCK-MALWARE xx"), filename="r.bin"))
    assert r.infected  # the second attempt carried the full content
    uploads = [q for q in api.requests if q.url.path == "/api/v1/scan/file"]
    assert len(uploads) == 2 and all(b"MOCK-MALWARE" in q.content for q in uploads)


@both
async def test_network_failure_and_timeout(make: Any, api: MockApi) -> None:
    kg = make(**options(max_retries=1))
    api.fail_next.extend([httpx.ConnectError("refused")] * 2)
    with pytest.raises(K.NetworkError):
        await call(kg.scan_bytes(b"x"))
    api.fail_next.extend([httpx.ReadTimeout("slow")] * 2)
    with pytest.raises(K.RequestTimeout):
        await call(kg.scan_bytes(b"x"))
    api.fail_next.append(httpx.ConnectError("blip"))  # one blip is retried and succeeds
    assert not (await call(kg.scan_bytes(b"x"))).infected


# ---- asynchronous scans and health


@both
async def test_submit_poll_and_wait(make: Any, api: MockApi) -> None:
    kg = make(**options())
    acc = await call(kg.scan_file_async(b"hello", filename="a.txt", webhook_url="https://example.com/hook"))
    assert acc.scan_id == "scan-1"
    assert b'name="webhook_url"' in api.requests[-1].content
    first = await call(kg.get_async_result(acc.scan_id))
    assert isinstance(first, K.PendingScan)
    done = await call(kg.wait_for_result(acc.scan_id, interval=0.001, timeout=5))
    assert done.status == "CLEAN"


@both
async def test_submit_url_sends_the_webhook(make: Any, api: MockApi) -> None:
    kg = make(**options())
    acc = await call(kg.scan_url_async("https://example.com/f", webhook_url="https://example.com/hook"))
    assert acc.scan_id == "scan-2" and b"example.com/hook" in api.requests[-1].content


@both
async def test_wait_times_out(make: Any, api: MockApi) -> None:
    api.poll_until = 10**9
    with pytest.raises(K.RequestTimeout):
        await call(make(**options()).wait_for_result("scan-1", interval=0.005, timeout=0.03))


@both
async def test_health_needs_no_credentials(make: Any, api: MockApi) -> None:
    h = await call(make(bearer_token="x").health())
    assert (h.ok, h.signature_version) == (True, "v-test")
    assert "authorization" not in api.requests[-1].headers


# ---- Idempotency-Key


def _scans(api: MockApi, path: str) -> list[httpx.Request]:
    return [q for q in api.requests if q.url.path == path]


@both
async def test_every_scan_sends_a_key_and_retries_reuse_it(make: Any, api: MockApi) -> None:
    api.fail_next.extend([(503, {}, {}), (502, {}, {})])
    await call(make(**options(max_retries=2)).scan_bytes(b"ok"))
    sent = _scans(api, "/api/v1/scan/file")
    assert len(sent) == 3
    key = sent[0].headers["idempotency-key"]
    assert uuid.UUID(key).version == 4
    assert all(q.headers["idempotency-key"] == key for q in sent)


@both
async def test_separate_calls_get_separate_keys(make: Any, api: MockApi) -> None:
    kg = make(**options())
    await call(kg.scan_bytes(b"one"))
    await call(kg.scan_bytes(b"two"))
    first, second = _scans(api, "/api/v1/scan/file")
    assert first.headers["idempotency-key"] != second.headers["idempotency-key"]


@both
async def test_the_retry_after_a_401_reuses_the_same_key(make: Any, api: MockApi) -> None:
    api.fail_next.append((401, {"error": "unauthorized"}, {}))
    await call(make(**options()).scan_bytes(b"ok"))
    sent = _scans(api, "/api/v1/scan/file")
    assert len(sent) == 2
    assert sent[1].headers["idempotency-key"] == sent[0].headers["idempotency-key"]


@both
async def test_a_key_you_pass_is_sent_as_given_on_every_scan_operation(make: Any, api: MockApi) -> None:
    kg = make(**options())
    key = "job-42:upload.1"
    await call(kg.scan_file(b"ok", idempotency_key=key))
    await call(kg.scan_bytes(b"ok", idempotency_key=key))
    await call(kg.scan_url("https://example.com/f.bin", idempotency_key=key))
    await call(kg.scan_file_async(b"ok", idempotency_key=key))
    await call(kg.scan_url_async("https://example.com/f.bin", idempotency_key=key))
    for path in ("/api/v1/scan/url", "/api/v1/async-scan/file", "/api/v1/async-scan/url"):
        assert _scans(api, path)[0].headers["idempotency-key"] == key, path
    assert [q.headers["idempotency-key"] for q in _scans(api, "/api/v1/scan/file")] == [key, key]


@both
async def test_an_invalid_key_is_a_config_error_before_any_request(make: Any, api: MockApi) -> None:
    kg = make(**options())
    for bad in ["", "has space", "a/b", "x" * 129, "ünï", "ok\n", 123]:
        before = len([q for q in api.requests if q.url.path.startswith("/api/")])
        with pytest.raises(K.ConfigError):
            await call(kg.scan_bytes(b"ok", idempotency_key=bad))
        with pytest.raises(K.ConfigError):
            await call(kg.scan_url("https://example.com/f.bin", idempotency_key=bad))
        assert len([q for q in api.requests if q.url.path.startswith("/api/")]) == before, repr(bad)
    r = await call(kg.scan_bytes(b"ok", idempotency_key="x" * 128))  # the longest allowed key
    assert not r.infected


@both
async def test_calls_that_are_not_counted_do_not_send_a_key(make: Any, api: MockApi) -> None:
    kg = make(**options())
    await call(kg.health())
    await call(kg.get_async_result("scan-1"))
    sent = [q for q in api.requests if q.url.path.startswith("/api/")]
    assert len(sent) >= 2
    assert all("idempotency-key" not in q.headers for q in sent)
