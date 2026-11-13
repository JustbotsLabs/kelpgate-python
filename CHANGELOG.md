# Changelog

## 0.4.0

- Every scan now sends an `Idempotency-Key`, so a retry after a timeout or a 502, 503 or 504 is not counted against your quota twice. The client makes a random key for each call and reuses it on its own retries; no change is needed in your code.
- New optional `idempotency_key` argument on `scan_file`, `scan_bytes`, `scan_url`, `scan_file_async` and `scan_url_async` (sync and async clients), to protect your own retries (a job id, for example). An invalid key (not 1 to 128 characters from `A-Za-z0-9._:-`) raises `ConfigError` before any request. Do not reuse one key for different files: the service counts a different file under the same key as a new scan.
- See the [Kelpgate client standard](https://github.com/KelpGate/.github/blob/main/docs/client-standard.md#idempotency).

## 0.3.0

- The license changed from GPL-2.0-or-later to MIT, so the package can be used in proprietary software as well as open-source software. Versions published earlier remain available under the GPL. The WordPress plugin and Drupal module stay GPL, as WordPress.org and Drupal.org require.
- No code changes.

## 0.2.0

- Method names now match the other Kelpgate clients (see the [Kelpgate client standard](https://github.com/KelpGate/.github/blob/main/docs/client-standard.md)): `scan_file_async`, `scan_url_async`, `get_async_result` and `wait_for_result`.
- The earlier names `submit_file`, `submit_url`, `get_result` and `wait` still work as aliases. Nothing that worked in 0.1.x breaks.

## 0.1.1

- Package metadata names JustBots Labs as the author. No code changes.

## 0.1.0

First release.

- `KelpgateClient` and `AsyncKelpgateClient`: scan files (path, bytes, file object) and URLs, sync or async, with `submit_*`, `get_result` and `wait`.
- OAuth2 client-credentials with a cached token, renewed before it expires, one renewal at a time.
- Retries on network errors, 429, 502, 503 and 504; typed errors for every API status.
- `kelpgate` command line tool with folder scanning (`-r`) and parallel workers.
- FastAPI helpers (`kelpgate.integrations.fastapi`) and a Django validator (`kelpgate.integrations.django`).
- Typed (`py.typed`), Python 3.9 to 3.13, one runtime dependency (`httpx`).
