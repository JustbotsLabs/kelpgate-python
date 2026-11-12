# Changelog

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
