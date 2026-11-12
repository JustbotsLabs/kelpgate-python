# Changelog

## 0.1.0

First release.

- `KelpgateClient` and `AsyncKelpgateClient`: scan files (path, bytes, file object) and URLs, sync or async, with `submit_*`, `get_result` and `wait`.
- OAuth2 client-credentials with a cached token, renewed before it expires, one renewal at a time.
- Retries on network errors, 429, 502, 503 and 504; typed errors for every API status.
- `kelpgate` command line tool with folder scanning (`-r`) and parallel workers.
- FastAPI helpers (`kelpgate.integrations.fastapi`) and a Django validator (`kelpgate.integrations.django`).
- Typed (`py.typed`), Python 3.9 to 3.13, one runtime dependency (`httpx`).
