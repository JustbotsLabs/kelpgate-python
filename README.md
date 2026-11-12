# kelpgate

Python client for the [Kelpgate](https://kelpgate.cloud) malware-scanning API. Scan uploaded files or remote URLs, get a verdict, and keep infected files out of your app.

- Sync and asyncio clients with the same methods, fully typed.
- Handles the OAuth2 token for you: fetched once, cached, renewed before it expires.
- Retries transient failures. Typed errors for quota, size, file type and rate limits.
- A `kelpgate` command line tool, plus helpers for FastAPI and Django.
- Python 3.9 to 3.13. One runtime dependency, [httpx](https://www.python-httpx.org/).

> This package is open source under GPL-2.0-or-later. It is a client for the Kelpgate scanning service, a hosted commercial product that is not part of this package. You need a Kelpgate account to use it.

```bash
pip install kelpgate
```

## Quick start

Create an API client in the [Kelpgate console](https://console.kelpgate.cloud), then:

```python
from kelpgate import Kelpgate

kg = Kelpgate(
    "https://api.kelpgate.cloud",
    token_url="https://auth.kelpgate.cloud/oauth2/token",
    client_id="...",
    client_secret="...",
)

result = kg.scan_file("upload.pdf")
if result.infected:
    print("Rejected:", result.signature)
```

`Kelpgate.from_env()` builds the same client from `KELPGATE_CLIENT_ID` and `KELPGATE_CLIENT_SECRET` (or `KELPGATE_TOKEN`), with optional `KELPGATE_API_URL` and `KELPGATE_TOKEN_URL`. Use the client as a context manager (`with Kelpgate.from_env() as kg:`) so connections are closed.

For asyncio, use `AsyncKelpgate` and `await` each call:

```python
from kelpgate import AsyncKelpgate

async with AsyncKelpgate.from_env() as kg:
    result = await kg.scan_bytes(data, filename="report.docx")
```

## Scanning

| Method | What it does |
| --- | --- |
| `scan_file(source)` | Scan a path, `bytes` or a binary file object |
| `scan_bytes(data)` | Same, for bytes in memory |
| `scan_url(url)` | Kelpgate fetches the URL and scans it |
| `submit_file(source)`, `submit_url(url)` | Start an asynchronous scan and get a `scan_id`. Pass `webhook_url` to be called back |
| `get_result(scan_id)` | A `PendingScan` until the verdict is ready, then a `ScanResult` |
| `wait(scan_id, interval=1, timeout=120)` | Poll until the scan finishes |
| `health()` | Service status. Needs no credentials |

A `ScanResult` has `infected`, `status`, `signature`, `sha256`, `scan_id`, `rule_authors`, `request_id` and the full response in `raw`. Two flags are worth checking:

- `policy_rejected`: the file was refused by policy (for example a disallowed type), not detected as malware.
- `degraded`: an engine did not finish, so coverage was reduced for this scan.

An infected file is a normal result, not an exception. Call `assert_clean(result)` if you prefer an exception. Files given as paths or file objects are streamed, not read into memory, and a retry sends the whole file again.

## Errors

Every error derives from `KelpgateError` and carries `status`, `code`, `request_id` (quote it to support) and the response `body`.

| Error | When |
| --- | --- |
| `AuthError` | Bad credentials (401) or a suspended organisation (403) |
| `QuotaExceededError` | Plan quota used up (402); has `quota`, `usage`, `upgrade_url` |
| `PayloadTooLargeError` | File over the plan limit (413) or the client's `max_bytes` |
| `UnsupportedFileError` | File type not allowed, or an encrypted archive (415) |
| `RateLimitedError` | Too many scans at once (429); has `retry_after` |
| `ScanError` | Invalid request (400), unparsable file (412) or an unreadable path |
| `ServerError` | 5xx |
| `NetworkError`, `RequestTimeout` | The service could not be reached |
| `ConfigError` | Wrong options, raised by the constructor |
| `InfectedError` | Raised by `assert_clean` |

## Options

`api_url`, `token_url`, `client_id`, `client_secret` (or `bearer_token`), `scope` (default `scan`), `timeout` (60 s), `max_retries` (2), `retry_delay` (0.5 s), `max_bytes` (128 MiB), `transport`.

Both URLs must be `https`; plain `http` is accepted only for `localhost`. Redirects are never followed, so credentials cannot be sent to another host. Secrets never appear in `repr()` or in error messages.

## FastAPI

```python
from fastapi import Depends, FastAPI, UploadFile
from kelpgate import AsyncKelpgate
from kelpgate.integrations.fastapi import scan_dependency

app = FastAPI()
kelpgate = AsyncKelpgate.from_env()

@app.post("/upload")
async def upload(file: UploadFile = Depends(scan_dependency(kelpgate))):
    ...  # only reached for files that scanned clean
```

An infected file gets a `422`. If the scan cannot run the request gets a `503` (`on_error="allow"` lets it through instead). For a field with another name, call `scan_upload(client, upload)` yourself.

## Django

```python
# settings.py
KELPGATE = {"CLIENT_ID": "...", "CLIENT_SECRET": "..."}   # or the KELPGATE_* environment variables

# models.py
from kelpgate.integrations.django import KelpgateValidator

class Document(models.Model):
    file = models.FileField(upload_to="docs/", validators=[KelpgateValidator()])
```

An infected file fails validation with the code `infected`. If the scan cannot run, validation fails with `scan_unavailable`, or passes with `KelpgateValidator(on_error="allow")`.

## Command line

```bash
export KELPGATE_CLIENT_ID=... KELPGATE_CLIENT_SECRET=...
kelpgate scan ./file.zip other.pdf
kelpgate scan -r ./uploads          # a whole folder, 4 files at a time (-w to change)
kelpgate scan-url https://example.com/file.exe
kelpgate health
```

Exit code `0` clean, `1` infected, `2` error. Add `--json` for one JSON object per line. Folders are scanned without following symbolic links.

## Compatibility

Python 3.9, 3.10, 3.11, 3.12 and 3.13, with `httpx` 0.25 or later. The test suite runs on every one of those Python versions, with Django 4.2, 5.2 and 6.1 and a current FastAPI.

## Contributing and security

Bug reports and pull requests are welcome; see the [contributing guide](https://github.com/JustBots-Labs/.github/blob/main/CONTRIBUTING.md). To report a vulnerability, email security@kelpgate.cloud or follow the [security policy](https://github.com/JustBots-Labs/.github/blob/main/SECURITY.md). For help, see [getting help](https://github.com/JustBots-Labs/.github/blob/main/SUPPORT.md).

```bash
pip install -e ".[dev]"
pytest && ruff check . && mypy
```

## Licence

GPL-2.0-or-later. See [LICENSE](LICENSE). The GPL applies to software you distribute that includes this package; using it on your own server does not require you to publish your code.
