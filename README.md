# Kelpgate Client for Python

**Check every upload for malware before your app stores it.**

Python client for the [Kelpgate](https://kelpgate.cloud) malware-scanning API. Scan uploaded files or remote URLs, get a verdict, and keep infected files out of your app. It includes sync and asyncio clients, helpers for FastAPI and Django, and a command line tool.

> This package is open source under GPL-2.0-or-later. It is a client for the Kelpgate scanning service, a hosted commercial product that is not part of this package. You need a Kelpgate account to use it.

## Contents

[Why Kelpgate](#why-kelpgate) · [How it works](#how-it-works) · [Install](#install) · [Quick start](#quick-start) · [Scanning](#scanning) · [Errors](#errors) · [Options](#options) · [FastAPI](#fastapi) · [Django](#django) · [Command line](#command-line) · [Failure policy](#failure-policy) · [Security and privacy](#security-and-privacy) · [Compatibility](#compatibility) · [Verify your setup](#verify-your-setup) · [Troubleshooting](#troubleshooting) · [Support and versioning](#support-and-versioning) · [Contributing and security](#contributing-and-security) · [License](#license)

## Why Kelpgate

| | |
| --- | --- |
| **One call per file** | Send a path, bytes, a file object or a URL and get a verdict back. An infected file is a normal result, not an exception. |
| **Sync and asyncio** | `KelpgateClient` and `AsyncKelpgateClient` have the same methods and are fully typed. |
| **Credentials handled for you** | The OAuth 2.0 access token is fetched, cached in memory and renewed before it expires, one renewal at a time. |
| **Predictable failure behavior** | Typed errors for quota, size, file type, rate limits and network problems. You choose what happens when the scanner cannot answer: block or allow. |
| **Safe by default** | API and token URLs must use HTTPS, redirects are never followed, and secrets never appear in `repr()` or errors. |
| **Ready for your stack** | FastAPI and Django helpers and a command line tool. One runtime dependency, [httpx](https://www.python-httpx.org/). |

## How it works

1. The client obtains an OAuth 2.0 access token with your client credentials. Tokens are cached and renewed shortly before they expire.
2. The file is sent to the scanning API over HTTPS.
3. The API answers with a verdict. A clean file and an infected file (HTTP 406) both come back as a result with `infected` set to `False` or `True`. Anything that stops a verdict, such as an exhausted quota or an unreachable service, is raised as a typed error. Your code, or the FastAPI and Django helpers, decide what to do next.

## Install

```bash
pip install kelpgate-client
```

The package is `kelpgate-client` on PyPI and you import it as `kelpgate`. It needs Python 3.9 or newer. You also need a Kelpgate account.

## Quick start

Create an API client in the [Kelpgate Console](https://console.kelpgate.cloud), then:

```python
from kelpgate import KelpgateClient

kg = KelpgateClient(
    "https://api.kelpgate.cloud",
    token_url="https://auth.kelpgate.cloud/oauth2/token",
    client_id="...",
    client_secret="...",
)

result = kg.scan_file("upload.pdf")
if result.infected:
    print("Rejected:", result.signature)
```

`KelpgateClient.from_env()` builds the same client from `KELPGATE_CLIENT_ID` and `KELPGATE_CLIENT_SECRET` (or `KELPGATE_TOKEN`), with optional `KELPGATE_API_URL` and `KELPGATE_TOKEN_URL`. Use the client as a context manager (`with KelpgateClient.from_env() as kg:`) so connections are closed.

For asyncio, use `AsyncKelpgateClient` and `await` each call:

```python
from kelpgate import AsyncKelpgateClient

async with AsyncKelpgateClient.from_env() as kg:
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

An infected file is a normal result, not an exception. Call `assert_clean(result)` if you prefer an exception. Paths and seekable file objects are streamed, not read into memory; other streams are buffered in memory up to `max_bytes`. A retry sends the whole file again.

## Errors

Every error derives from `KelpgateError` and carries `status`, `code`, `request_id` (quote it to support) and the response `body`.

| Error | When |
| --- | --- |
| `AuthError` | Bad credentials (401) or a suspended organization (403) |
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
from kelpgate import AsyncKelpgateClient
from kelpgate.integrations.fastapi import scan_dependency

app = FastAPI()
kelpgate = AsyncKelpgateClient.from_env()

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

## Failure policy

When the scanner cannot give a verdict, the client raises a typed error. The FastAPI and Django helpers turn that into a decision you control with `on_error`.

| Situation | Client | FastAPI, `on_error="block"` (default) | Django, `on_error="block"` (default) | `on_error="allow"` |
| --- | --- | --- | --- | --- |
| Scanner unreachable, timed out or returned 5xx after retries | Raises `NetworkError`, `RequestTimeout` or `ServerError` | `503` | Validation error `scan_unavailable` | Upload continues |
| Authentication fails | Raises `AuthError` | `503` | `scan_unavailable` | Continues |
| Plan quota used up | Raises `QuotaExceededError` | `402` | `scan_unavailable` | Continues |
| File over the plan limit or `max_bytes` | Raises `PayloadTooLargeError` | `413` | `scan_unavailable` | Continues |
| File type not allowed | Raises `UnsupportedFileError` | `415` | `scan_unavailable` | Continues |

Choose `block` where stopping malware matters more than availability, and `allow` where uploads must keep working during an outage.

## Security and privacy

- **What leaves your server:** the uploaded file and its file name, sent over HTTPS to the API URL you configure. Nothing else about your application is sent.
- **Transport:** API and token endpoints must use HTTPS (plain HTTP is accepted only for `localhost`). Redirects are never followed.
- **Secrets:** the client secret never appears in `repr()` or in error messages. Keep it in an environment variable or a secrets manager, not in source control.
- **Token handling:** access tokens are kept in memory only, never written to disk, and refreshed ahead of expiry. A rejected token is discarded and retried once.
- **Nothing stored locally:** the package writes nothing to disk. Files are read from where they already are.
- **Data kept by the service:** files that scan clean are kept briefly and infected files are quarantined, according to your Kelpgate plan. That is the service's behavior, not this package's.

## Compatibility

Python 3.9, 3.10, 3.11, 3.12 and 3.13, with `httpx` 0.25 or later. The test suite runs on every one of those Python versions, with Django 4.2, 5.2 and 6.1 and a current FastAPI.

## Verify your setup

Download the standard EICAR test file from [eicar.org](https://www.eicar.org/download-anti-malware-testfile/). It is a harmless file that every scanner treats as a virus.

```bash
kelpgate scan ./eicar.com
```

The scan should report `INFECTED` and exit with code `1`. Then scan any ordinary file and confirm it reports `clean` and exits with `0`.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `ConfigError`: must use https | `api_url` or `token_url` is not HTTPS. Plain HTTP works only for `localhost`. |
| `AuthError` with code `TOKEN_REQUEST_FAILED` | The client ID or secret is wrong, or the API client does not have the `scan` scope. |
| `AuthError` with status 403 | The organization is suspended, or the API client is not linked to an organization. |
| `QuotaExceededError` | The plan's scan quota is used up. The error carries an `upgrade_url`. |
| `RateLimitedError`, or slow scans under load | Too many scans at once. The client retries and honours `Retry-After`; lower your concurrency. |
| `PayloadTooLargeError` | The file is over the plan limit or the client's `max_bytes`. |
| `RequestTimeout` on large files | Raise `timeout`, or use `submit_file` and `wait`. |
| Clean results with `degraded` set | An engine did not finish for that scan. The result is still valid; coverage was reduced. |

## Support and versioning

This project follows [Semantic Versioning](https://semver.org): breaking changes only in major versions, new features in minor versions, fixes in patch versions. Releases are tagged on GitHub, and user-visible changes are listed in the [changelog](CHANGELOG.md).

Fixes, including security fixes, go into the latest release only, so upgrade to receive them. The tested runtime versions are listed under Compatibility. The client talks to version 1 of the Kelpgate API (`/api/v1`).

For help, see [getting help](https://github.com/KelpGate/.github/blob/main/SUPPORT.md) or email support@kelpgate.cloud.

## Contributing and security

Bug reports and pull requests are welcome; see the [contributing guide](https://github.com/KelpGate/.github/blob/main/CONTRIBUTING.md). To report a vulnerability, email security@kelpgate.cloud or follow the [security policy](https://github.com/KelpGate/.github/blob/main/SECURITY.md). For help, see [getting help](https://github.com/KelpGate/.github/blob/main/SUPPORT.md).

```bash
pip install -e ".[dev]"
pytest && ruff check . && mypy
```

## License

GPL-2.0-or-later. See [LICENSE](LICENSE). The GPL applies to software you distribute that includes this package; using it on your own server does not require you to publish your code.
