"""The ``kelpgate`` command line tool.

    kelpgate scan ./file.zip other.pdf
    kelpgate scan -r ./uploads
    kelpgate scan-url https://example.com/file.exe
    kelpgate health

Exit codes: 0 clean, 1 infected, 2 error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import Kelpgate, KelpgateError, ScanResult, __version__

_ENV_HELP = """\
environment:
  KELPGATE_CLIENT_ID, KELPGATE_CLIENT_SECRET   OAuth client credentials
  KELPGATE_TOKEN                               or a bearer token
  KELPGATE_API_URL, KELPGATE_TOKEN_URL         override the default endpoints
"""


def _files(paths: Iterable[str], recursive: bool) -> List[str]:
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            if not recursive:
                raise KelpgateError(f"{p} is a directory; use -r to scan it", code="CONFIG")
            for root, _dirs, names in os.walk(p, followlinks=False):  # never follow links out of the tree
                for n in sorted(names):
                    full = os.path.join(root, n)
                    if os.path.isfile(full) and not os.path.islink(full):
                        out.append(full)
        else:
            out.append(p)
    return out


def _record(target: str, r: ScanResult) -> Dict[str, Any]:
    return {
        "target": target,
        "infected": r.infected,
        "status": r.status,
        "signature": r.signature,
        "sha256": r.sha256,
        "scan_id": r.scan_id,
        "policy_rejected": r.policy_rejected,
        "degraded": r.degraded,
    }


def _line(target: str, r: ScanResult) -> str:
    note = f"  ({r.signature})" if r.infected or r.degraded else ""
    return f"{'INFECTED' if r.infected else 'clean   '}  {target}{note}"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kelpgate",
        description="Scan files and URLs for malware with Kelpgate.",
        epilog=_ENV_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"kelpgate {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_scan = sub.add_parser("scan", help="scan files, or folders with -r")
    p_scan.add_argument("paths", nargs="+")
    p_scan.add_argument("-r", "--recursive", action="store_true", help="scan folders recursively")
    p_scan.add_argument("-w", "--workers", type=int, default=4, help="parallel scans (default 4)")
    p_scan.add_argument("--json", action="store_true", help="print one JSON object per line")
    p_url = sub.add_parser("scan-url", help="have Kelpgate fetch and scan a URL")
    p_url.add_argument("urls", nargs="+")
    p_url.add_argument("--json", action="store_true")
    p_health = sub.add_parser("health", help="check the service")
    p_health.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    def emit(obj: Dict[str, Any], text: str) -> None:
        print(json.dumps(obj) if args.json else text, flush=True)

    try:
        with Kelpgate.from_env() as kg:
            if args.cmd == "health":
                h = kg.health()
                emit(
                    {"ok": h.ok, "status": h.status, "signature_version": h.signature_version},
                    f"{'ok' if h.ok else 'unhealthy'} (HTTP {h.status})"
                    + (f", signatures {h.signature_version}" if h.signature_version else ""),
                )
                return 0 if h.ok else 2
            infected = False
            if args.cmd == "scan-url":
                for u in args.urls:
                    r = kg.scan_url(u)
                    infected = infected or r.infected
                    emit(_record(u, r), _line(u, r))
                return 1 if infected else 0
            targets = _files(args.paths, args.recursive)
            if not targets:
                print("kelpgate: no files to scan", file=sys.stderr)
                return 2
            failed = False

            def one(path: str) -> tuple[str, Any]:
                try:
                    return path, kg.scan_file(path)
                except KelpgateError as exc:
                    return path, exc

            with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
                for path, outcome in pool.map(one, targets):
                    if isinstance(outcome, KelpgateError):
                        failed = True
                        print(
                            f"kelpgate: {path}: {outcome}"
                            + (f" (request {outcome.request_id})" if outcome.request_id else ""),
                            file=sys.stderr,
                        )
                        continue
                    infected = infected or outcome.infected
                    emit(_record(path, outcome), _line(path, outcome))
            return 2 if failed and not infected else (1 if infected else 0)
    except KelpgateError as exc:
        rid = f" (request {exc.request_id})" if exc.request_id else ""
        print(f"kelpgate: {exc}{rid}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
