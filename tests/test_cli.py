from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from conftest import API, MockApi, options
from kelpgate import KelpgateClient, cli


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, api: MockApi, capsys: pytest.CaptureFixture[str]) -> Any:
    def from_env(cls: Any, env: Any = None, **overrides: Any) -> KelpgateClient:
        return KelpgateClient(API, **options(transport=api.transport()))

    monkeypatch.setattr(KelpgateClient, "from_env", classmethod(from_env))

    def go(*argv: str) -> Dict[str, Any]:
        code = cli.main(list(argv))
        out = capsys.readouterr()
        return {"code": code, "out": out.out, "err": out.err}

    return go


def test_clean_file_exits_0(run: Any, tmp_path: Path) -> None:
    f = tmp_path / "ok.txt"
    f.write_text("fine")
    r = run("scan", str(f))
    assert r["code"] == 0 and "clean" in r["out"]


def test_infected_file_exits_1(run: Any, tmp_path: Path) -> None:
    ok, bad = tmp_path / "ok.txt", tmp_path / "bad.txt"
    ok.write_text("fine")
    bad.write_text("MOCK-MALWARE")
    r = run("scan", str(ok), str(bad))
    assert r["code"] == 1 and "INFECTED" in r["out"]


def test_json_output_is_one_object_per_line(run: Any, tmp_path: Path) -> None:
    bad = tmp_path / "bad.txt"
    bad.write_text("MOCK-MALWARE")
    r = run("scan", "--json", str(bad))
    rec = json.loads(r["out"].strip())
    assert rec["infected"] is True and rec["target"] == str(bad)


def test_recursive_scan_walks_folders_and_skips_links(run: Any, tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "one.txt").write_text("fine")
    (tmp_path / "a" / "two.txt").write_text("MOCK-MALWARE")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("fine")
    os.symlink(outside, tmp_path / "a" / "link")
    r = run("scan", "-r", "--json", str(tmp_path / "a"))
    targets: List[str] = [json.loads(line)["target"] for line in r["out"].strip().splitlines()]
    assert r["code"] == 1 and len(targets) == 2 and not any("secret" in t for t in targets)


def test_a_folder_without_r_is_an_error(run: Any, tmp_path: Path) -> None:
    r = run("scan", str(tmp_path))
    assert r["code"] == 2 and "-r" in r["err"]


def test_errors_exit_2_and_do_not_print_the_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], api: MockApi, tmp_path: Path
) -> None:
    def from_env(cls: Any, env: Any = None, **o: Any) -> KelpgateClient:
        return KelpgateClient(API, **options(client_secret="wrong-secret", transport=api.transport()))

    monkeypatch.setattr(KelpgateClient, "from_env", classmethod(from_env))
    f = tmp_path / "x.txt"
    f.write_text("x")
    code = cli.main(["scan", str(f)])
    err = capsys.readouterr().err
    assert code == 2 and "wrong-secret" not in err


def test_health_and_version(run: Any, capsys: pytest.CaptureFixture[str]) -> None:
    assert run("health")["code"] == 0
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0 and "kelpgate" in capsys.readouterr().out


def test_scan_url(run: Any) -> None:
    r = run("scan-url", "https://example.com/file.pdf")
    assert r["code"] == 0 and "clean" in r["out"]
