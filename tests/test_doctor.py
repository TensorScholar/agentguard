from __future__ import annotations

import json
from pathlib import Path

from pytest import CaptureFixture

from agentguard.cli import main
from agentguard.doctor import run_doctor


def test_run_doctor_reports_required_local_checks(tmp_path: Path) -> None:
    report = run_doctor(tmp_path)
    checks = {check.name: check for check in report.checks}

    assert report.ok
    assert checks["python"].status == "pass"
    assert checks["sqlite"].status == "pass"
    assert checks["package"].status == "pass"
    assert checks["local_output"].status == "pass"


def test_run_doctor_fails_when_output_path_is_missing(tmp_path: Path) -> None:
    report = run_doctor(tmp_path / "missing")
    checks = {check.name: check for check in report.checks}

    assert not report.ok
    assert checks["local_output"].status == "fail"


def test_doctor_cli_outputs_json(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    exit_code = main(["doctor", "--format", "json", "--workdir", str(tmp_path)])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["version"]
    assert {check["name"] for check in payload["checks"]} >= {
        "python",
        "sqlite",
        "package",
        "local_output",
    }
