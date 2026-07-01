from __future__ import annotations

from pathlib import Path

from pytest import CaptureFixture

from agentguard.cli import main


def test_init_writes_default_policy(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    output = tmp_path / ".agentguard" / "policy.yaml"

    exit_code = main(["init", "--output", str(output)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert output.exists()
    assert "coding-agent-local" in output.read_text(encoding="utf-8")
    assert str(output) in captured.out


def test_init_refuses_to_overwrite_existing_policy(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    output = tmp_path / "policy.yaml"
    output.write_text("existing: true\n", encoding="utf-8")

    exit_code = main(["init", "--output", str(output)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert output.read_text(encoding="utf-8") == "existing: true\n"
    assert "Refusing to overwrite" in captured.err


def test_init_force_overwrites_existing_policy(tmp_path: Path) -> None:
    output = tmp_path / "policy.yaml"
    output.write_text("existing: true\n", encoding="utf-8")

    exit_code = main(["init", "--pack", "ci-agent", "--output", str(output), "--force"])

    assert exit_code == 0
    assert "ci-agent" in output.read_text(encoding="utf-8")
