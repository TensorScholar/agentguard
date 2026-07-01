from __future__ import annotations

from pathlib import Path

from pytest import CaptureFixture

from agentguard.cli import main
from agentguard.demo import write_demo


def test_write_demo_creates_expected_files(tmp_path: Path) -> None:
    output = tmp_path / "demo"

    written = write_demo(output)

    assert {path.name for path in written} == {
        "README.md",
        "dangerous_mcp_config.json",
        "policy.yaml",
        "safe_mcp_config.json",
        "tool_calls.jsonl",
    }
    assert "dangerous_mcp_config.json" in (output / "README.md").read_text(encoding="utf-8")


def test_write_demo_refuses_non_empty_directory(tmp_path: Path) -> None:
    output = tmp_path / "demo"
    output.mkdir()
    (output / "existing.txt").write_text("keep me\n", encoding="utf-8")

    try:
        write_demo(output)
    except FileExistsError as exc:
        assert str(output) in str(exc)
    else:
        raise AssertionError("expected FileExistsError")


def test_demo_command_writes_files_and_next_step(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    output = tmp_path / "demo"

    exit_code = main(["demo", "--output", str(output)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert (output / "dangerous_mcp_config.json").exists()
    assert str(output / "dangerous_mcp_config.json") in captured.out


def test_demo_command_refuses_to_overwrite_without_force(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    output = tmp_path / "demo"
    output.mkdir()
    (output / "existing.txt").write_text("keep me\n", encoding="utf-8")

    exit_code = main(["demo", "--output", str(output)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "refusing to overwrite" in captured.err
