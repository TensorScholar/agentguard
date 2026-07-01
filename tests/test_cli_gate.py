from __future__ import annotations

from pathlib import Path

from pytest import CaptureFixture, MonkeyPatch

from agentguard.cli import main


def test_gate_fails_when_config_crosses_risk_threshold(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        """
        {
          "mcpServers": {
            "github": {
              "command": "docker",
              "args": ["run", "github"],
              "env": {"GITHUB_TOKEN": "x"}
            }
          }
        }
        """,
        encoding="utf-8",
    )

    exit_code = main(["gate", "--config", str(config), "--fail-on-risk", "high"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "AgentGuard gate failed" in captured.err
    assert "Highest risk: **critical**" in captured.out


def test_gate_passes_when_config_stays_below_threshold(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        """
        {
          "mcpServers": {
            "docs": {"command": "node", "args": ["readme-viewer"]}
          }
        }
        """,
        encoding="utf-8",
    )

    exit_code = main(["gate", "--config", str(config), "--fail-on-risk", "critical"])

    assert exit_code == 0


def test_gate_uses_changed_config_paths(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        """
        {
          "mcpServers": {
            "fs": {"command": "npx", "args": ["server-filesystem", "."]}
          }
        }
        """,
        encoding="utf-8",
    )

    monkeypatch.setattr("agentguard.cli.changed_config_paths", lambda base, head: [config])

    exit_code = main(["gate", "--changed-from", "origin/main", "--fail-on-risk", "critical"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "fs" in captured.out


def test_scan_writes_report_output_file(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    config = tmp_path / "mcp.json"
    report = tmp_path / "reports" / "agentguard.md"
    config.write_text(
        '{"mcpServers":{"fs":{"command":"npx","args":["server-filesystem","."]}}}',
        encoding="utf-8",
    )

    exit_code = main(["scan", "--config", str(config), "--output", str(report)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == ""
    assert "AgentGuard Scan Report" in report.read_text(encoding="utf-8")
