from __future__ import annotations

from pathlib import Path

from agentguard.discovery import scan_configs
from agentguard.render import (
    FINDINGS_SCHEMA_VERSION,
    render_findings_summary_markdown,
    scan_report_to_findings,
    to_json,
)


def test_findings_json_has_stable_summary_and_findings(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        """
        {
          "mcpServers": {
            "github": {
              "command": "docker",
              "args": ["run", "github"],
              "env": {"GITHUB_TOKEN": "redacted"}
            }
          }
        }
        """,
        encoding="utf-8",
    )

    report = scan_configs([config])
    payload = scan_report_to_findings(report)
    finding = payload["findings"][0]

    assert payload["schema_version"] == FINDINGS_SCHEMA_VERSION
    assert payload["summary"]["finding_count"] == 1
    assert payload["summary"]["highest_risk"] == "critical"
    assert payload["summary"]["by_risk"]["critical"] == 1
    assert finding["id"].startswith("AG-MCP-")
    assert finding["name"] == "github"
    assert finding["risk"] == "critical"
    assert "credential_access" in finding["capabilities"]


def test_findings_json_redacts_secret_like_args(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        """
        {
          "mcpServers": {
            "unsafe": {
              "command": "agentguard-token-test",
              "args": ["--api-key", "sk-abcdefghijklmnopqrstuvwxyz"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    payload = scan_report_to_findings(scan_configs([config]))
    serialized = to_json(payload)

    assert "sk-abcdefghijklmnopqrstuvwxyz" not in serialized
    assert "[REDACTED:openai_key]" in serialized


def test_findings_summary_markdown_is_compact(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        '{"mcpServers":{"fs":{"command":"npx","args":["server-filesystem","."]}}}',
        encoding="utf-8",
    )

    output = render_findings_summary_markdown(scan_configs([config]))

    assert "# AgentGuard CI Summary" in output
    assert "Highest risk: **high**" in output
    assert "| high | 1 |" in output
