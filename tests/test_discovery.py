from __future__ import annotations

from pathlib import Path

from agentguard.discovery import scan_configs
from agentguard.models import Capability, RiskLevel


def test_scan_classifies_filesystem_and_credential_risk(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        """
        {
          "mcpServers": {
            "fs": {"command": "npx", "args": ["server-filesystem", "."]},
            "github": {"command": "docker", "args": ["run", "github"], "env": {"GITHUB_TOKEN": "x"}}
          }
        }
        """,
        encoding="utf-8",
    )

    report = scan_configs([config])

    assert len(report.findings) == 2
    assert report.highest_risk == RiskLevel.CRITICAL
    github = next(item for item in report.findings if item.name == "github")
    assert Capability.CREDENTIAL_ACCESS in github.capabilities
