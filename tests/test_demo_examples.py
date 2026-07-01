from __future__ import annotations

from pathlib import Path

from agentguard.discovery import scan_configs
from agentguard.gate import scan_report_fails_gate
from agentguard.models import Capability, RiskLevel


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_safe_demo_config_stays_below_high_gate() -> None:
    report = scan_configs([REPO_ROOT / "examples" / "safe_mcp_config.json"])

    assert report.highest_risk == RiskLevel.MEDIUM
    assert not scan_report_fails_gate(report, RiskLevel.HIGH)


def test_dangerous_demo_config_trips_high_gate() -> None:
    report = scan_configs([REPO_ROOT / "examples" / "dangerous_mcp_config.json"])
    capabilities = {
        capability
        for finding in report.findings
        for capability in finding.capabilities
    }

    assert report.highest_risk == RiskLevel.CRITICAL
    assert Capability.CREDENTIAL_ACCESS in capabilities
    assert Capability.PRODUCTION_MUTATION in capabilities
    assert Capability.SHELL_EXECUTION in capabilities
    assert scan_report_fails_gate(report, RiskLevel.HIGH)
