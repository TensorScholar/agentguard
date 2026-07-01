from __future__ import annotations

from datetime import datetime, timezone

from agentguard.gate import risk_at_or_above, scan_report_fails_gate
from agentguard.models import RiskLevel, ScanReport, ServerFinding


def test_risk_threshold_ordering() -> None:
    assert risk_at_or_above(RiskLevel.CRITICAL, RiskLevel.HIGH)
    assert risk_at_or_above(RiskLevel.HIGH, RiskLevel.HIGH)
    assert not risk_at_or_above(RiskLevel.MEDIUM, RiskLevel.HIGH)


def test_scan_report_gate_fails_only_when_findings_cross_threshold() -> None:
    report = ScanReport(
        generated_at=datetime.now(timezone.utc),
        findings=(ServerFinding(name="danger", command="bash", risk_level=RiskLevel.HIGH),),
    )
    empty_report = ScanReport(generated_at=datetime.now(timezone.utc), findings=())

    assert scan_report_fails_gate(report, RiskLevel.HIGH)
    assert not scan_report_fails_gate(report, RiskLevel.CRITICAL)
    assert not scan_report_fails_gate(empty_report, RiskLevel.LOW)
