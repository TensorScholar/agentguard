from __future__ import annotations

from .models import RiskLevel, ScanReport


RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def risk_at_or_above(value: RiskLevel, threshold: RiskLevel) -> bool:
    return RISK_ORDER[value] >= RISK_ORDER[threshold]


def scan_report_fails_gate(report: ScanReport, threshold: RiskLevel) -> bool:
    if not report.findings:
        return False
    return risk_at_or_above(report.highest_risk, threshold)
