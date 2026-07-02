from __future__ import annotations

import json
import hashlib
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any

from .models import AuditEvent, RiskLevel, ScanReport, ServerFinding, ToolInventoryItem
from .secrets import redact_value


FINDINGS_SCHEMA_VERSION = "agentguard.findings.v1"
RISK_ORDER = (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)


def to_json(data: object) -> str:
    return json.dumps(_to_jsonable(data), indent=2, sort_keys=True)


def render_scan_markdown(report: ScanReport) -> str:
    lines = [
        "# AgentGuard Scan Report",
        "",
        f"Generated: {report.generated_at.isoformat()}",
        f"Highest risk: **{report.highest_risk.value}**",
        "",
        "| Server | Risk | Capabilities | Reasons |",
        "| --- | --- | --- | --- |",
    ]
    if not report.findings:
        lines.append("| None | low | None | No MCP configs found |")
    for finding in report.findings:
        capabilities = ", ".join(capability.value for capability in finding.capabilities)
        reasons = "<br>".join(finding.reasons)
        lines.append(
            f"| {finding.name} | {finding.risk_level.value} | {capabilities} | {reasons} |"
        )
    return "\n".join(lines) + "\n"


def scan_report_to_findings(report: ScanReport) -> dict[str, object]:
    return {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "generated_at": report.generated_at.isoformat(),
        "summary": {
            "finding_count": len(report.findings),
            "highest_risk": report.highest_risk.value,
            "by_risk": _risk_counts(report),
        },
        "findings": [_finding_to_jsonable(finding) for finding in report.findings],
    }


def render_findings_summary_markdown(report: ScanReport) -> str:
    counts = _risk_counts(report)
    lines = [
        "# AgentGuard CI Summary",
        "",
        f"Highest risk: **{report.highest_risk.value}**",
        f"Findings: **{len(report.findings)}**",
        "",
        "| Risk | Count |",
        "| --- | ---: |",
    ]
    for risk in RISK_ORDER:
        lines.append(f"| {risk.value} | {counts[risk.value]} |")
    lines.extend(["", "| Server | Risk | Capabilities | Config |", "| --- | --- | --- | --- |"])
    if not report.findings:
        lines.append("| None | low | None | None |")
    for finding in report.findings:
        capabilities = ", ".join(capability.value for capability in finding.capabilities)
        config_path = finding.config_path or ""
        lines.append(
            f"| {_markdown_cell(finding.name)} | {finding.risk_level.value} | "
            f"{_markdown_cell(capabilities)} | {_markdown_cell(config_path)} |"
        )
    return "\n".join(lines) + "\n"


def render_audit_markdown(
    events: list[AuditEvent], tools: list[ToolInventoryItem] | None = None
) -> str:
    decisions = Counter(event.decision.value for event in events)
    lines = [
        "# AgentGuard Audit Report",
        "",
        f"Total events: {len(events)}",
        "",
        "| Decision | Count |",
        "| --- | ---: |",
    ]
    for decision, count in sorted(decisions.items()):
        lines.append(f"| {decision} | {count} |")
    lines.extend(
        [
            "",
            "| Time | Agent | Tool | Decision | Rule | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for event in events:
        lines.append(
            "| "
            + " | ".join(
                [
                    event.timestamp.isoformat(),
                    event.agent_id,
                    event.tool_name,
                    event.decision.value,
                    event.rule_id,
                    event.reason.replace("|", "\\|"),
                ]
            )
            + " |"
        )
    if tools is not None:
        lines.extend(
            [
                "",
                "## Discovered Tools",
                "",
                "| Source | Tool | Risk | Capabilities | Reasons |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        if not tools:
            lines.append("| None | None | low | None | No tools discovered from MCP traffic |")
        for tool in tools:
            capabilities = ", ".join(capability.value for capability in tool.capabilities)
            reasons = "<br>".join(reason.replace("|", "\\|") for reason in tool.reasons)
            lines.append(
                f"| {tool.source} | {tool.name} | {tool.risk_level.value} | "
                f"{capabilities} | {reasons} |"
            )
    return "\n".join(lines) + "\n"


def _to_jsonable(value: object) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "__dataclass_fields__"):
        return {key: _to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]
    return value


def _risk_counts(report: ScanReport) -> dict[str, int]:
    counts = Counter(finding.risk_level.value for finding in report.findings)
    return {risk.value: counts.get(risk.value, 0) for risk in RISK_ORDER}


def _finding_to_jsonable(finding: ServerFinding) -> dict[str, object]:
    reasons = tuple(finding.reasons)
    return {
        "id": _finding_id(finding),
        "name": finding.name,
        "risk": finding.risk_level.value,
        "capabilities": [capability.value for capability in finding.capabilities],
        "config_path": finding.config_path,
        "command": redact_value(finding.command),
        "args": redact_value(list(finding.args)),
        "env_keys": list(finding.env_keys),
        "reasons": list(reasons),
        "message": _finding_message(finding, reasons),
    }


def _finding_id(finding: ServerFinding) -> str:
    payload = "|".join([finding.config_path or "", finding.name, finding.risk_level.value])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"AG-MCP-{digest}"


def _finding_message(finding: ServerFinding, reasons: tuple[str, ...]) -> str:
    if not reasons:
        return f"MCP server '{finding.name}' has {finding.risk_level.value} risk"
    return f"MCP server '{finding.name}' has {finding.risk_level.value} risk: {reasons[0]}"


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|")
