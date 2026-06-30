from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any

from .models import AuditEvent, ScanReport, ToolInventoryItem


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
        lines.append(f"| {finding.name} | {finding.risk_level.value} | {capabilities} | {reasons} |")
    return "\n".join(lines) + "\n"


def render_audit_markdown(events: list[AuditEvent], tools: list[ToolInventoryItem] | None = None) -> str:
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
    lines.extend(["", "| Time | Agent | Tool | Decision | Rule | Reason |", "| --- | --- | --- | --- | --- | --- |"])
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
                f"| {tool.source} | {tool.name} | {tool.risk_level.value} | {capabilities} | {reasons} |"
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
