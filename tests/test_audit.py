from __future__ import annotations

from pathlib import Path

from agentguard.audit import AuditLedger
from agentguard.models import AuditEvent, Capability, RiskLevel, ToolCall, ToolInventoryItem
from agentguard.policy import Policy


def test_audit_ledger_round_trip(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    call = ToolCall(tool_name="read_file", arguments={"path": ".env"}, agent_id="test")
    decision = Policy().evaluate(call)
    ledger.record(AuditEvent.from_decision(call, decision))

    events = ledger.list_events()

    assert len(events) == 1
    assert events[0].tool_name == "read_file"
    assert events[0].rule_id == "path.sensitive"


def test_tool_inventory_round_trip(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="write_file",
                description="Write a file",
                input_schema={"type": "object"},
                capabilities=(Capability.FILESYSTEM_WRITE,),
                risk_level=RiskLevel.HIGH,
                reasons=("tool can mutate files",),
            )
        ]
    )

    tools = ledger.list_tool_inventory()

    assert len(tools) == 1
    assert tools[0].name == "write_file"
    assert tools[0].capabilities == (Capability.FILESYSTEM_WRITE,)
    assert tools[0].risk_level == RiskLevel.HIGH
