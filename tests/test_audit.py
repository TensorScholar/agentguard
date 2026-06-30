from __future__ import annotations

from pathlib import Path

from agentguard.audit import AuditLedger
from agentguard.models import AuditEvent, ToolCall
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
