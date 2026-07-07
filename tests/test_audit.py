from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentguard.audit import AuditLedger, hash_tool_arguments
from agentguard.models import (
    ApprovalGrant,
    AuditEvent,
    Capability,
    RiskLevel,
    ToolCall,
    ToolInventoryItem,
)
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


def test_audit_chain_verifies_recorded_events(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    first_call = ToolCall(tool_name="read_file", arguments={"path": ".env"}, agent_id="test")
    second_call = ToolCall(
        tool_name="run_command",
        arguments={"command": "git status"},
        agent_id="test",
    )
    policy = Policy()

    ledger.record(AuditEvent.from_decision(first_call, policy.evaluate(first_call)))
    ledger.record(AuditEvent.from_decision(second_call, policy.evaluate(second_call)))

    verification = ledger.verify_chain()

    assert verification.ok
    assert verification.checked_events == 2
    assert len(verification.head_hash) == 64
    assert verification.first_invalid_event_id is None
    assert verification.reason is None


def test_audit_chain_detects_event_mutation(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    ledger = AuditLedger(ledger_path)
    call = ToolCall(tool_name="read_file", arguments={"path": ".env"}, agent_id="test")
    event = AuditEvent.from_decision(call, Policy().evaluate(call))
    ledger.record(event)

    with sqlite3.connect(ledger_path) as conn:
        conn.execute(
            "UPDATE audit_events SET reason = ? WHERE event_id = ?",
            ("tampered reason", event.event_id),
        )

    verification = ledger.verify_chain()

    assert not verification.ok
    assert verification.checked_events == 1
    assert verification.first_invalid_event_id == event.event_id
    assert verification.reason == "event hash mismatch"


def test_audit_chain_detects_broken_previous_hash(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    ledger = AuditLedger(ledger_path)
    policy = Policy()
    first_call = ToolCall(tool_name="read_file", arguments={"path": ".env"}, agent_id="test")
    second_call = ToolCall(
        tool_name="run_command",
        arguments={"command": "git status"},
        agent_id="test",
    )
    first_event = AuditEvent.from_decision(first_call, policy.evaluate(first_call))
    second_event = AuditEvent.from_decision(second_call, policy.evaluate(second_call))
    ledger.record(first_event)
    ledger.record(second_event)

    with sqlite3.connect(ledger_path) as conn:
        conn.execute(
            "UPDATE audit_events SET previous_hash = ? WHERE event_id = ?",
            ("f" * 64, second_event.event_id),
        )

    verification = ledger.verify_chain()

    assert not verification.ok
    assert verification.checked_events == 2
    assert verification.first_invalid_event_id == second_event.event_id
    assert verification.reason == "previous hash mismatch"


def test_audit_chain_detects_legacy_unhashed_events(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    AuditLedger(ledger_path)
    with sqlite3.connect(ledger_path) as conn:
        conn.execute(
            """
            INSERT INTO audit_events (
                event_id, timestamp, agent_id, source, tool_name, call_id,
                decision, reason, rule_id, arguments_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-event",
                datetime.now(timezone.utc).isoformat(),
                "test",
                "local",
                "read_file",
                "call-1",
                "deny",
                "legacy row",
                "legacy.rule",
                "{}",
            ),
        )

    verification = AuditLedger(ledger_path).verify_chain()

    assert not verification.ok
    assert verification.first_invalid_event_id == "legacy-event"
    assert verification.reason == "missing audit chain hash"


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

    loaded = ledger.get_tool_inventory("mcp_stdio", "write_file")

    assert loaded is not None
    assert loaded.name == "write_file"
    assert loaded.capabilities == (Capability.FILESYSTEM_WRITE,)


def test_replace_tool_inventory_removes_tools_missing_from_latest_list(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(source="mcp_stdio", name="old_tool"),
            ToolInventoryItem(source="mcp_stdio", name="kept_tool"),
            ToolInventoryItem(source="other_source", name="old_tool"),
        ]
    )

    ledger.replace_tool_inventory(
        "mcp_stdio",
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="kept_tool",
                capabilities=(Capability.FILESYSTEM_READ,),
            )
        ],
    )

    assert {(tool.source, tool.name) for tool in ledger.list_tool_inventory()} == {
        ("mcp_stdio", "kept_tool"),
        ("other_source", "old_tool"),
    }


def test_approval_grant_round_trip_and_consumption(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    call = ToolCall(
        tool_name="run_command",
        arguments={"command": "git status"},
        agent_id="mcp-client",
        source="mcp_stdio",
    )
    now = datetime.now(timezone.utc)
    grant = ApprovalGrant(
        agent_id=call.agent_id,
        source=call.source,
        tool_name=call.tool_name,
        arguments_hash=hash_tool_arguments(call.arguments),
        approved_by="security",
        reason="local status check",
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    ledger.add_approval_grant(grant)

    active = ledger.list_approval_grants()
    consumed = ledger.consume_approval_grant(call)

    assert len(active) == 1
    assert active[0].grant_id == grant.grant_id
    assert consumed is not None
    assert consumed.grant_id == grant.grant_id
    assert consumed.used_count == 1
    assert ledger.consume_approval_grant(call) is None


def test_expired_approval_grant_is_not_consumed(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    call = ToolCall(
        tool_name="run_command",
        arguments={"command": "git status"},
        agent_id="mcp-client",
        source="mcp_stdio",
    )
    created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    ledger.add_approval_grant(
        ApprovalGrant(
            agent_id=call.agent_id,
            source=call.source,
            tool_name=call.tool_name,
            arguments_hash=hash_tool_arguments(call.arguments),
            approved_by="security",
            reason="expired",
            created_at=created_at,
            expires_at=created_at + timedelta(minutes=1),
        )
    )

    assert ledger.list_approval_grants() == []
    assert ledger.consume_approval_grant(call) is None


def test_approval_grant_requires_exact_argument_hash(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    now = datetime.now(timezone.utc)
    ledger.add_approval_grant(
        ApprovalGrant(
            agent_id="mcp-client",
            source="mcp_stdio",
            tool_name="run_command",
            arguments_hash=hash_tool_arguments({"command": "git status"}),
            approved_by="security",
            reason="local status check",
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    )

    assert (
        ledger.consume_approval_grant(
            ToolCall(
                tool_name="run_command",
                arguments={"command": "git push"},
                agent_id="mcp-client",
                source="mcp_stdio",
            )
        )
        is None
    )
