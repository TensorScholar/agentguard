from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from pytest import CaptureFixture

from agentguard.audit import AuditLedger
from agentguard.cli import main
from agentguard.models import AuditEvent, ToolCall
from agentguard.policy import Policy


def test_verify_audit_succeeds_for_valid_chain(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    _record_event(ledger_path)

    exit_code = main(["verify-audit", "--ledger", str(ledger_path), "--format", "json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["checked_events"] == 1
    assert len(payload["head_hash"]) == 64


def test_verify_audit_fails_for_tampered_chain(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    event_id = _record_event(ledger_path)
    with sqlite3.connect(ledger_path) as conn:
        conn.execute(
            "UPDATE audit_events SET tool_name = ? WHERE event_id = ?",
            ("tampered_tool", event_id),
        )

    exit_code = main(["verify-audit", "--ledger", str(ledger_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Status: **FAILED**" in captured.out
    assert f"First invalid event: `{event_id}`" in captured.out
    assert "Reason: event hash mismatch" in captured.out


def test_verify_audit_fails_for_missing_ledger(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    ledger_path = tmp_path / "missing.sqlite"

    exit_code = main(["verify-audit", "--ledger", str(ledger_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Audit ledger does not exist" in captured.err


def test_report_json_includes_chain_status(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    _record_event(ledger_path)

    exit_code = main(["report", "--ledger", str(ledger_path), "--format", "json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["chain"]["ok"] is True
    assert payload["chain"]["checked_events"] == 1


def _record_event(ledger_path: Path) -> str:
    ledger = AuditLedger(ledger_path)
    call = ToolCall(tool_name="read_file", arguments={"path": ".env"}, agent_id="test")
    event = AuditEvent.from_decision(call, Policy().evaluate(call))
    ledger.record(event)
    return event.event_id
