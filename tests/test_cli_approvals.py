from __future__ import annotations

import json
from pathlib import Path

from pytest import CaptureFixture, MonkeyPatch

from agentguard.audit import AuditLedger
from agentguard.cli import main


def test_approve_call_creates_scoped_grant(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    ledger_path = tmp_path / "audit.sqlite"

    exit_code = main(
        [
            "approve-call",
            "--ledger",
            str(ledger_path),
            "--tool",
            "run_command",
            "--arg",
            "command=git status",
            "--approved-by",
            "security",
            "--reason",
            "local repository status",
        ]
    )
    captured = capsys.readouterr()
    grants = AuditLedger(ledger_path).list_approval_grants()

    assert exit_code == 0
    assert "Created approval grant" in captured.out
    assert len(grants) == 1
    assert grants[0].tool_name == "run_command"
    assert grants[0].approved_by == "security"


def test_approve_call_json_does_not_print_raw_arguments(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    ledger_path = tmp_path / "audit.sqlite"

    exit_code = main(
        [
            "approve-call",
            "--ledger",
            str(ledger_path),
            "--tool",
            "run_command",
            "--arg",
            "command=deploy super-secret-value",
            "--approved-by",
            "security",
            "--reason",
            "one approved deployment",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert "super-secret-value" not in captured.out
    assert payload["tool_name"] == "run_command"
    assert len(payload["arguments_hash"]) == 64


def test_approvals_lists_active_grants(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    main(
        [
            "approve-call",
            "--ledger",
            str(ledger_path),
            "--tool",
            "run_command",
            "--arg",
            "command=git status",
            "--approved-by",
            "security",
            "--reason",
            "local repository status",
        ]
    )
    capsys.readouterr()

    exit_code = main(["approvals", "--ledger", str(ledger_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "AgentGuard Approval Grants" in captured.out
    assert "run_command" in captured.out
    assert "local repository status" in captured.out


def test_proxy_consumes_matching_approval_grant(
    monkeypatch: MonkeyPatch, tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    main(
        [
            "approve-call",
            "--ledger",
            str(ledger_path),
            "--tool",
            "run_command",
            "--arg",
            "command=git status",
            "--approved-by",
            "security",
            "--reason",
            "local repository status",
            "--agent-id",
            "agent-1",
            "--source",
            "jsonl",
        ]
    )
    capsys.readouterr()
    monkeypatch.setattr(
        "sys.stdin",
        [
            json.dumps(
                {
                    "tool_name": "run_command",
                    "arguments": {"command": "git status"},
                    "agent_id": "agent-1",
                    "source": "jsonl",
                }
            )
            + "\n"
        ],
    )

    exit_code = main(["proxy", "--ledger", str(ledger_path)])
    captured = capsys.readouterr()
    event = json.loads(captured.out)

    assert exit_code == 0
    assert event["decision"] == "allow"
    assert event["rule_id"].startswith("approval.grant.")
    assert AuditLedger(ledger_path).list_approval_grants() == []


def test_approve_call_rejects_invalid_ttl(tmp_path: Path, capsys: CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "approve-call",
            "--ledger",
            str(tmp_path / "audit.sqlite"),
            "--tool",
            "run_command",
            "--approved-by",
            "security",
            "--reason",
            "invalid",
            "--ttl-seconds",
            "0",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "--ttl-seconds must be greater than zero" in captured.err
