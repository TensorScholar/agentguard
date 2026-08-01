from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.domain import AuditEvent, AuditEventType
from agentguard.engine.checkpoints import (
    AuditCheckpointError,
    issue_audit_checkpoint,
    verify_audit_checkpoint_signature,
)
from agentguard.posture import EnforcementStatus, scan_enforcement_posture


def test_signed_audit_checkpoint_survives_growth_and_detects_replacement(
    tmp_path: Path,
) -> None:
    state = SQLiteState(tmp_path / "state.sqlite")
    for index in range(2):
        state.append(
            AuditEvent(
                event_id=f"event-{index}",
                event_type=AuditEventType.AUTHORIZATION_REQUESTED,
                timestamp=datetime.now(UTC),
                trace_id="trace",
                source="test",
            )
        )
    ok, count, head, _ = state.verify()
    assert ok
    signer = Ed25519Signer.generate("checkpoint-key")
    checkpoint = issue_audit_checkpoint(
        ledger_id="production-eu-1",
        event_count=count,
        head_hash=head,
        signer=signer,
    )
    verify_audit_checkpoint_signature(
        checkpoint,
        Ed25519Verifier({signer.key_id: signer.public_key()}),
    )

    state.append(
        AuditEvent(
            event_id="event-2",
            event_type=AuditEventType.AUTHORIZATION_DECIDED,
            timestamp=datetime.now(UTC),
            trace_id="trace",
            source="test",
        )
    )
    assert state.audit_head_at(checkpoint.event_count) == checkpoint.head_hash

    forged = checkpoint.model_copy(update={"head_hash": "f" * 64})
    with pytest.raises(AuditCheckpointError, match="signature_invalid"):
        verify_audit_checkpoint_signature(
            forged,
            Ed25519Verifier({signer.key_id: signer.public_key()}),
        )


def test_signed_audit_checkpoint_rejects_future_timestamp() -> None:
    signer = Ed25519Signer.generate("checkpoint-key")
    future = datetime.now(UTC) + timedelta(hours=2)
    checkpoint = issue_audit_checkpoint(
        ledger_id="production-eu-1",
        event_count=0,
        head_hash="0" * 64,
        signer=signer,
        now=future,
    )
    with pytest.raises(AuditCheckpointError, match="not_yet_valid"):
        verify_audit_checkpoint_signature(
            checkpoint,
            Ed25519Verifier({signer.key_id: signer.public_key()}),
        )


def test_mcp_posture_finds_parallel_direct_bypass(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "guarded": {
                        "command": "agentguard",
                        "args": ["mcp-proxy", "--", "npx", "example-mcp"],
                    },
                    "unguarded": {"command": "npx", "args": ["example-mcp"]},
                    "remote": {"url": "https://mcp.example.test/rpc"},
                }
            }
        ),
        encoding="utf-8",
    )

    report = scan_enforcement_posture([config])
    by_name = {route.server_name: route for route in report.routes}

    assert by_name["guarded"].status == EnforcementStatus.PROTECTED
    assert by_name["unguarded"].status == EnforcementStatus.DIRECT
    assert "mcp.parallel_direct_bypass" in by_name["unguarded"].reason_codes
    assert by_name["remote"].status == EnforcementStatus.DIRECT
    assert report.has_bypass
    assert len(report.duplicate_bypass_fingerprints) == 1


def test_mcp_posture_does_not_trust_agentguard_tokens_inside_direct_server_args(
    tmp_path: Path,
) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "camouflaged": {
                        "command": "python",
                        "args": [
                            "server.py",
                            "--description",
                            "agentguard",
                            "mcp-proxy",
                            "--",
                            "target",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    route = scan_enforcement_posture([config]).routes[0]
    assert route.status == EnforcementStatus.DIRECT
    assert route.reason_codes == ("mcp.direct_connection_bypasses_agentguard",)


def test_mcp_posture_recognizes_python_module_entrypoint(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "guarded": {
                        "command": "python",
                        "args": ["-m", "agentguard", "mcp-proxy", "--", "npx", "server"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    route = scan_enforcement_posture([config]).routes[0]
    assert route.status == EnforcementStatus.PROTECTED
