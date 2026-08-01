from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import Ed25519Signer
from agentguard.audit import AuditLedger
from agentguard.domain import CredentialRequest, Effect, ExecutionBudget
from agentguard.domain.policy import ActionMatcher, PolicyRule
from agentguard.engine.credentials import (
    CredentialVerificationError,
    attest_credential_grant,
    verify_credential_grant,
)
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import (
    ReceiptVerificationError,
    issue_approval_receipt,
    issue_decision_receipt,
)
from agentguard.models import AuditEvent, Decision, ToolCall
from agentguard.policy import Policy, load_policy
from agentguard.secrets import redact_mapping


def test_legacy_deny_never_persists_raw_secret_and_ledger_is_private(tmp_path: Path) -> None:
    token = "sk-" + "a" * 40
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    call = ToolCall(tool_name="read_file", arguments={"api_key": token, "path": ".env"})
    decision = Policy().evaluate(call)
    assert decision.decision == Decision.DENY

    ledger.record(AuditEvent.from_decision(call, decision))

    assert token.encode() not in ledger.path.read_bytes()
    assert ledger.list_events()[0].arguments["api_key"] == "[REDACTED:sensitive_key]"
    assert os.stat(ledger.path).st_mode & 0o777 == 0o600


def test_legacy_policy_blocks_encoded_path_and_raw_metadata_host() -> None:
    policy = Policy()
    encoded = policy.evaluate(ToolCall(tool_name="read_file", arguments={"path": "%2Eenv"}))
    metadata = policy.evaluate(ToolCall(tool_name="request", arguments={"host": "169.254.169.254"}))
    decimal = policy.evaluate(
        ToolCall(
            tool_name="request",
            arguments={"host": str(int.from_bytes(bytes([169, 254, 169, 254]), "big"))},
        )
    )

    assert encoded.rule_id == "path.sensitive"
    assert metadata.rule_id == "network.blocked_host"
    assert decimal.rule_id == "network.blocked_host"


def test_legacy_policy_rejects_duplicate_and_unknown_fields(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("default_action: allow\ndefault_action: deny\n", encoding="utf-8")
    unknown = tmp_path / "unknown.yaml"
    unknown.write_text("default_action: allow\nallow_magic: true\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate policy key"):
        load_policy(str(duplicate))
    with pytest.raises(ValueError, match="unknown policy field"):
        load_policy(str(unknown))


def _approval_policy(policy):
    rule = PolicyRule(
        id="approval-budget",
        priority=5000,
        effect=Effect.REQUIRE_APPROVAL,
        action=ActionMatcher(tools=frozenset({"refund.create"})),
        credential=policy.rules[1].credential,
        execution_budget=ExecutionBudget(maximum_financial_amount_minor=10_000),
        reason_code="approval.required",
    )
    return policy.model_copy(update={"rules": (rule,)})


def test_approval_budget_cannot_expand_decision(intent, policy, signer, verifier) -> None:
    document = _approval_policy(policy)
    receipt = issue_decision_receipt(intent, evaluate_policy(document, intent), signer)
    with pytest.raises(ReceiptVerificationError, match="budget_exceeds_decision"):
        issue_approval_receipt(
            receipt,
            intent,
            signer,
            verifier,
            approver_subject="security",
            reason="too broad",
            approved_budget=ExecutionBudget(maximum_financial_amount_minor=10_001),
        )


def test_credential_grant_cannot_outlive_decision(intent, policy, signer) -> None:
    now = datetime.now(UTC)
    receipt = issue_decision_receipt(
        intent,
        evaluate_policy(policy, intent),
        signer,
        now=now,
        ttl_seconds=60,
    )
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="cred-window",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    broker_signer = Ed25519Signer.generate("broker-key")
    broker = MockCredentialBroker(signer=broker_signer)
    grant = broker.issue(receipt, request)
    forged = attest_credential_grant(
        grant.model_copy(
            update={
                "issued_at": receipt.expires_at - timedelta(seconds=10),
                "expires_at": receipt.expires_at + timedelta(seconds=1),
            }
        ),
        broker_signer,
    )

    with pytest.raises(CredentialVerificationError, match="validity_exceeds_decision"):
        verify_credential_grant(
            receipt,
            forged,
            broker.verifier,
            now=receipt.expires_at - timedelta(seconds=5),
        )


def test_v2_state_database_is_private(state) -> None:
    assert os.stat(state.path).st_mode & 0o777 == 0o600
    # Assert the connection-local pragma on the managed connection for cross-platform correctness.
    with state._connect() as connection:
        assert connection.execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_legacy_explicit_sanitizer_removes_retained_secret_and_rechains(tmp_path: Path) -> None:
    token = "ghp_" + "z" * 40
    ledger = AuditLedger(tmp_path / "legacy.sqlite")
    call = ToolCall(tool_name="safe", arguments={"token": token})
    decision = Policy().evaluate(call)
    ledger.record(AuditEvent.from_decision(call, decision))

    with sqlite3.connect(ledger.path) as connection:
        connection.execute(
            "UPDATE audit_events SET arguments_json = ?, reason = ?",
            (json.dumps({"token": token}), f"received {token}"),
        )
    assert token.encode() in ledger.path.read_bytes()

    result = ledger.sanitize_and_rechain()

    assert result.ok
    assert ledger.verify_chain().ok
    assert token.encode() not in ledger.path.read_bytes()
    assert ledger.list_events()[0].arguments == redact_mapping({"token": token})


@pytest.mark.parametrize(
    "host",
    [
        "fe80::1",
        "::ffff:169.254.169.254",
        "[::ffff:169.254.169.254]",
        "http://[::ffff:169.254.169.254]/latest/meta-data",
        "169.254.169.254",
        "0xA9FEA9FE",
        "0251.0376.0251.0376",
        "169.254.43518",
    ],
)
def test_legacy_policy_blocks_noncanonical_metadata_and_link_local_hosts(host: str) -> None:
    decision = Policy().evaluate(ToolCall(tool_name="request", arguments={"host": host}))
    assert decision.rule_id == "network.blocked_host"


def test_legacy_policy_fails_closed_on_excessive_nested_encoding() -> None:
    value = ".env"
    for _ in range(12):
        value = value.replace("%", "%25").replace(".", "%2E")

    path_decision = Policy().evaluate(ToolCall(tool_name="read_file", arguments={"path": value}))
    host_value = "169.254.169.254"
    for _ in range(12):
        host_value = host_value.replace("%", "%25").replace(".", "%2E")
    host_decision = Policy().evaluate(ToolCall(tool_name="request", arguments={"host": host_value}))

    assert path_decision.rule_id == "input.excessive_encoding"
    assert host_decision.rule_id == "input.excessive_encoding"
