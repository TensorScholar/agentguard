from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from decisionlock.adapters.broker import MockCredentialBroker
from decisionlock.application import DecisionLockService
from decisionlock.domain import (
    ApprovalReceipt,
    AuditEvent,
    AuditEventType,
    CredentialGrant,
    CredentialRequest,
    DecisionReceipt,
    DelegationContext,
    Effect,
    ExecutionOutcome,
    ExecutionStatus,
)


def _reject_naive(model, instance, field: str) -> None:
    data = instance.model_dump(mode="json")
    data[field] = "2026-01-01T00:00:00"
    with pytest.raises(ValidationError, match="timezone-aware"):
        model.model_validate_json(json.dumps(data))


def test_delegation_rejects_naive_expiry() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        DelegationContext(
            delegation_id="delegation",
            depth=1,
            permitted_capabilities=frozenset(),
            expires_at=datetime.fromisoformat("2026-01-01T00:00:00"),
        )


def test_all_security_artifacts_reject_naive_timestamps(intent, policy, signer, verifier, state):
    service = DecisionLockService(signer, verifier, state)
    receipt = service.authorize(intent, policy)
    _reject_naive(DecisionReceipt, receipt, "issued_at")
    _reject_naive(DecisionReceipt, receipt, "not_before")
    _reject_naive(DecisionReceipt, receipt, "expires_at")

    pending_policy = policy.model_copy(
        update={"rules": (policy.rules[1].model_copy(update={"effect": Effect.REQUIRE_APPROVAL}),)}
    )
    pending = service.authorize(intent, pending_policy)
    approval = service.approve(
        intent,
        pending,
        approver_subject="security",
        reason="timestamp validation",
    )
    _reject_naive(ApprovalReceipt, approval, "issued_at")
    _reject_naive(ApprovalReceipt, approval, "expires_at")

    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="timestamp-grant",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    grant = MockCredentialBroker().issue(receipt, request)
    _reject_naive(CredentialGrant, grant, "issued_at")
    _reject_naive(CredentialGrant, grant, "expires_at")

    outcome = ExecutionOutcome(
        execution_id="execution",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        status=ExecutionStatus.SUCCESS,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC) + timedelta(seconds=1),
    )
    _reject_naive(ExecutionOutcome, outcome, "started_at")
    _reject_naive(ExecutionOutcome, outcome, "completed_at")

    event = AuditEvent(
        event_id="event",
        event_type=AuditEventType.EXECUTION_SUCCEEDED,
        timestamp=datetime.now(UTC),
        trace_id=receipt.trace_id,
        source="test",
    )
    _reject_naive(AuditEvent, event, "timestamp")
