from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentguard.domain import (
    EvidenceTrustLevel,
    ExecutionAttemptIdentity,
    ExternalEffectBinding,
    ExternalOperationIdentity,
    IdempotencyBinding,
    IdempotencyMechanism,
    ProviderEvidence,
    ProviderIdentity,
    ProviderReconciliationEvidence,
    ReconciliationStatus,
    ReplayDisposition,
    VerifiedCredentialAuthority,
)
from agentguard.engine.provider_contracts import (
    credential_binding_digest,
    credential_binding_from_verified_authority,
    execution_attempt_identity_digest,
    external_effect_binding_digest,
    external_operation_identity_digest,
    provider_identity_digest,
    verify_provider_evidence_binding,
)


def _sha(char: str) -> str:
    return "sha256:" + char * 64


def _provider() -> ProviderIdentity:
    return ProviderIdentity(
        provider_id="example-provider",
        account_id="account-1",
        tenant_id="tenant-1",
        endpoint_digest=_sha("a"),
    )


def _operation() -> ExternalOperationIdentity:
    return ExternalOperationIdentity(
        operation_id="operation-1",
        operation_kind="mcp_tool_call",
        operation_name="refund.create",
    )


def _attempt(*, number: int = 1) -> ExecutionAttemptIdentity:
    return ExecutionAttemptIdentity(
        execution_id="execution-1",
        attempt_id=f"attempt-{number}",
        attempt_number=number,
        parent_attempt_id=None if number == 1 else f"attempt-{number - 1}",
        started_at=datetime(2026, 9, 1, 12, 0, tzinfo=UTC) + timedelta(seconds=number),
    )


def _binding(
    *,
    attempt: ExecutionAttemptIdentity | None = None,
    idempotency: IdempotencyBinding | None = None,
) -> ExternalEffectBinding:
    return ExternalEffectBinding(
        decision_id="decision-1",
        intent_digest=_sha("b"),
        action_digest=_sha("c"),
        resource_digest=_sha("d"),
        arguments_digest=_sha("e"),
        provider=_provider(),
        operation=_operation(),
        credential=None,
        attempt=attempt or _attempt(),
        idempotency=idempotency or IdempotencyBinding(),
    )


def test_provider_identity_requires_account_or_endpoint() -> None:
    with pytest.raises(ValueError, match="requires_account_or_endpoint"):
        ProviderIdentity(provider_id="provider")


def test_execution_attempt_lineage_is_explicit() -> None:
    with pytest.raises(ValueError, match="first_attempt_cannot_have_parent"):
        ExecutionAttemptIdentity(
            execution_id="execution-1",
            attempt_id="attempt-1",
            attempt_number=1,
            parent_attempt_id="older",
            started_at=datetime(2026, 9, 1, 12, 0, tzinfo=UTC),
        )

    with pytest.raises(ValueError, match="retry_requires_parent"):
        ExecutionAttemptIdentity(
            execution_id="execution-1",
            attempt_id="attempt-2",
            attempt_number=2,
            started_at=datetime(2026, 9, 1, 12, 0, tzinfo=UTC),
        )


def test_idempotency_key_contract_fails_closed() -> None:
    with pytest.raises(ValueError, match="none_forbids_key"):
        IdempotencyBinding(idempotency_key_digest=_sha("f"))

    with pytest.raises(ValueError, match="requires_key_digest"):
        IdempotencyBinding(mechanism=IdempotencyMechanism.AGENTGUARD_GENERATED_KEY)

    with pytest.raises(ValueError, match="same_key_requires_key_mechanism"):
        IdempotencyBinding(replay_disposition=ReplayDisposition.SAME_IDEMPOTENCY_KEY_ONLY)


def test_retry_is_rejected_when_replay_contract_forbids_it() -> None:
    with pytest.raises(ValueError, match="retry_forbidden"):
        _binding(
            attempt=_attempt(number=2),
            idempotency=IdempotencyBinding(replay_disposition=ReplayDisposition.FORBIDDEN),
        )


def test_contract_component_digests_are_stable() -> None:
    provider = _provider()
    operation = _operation()
    attempt = _attempt()

    assert provider_identity_digest(provider) == provider_identity_digest(provider.model_copy())
    assert external_operation_identity_digest(operation) == external_operation_identity_digest(
        operation.model_copy()
    )
    assert execution_attempt_identity_digest(attempt) == execution_attempt_identity_digest(
        attempt.model_copy()
    )


def test_credential_projection_contains_only_verified_non_secret_metadata() -> None:
    authority = VerifiedCredentialAuthority(
        grant_id="grant-1",
        issuance_id="issuance-1",
        mode="opaque_handle",
        credential_handle_digest=_sha("1"),
        audience="https://api.example.test",
        scopes=frozenset({"refund:create", "refund:read"}),
        tenant_id="tenant-1",
        expires_at=datetime(2026, 9, 1, 13, 0, tzinfo=UTC),
        broker="broker-1",
        broker_key_id="broker-key-1",
    )

    binding = credential_binding_from_verified_authority(authority)

    assert binding.grant_id == authority.grant_id
    assert binding.credential_handle_digest == authority.credential_handle_digest
    assert "credential_handle" not in binding.model_dump()
    assert credential_binding_digest(binding) == credential_binding_digest(
        binding.model_copy(update={"scopes": frozenset({"refund:read", "refund:create"})})
    )


def test_external_effect_digest_changes_when_security_binding_changes() -> None:
    original = _binding()
    changed = original.model_copy(
        update={
            "provider": original.provider.model_copy(update={"account_id": "different-account"})
        }
    )

    assert external_effect_binding_digest(original) != external_effect_binding_digest(changed)


def test_provider_evidence_must_bind_to_exact_external_effect() -> None:
    binding = _binding()
    evidence = ProviderEvidence(
        binding_digest=external_effect_binding_digest(binding),
        source="provider-status-api",
        evidence_digest=_sha("2"),
        trust_level=EvidenceTrustLevel.PROVIDER_CORRELATED,
        observed_at=datetime(2026, 9, 1, 12, 5, tzinfo=UTC),
        provider_operation_id_digest=_sha("3"),
    )

    verify_provider_evidence_binding(binding, evidence)

    with pytest.raises(ValueError, match="binding_mismatch"):
        verify_provider_evidence_binding(
            binding,
            evidence.model_copy(update={"binding_digest": _sha("4")}),
        )


def test_confirmed_reconciliation_requires_provider_verified_evidence() -> None:
    common = {
        "binding_digest": external_effect_binding_digest(_binding()),
        "source": "provider-status-api",
        "evidence_digest": _sha("5"),
        "observed_at": datetime(2026, 9, 1, 12, 5, tzinfo=UTC),
        "provider_operation_id_digest": _sha("6"),
        "status": ReconciliationStatus.CONFIRMED_SUCCEEDED,
    }

    with pytest.raises(ValueError, match="confirmation_requires_provider_verified"):
        ProviderReconciliationEvidence(
            **common,
            trust_level=EvidenceTrustLevel.PROVIDER_CORRELATED,
        )

    verified = ProviderReconciliationEvidence(
        **common,
        trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
    )
    assert verified.status == ReconciliationStatus.CONFIRMED_SUCCEEDED
