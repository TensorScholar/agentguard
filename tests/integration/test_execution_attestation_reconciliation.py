from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.executor import DeterministicFakeExecutor
from agentguard.adapters.reconciliation import DeterministicReconciler
from agentguard.application import AgentGuardService
from agentguard.domain import (
    CredentialRequest,
    EvidenceTrustLevel,
    ExecutionState,
    ReconciliationEvidence,
    ReconciliationStatus,
)
from agentguard.engine.attestation import (
    AttestationVerificationError,
    attestation_metadata,
    issue_execution_attestation,
    verify_attestation_chain,
    verify_execution_attestation,
)
from agentguard.engine.canonical import digest
from agentguard.engine.execution import ExecutionGuardError


def _unknown_execution(intent, policy, signer, verifier, state):
    broker = MockCredentialBroker()
    service = AgentGuardService(signer, verifier, state, broker.verifier)
    receipt = service.authorize(intent, policy)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="reconciliation-credential",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    grant = service.request_credential(intent, receipt, request, broker)
    outcome = service.execute_protected(
        intent,
        receipt,
        grant,
        DeterministicFakeExecutor(mode="unknown"),
        current_policy=policy,
    )
    record = state.get_execution(outcome.execution_id)
    assert record is not None
    assert record.state == ExecutionState.UNKNOWN
    return service, record


def _evidence(status: ReconciliationStatus, marker: str) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        status=status,
        source="synthetic-provider-status",
        evidence_digest=digest({"marker": marker}),
        observed_at=datetime.now(UTC),
        trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
        provider_operation_id=f"provider-operation-{marker}",
    )


def test_attestation_round_trip_and_tamper_detection(intent, policy, signer, verifier, state):
    service, record = _unknown_execution(intent, policy, signer, verifier, state)
    attestation_signer = Ed25519Signer.generate("attestation-ed25519")
    attestation_verifier = Ed25519Verifier(
        {attestation_signer.key_id: attestation_signer.public_key()}
    )

    attestation = service.issue_execution_attestation(record.execution_id, attestation_signer)
    verify_execution_attestation(attestation, attestation_verifier)

    tampered_payload = attestation.payload.model_copy(update={"execution_id": "exec_tampered"})
    tampered = attestation.model_copy(update={"payload": tampered_payload})
    with pytest.raises(AttestationVerificationError, match="payload_digest_mismatch"):
        verify_execution_attestation(tampered, attestation_verifier)

    wrong_signer = Ed25519Signer.generate("attestation-ed25519")
    wrong_verifier = Ed25519Verifier({wrong_signer.key_id: wrong_signer.public_key()})
    with pytest.raises(AttestationVerificationError, match="signature_invalid"):
        verify_execution_attestation(attestation, wrong_verifier)


def test_attestation_is_secret_minimized_and_chains_after_reconciliation(
    intent, policy, signer, verifier, state
):
    service, record = _unknown_execution(intent, policy, signer, verifier, state)
    attestation_signer = Ed25519Signer.generate("attestation-ed25519")

    first = service.issue_execution_attestation(record.execution_id, attestation_signer)
    resolution = service.reconcile_execution(
        record.execution_id,
        DeterministicReconciler(_evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "one")),
    )
    second = service.issue_execution_attestation(record.execution_id, attestation_signer)

    assert first.payload.resolution is None
    assert second.payload.resolution == resolution
    assert second.payload.previous_attestation_digest == first.payload_digest
    verifier2 = Ed25519Verifier({attestation_signer.key_id: attestation_signer.public_key()})
    verify_attestation_chain((first, second), verifier2)
    broken_second = second.model_copy(
        update={
            "payload": second.payload.model_copy(
                update={"previous_attestation_digest": "sha256:" + "0" * 64}
            )
        }
    )
    with pytest.raises(AttestationVerificationError):
        verify_attestation_chain((first, broken_second), verifier2)
    serialized = second.model_dump_json()
    assert "order-1042" not in serialized
    assert "provider-operation-one" not in serialized
    assert "credential_handle" not in serialized
    assert "private" not in serialized.lower()

    database_bytes = state.path.read_bytes()
    assert b"provider-operation-one" not in database_bytes


def test_reconciliation_is_append_only_and_never_rewrites_unknown(
    intent, policy, signer, verifier, state
):
    service, record = _unknown_execution(intent, policy, signer, verifier, state)
    evidence = _evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "success")
    reconciler = DeterministicReconciler(evidence)

    first = service.reconcile_execution(record.execution_id, reconciler)
    repeated = service.reconcile_execution(record.execution_id, reconciler)

    assert first == repeated
    assert len(state.list_execution_resolutions(record.execution_id)) == 1
    unchanged = state.get_execution(record.execution_id)
    assert unchanged is not None
    assert unchanged.state == ExecutionState.UNKNOWN
    assert reconciler.calls == [record.execution_id, record.execution_id]


def test_conflicting_reconciliation_evidence_becomes_explicit_conflict(
    intent, policy, signer, verifier, state
):
    service, record = _unknown_execution(intent, policy, signer, verifier, state)

    success = service.reconcile_execution(
        record.execution_id,
        DeterministicReconciler(_evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "success")),
    )
    conflict = service.reconcile_execution(
        record.execution_id,
        DeterministicReconciler(_evidence(ReconciliationStatus.CONFIRMED_FAILED, "failure")),
    )

    assert success.status == ReconciliationStatus.CONFIRMED_SUCCEEDED
    assert conflict.status == ReconciliationStatus.CONFLICT
    assert conflict.error_code == "reconciliation.conflicting_evidence"
    assert len(state.list_execution_resolutions(record.execution_id)) == 2
    unchanged = state.get_execution(record.execution_id)
    assert unchanged is not None and unchanged.state == ExecutionState.UNKNOWN


@pytest.mark.parametrize(
    "status",
    [
        ReconciliationStatus.CONFIRMED_FAILED,
        ReconciliationStatus.STILL_UNKNOWN,
        ReconciliationStatus.UNSUPPORTED,
    ],
)
def test_reconciliation_records_supported_non_success_classifications(
    intent, policy, signer, verifier, state, status
):
    service, record = _unknown_execution(intent, policy, signer, verifier, state)
    resolution = service.reconcile_execution(
        record.execution_id,
        DeterministicReconciler(_evidence(status, status.value)),
    )
    assert resolution.status == status
    assert state.get_execution(record.execution_id).state == ExecutionState.UNKNOWN


def test_reconciliation_refuses_non_unknown_execution(intent, policy, signer, verifier, state):
    broker = MockCredentialBroker()
    service = AgentGuardService(signer, verifier, state, broker.verifier)
    receipt = service.authorize(intent, policy)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="successful-credential",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    grant = service.request_credential(intent, receipt, request, broker)
    outcome = service.execute_protected(
        intent, receipt, grant, DeterministicFakeExecutor(), current_policy=policy
    )
    with pytest.raises(ExecutionGuardError, match="execution_not_unknown"):
        service.reconcile_execution(
            outcome.execution_id,
            DeterministicReconciler(_evidence(ReconciliationStatus.STILL_UNKNOWN, "x")),
        )


def test_confirmed_resolution_cannot_regress_to_weaker_or_escape_conflict(
    intent, policy, signer, verifier, state
):
    service, record = _unknown_execution(intent, policy, signer, verifier, state)
    confirmed = service.reconcile_execution(
        record.execution_id,
        DeterministicReconciler(_evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "final")),
    )
    weaker = service.reconcile_execution(
        record.execution_id,
        DeterministicReconciler(_evidence(ReconciliationStatus.STILL_UNKNOWN, "late-timeout")),
    )
    assert weaker == confirmed

    conflict = service.reconcile_execution(
        record.execution_id,
        DeterministicReconciler(_evidence(ReconciliationStatus.CONFIRMED_FAILED, "opposite")),
    )
    assert conflict.status == ReconciliationStatus.CONFLICT
    after_conflict = service.reconcile_execution(
        record.execution_id,
        DeterministicReconciler(_evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "newer")),
    )
    assert after_conflict == conflict


@pytest.mark.parametrize(
    "status",
    [
        ReconciliationStatus.CONFIRMED_SUCCEEDED,
        ReconciliationStatus.CONFIRMED_FAILED,
    ],
)
@pytest.mark.parametrize(
    "trust_level",
    [
        EvidenceTrustLevel.AGENTGUARD_SIGNED,
        EvidenceTrustLevel.PROVIDER_CORRELATED,
    ],
)
def test_confirmed_reconciliation_requires_provider_verified_evidence(status, trust_level):
    with pytest.raises(ValueError, match="confirmation_requires_provider_verified_evidence"):
        ReconciliationEvidence(
            status=status,
            source="unverified-status-observation",
            evidence_digest=digest({"status": status.value, "trust": trust_level.value}),
            observed_at=datetime.now(UTC),
            trust_level=trust_level,
            provider_operation_id="provider-operation-unverified",
        )


@pytest.mark.parametrize(
    "trust_level",
    [
        EvidenceTrustLevel.AGENTGUARD_SIGNED,
        EvidenceTrustLevel.PROVIDER_CORRELATED,
        EvidenceTrustLevel.PROVIDER_VERIFIED,
    ],
)
def test_non_confirming_reconciliation_preserves_explicit_assurance(trust_level):
    evidence = ReconciliationEvidence(
        status=ReconciliationStatus.STILL_UNKNOWN,
        source="status-observation",
        evidence_digest=digest({"trust": trust_level.value}),
        observed_at=datetime.now(UTC),
        trust_level=trust_level,
        provider_operation_id="provider-operation-observed",
    )
    assert evidence.trust_level == trust_level


def test_concurrent_conflicting_reconciliation_serializes_to_sticky_conflict(
    intent, policy, signer, verifier, state
):
    service, record = _unknown_execution(intent, policy, signer, verifier, state)
    barrier = Barrier(2)

    class BarrierReconciler:
        def __init__(self, evidence):
            self.evidence = evidence

        def reconcile(self, execution):
            assert execution.execution_id == record.execution_id
            barrier.wait(timeout=5)
            return self.evidence

    reconcilers = (
        BarrierReconciler(_evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "race-success")),
        BarrierReconciler(_evidence(ReconciliationStatus.CONFIRMED_FAILED, "race-failure")),
    )

    def reconcile(value):
        return service.reconcile_execution(record.execution_id, value)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reconcile, reconcilers))

    assert ReconciliationStatus.CONFLICT in {result.status for result in results}
    resolutions = state.list_execution_resolutions(record.execution_id)
    assert len(resolutions) == 2
    assert resolutions[-1].status == ReconciliationStatus.CONFLICT
    assert resolutions[-1].error_code == "reconciliation.conflicting_evidence"


def test_attestation_repository_rejects_concurrent_chain_fork(
    intent, policy, signer, verifier, state
):
    service, record = _unknown_execution(intent, policy, signer, verifier, state)
    attestation_signer = Ed25519Signer.generate("attestation-ed25519")
    first = service.issue_execution_attestation(record.execution_id, attestation_signer)

    left = issue_execution_attestation(
        record,
        attestation_signer,
        previous_attestation_digest=first.payload_digest,
    )
    right = issue_execution_attestation(
        record,
        attestation_signer,
        previous_attestation_digest=first.payload_digest,
    )

    state.record_attestation_metadata(attestation_metadata(left))
    with pytest.raises(RuntimeError, match="attestation.chain_head_changed"):
        state.record_attestation_metadata(attestation_metadata(right))

    latest = state.get_latest_attestation_metadata(record.execution_id)
    assert latest is not None
    assert latest.payload_digest == left.payload_digest
