from __future__ import annotations

from datetime import UTC, datetime

from decisionlock.domain import (
    ExecutionRecord,
    ReconciliationEvidence,
    ReconciliationStatus,
)
from decisionlock.engine.provider_contracts import verify_provider_evidence_binding
from decisionlock.ports import ProviderEffectRepository, ProviderExecutionReconciler


class ProviderReconciliationError(RuntimeError):
    pass


class ProviderBoundExecutionReconciler:
    """Adapt provider-specific evidence into the frozen generic reconciliation lifecycle."""

    def __init__(
        self,
        repository: ProviderEffectRepository,
        reconciler: ProviderExecutionReconciler,
    ) -> None:
        self.repository = repository
        self.reconciler = reconciler

    def reconcile(self, execution: ExecutionRecord) -> ReconciliationEvidence:
        binding = self.repository.get_external_effect_binding(execution.execution_id)
        if binding is None:
            raise ProviderReconciliationError("provider_reconciliation.binding_missing")
        if binding.attempt.execution_id != execution.execution_id:
            raise ProviderReconciliationError("provider_reconciliation.execution_binding_mismatch")
        if binding.decision_id != execution.decision_id:
            raise ProviderReconciliationError("provider_reconciliation.decision_binding_mismatch")
        if binding.intent_digest != execution.intent_digest:
            raise ProviderReconciliationError("provider_reconciliation.intent_binding_mismatch")
        if execution.dispatching_at is None:
            raise ProviderReconciliationError("provider_reconciliation.dispatch_time_missing")
        if binding.attempt.started_at != execution.dispatching_at:
            raise ProviderReconciliationError("provider_reconciliation.attempt_time_mismatch")

        evidence = self.reconciler.reconcile(binding)
        if evidence.status == ReconciliationStatus.CONFLICT:
            raise ProviderReconciliationError("reconciliation.adapter_cannot_assert_conflict")
        try:
            verify_provider_evidence_binding(binding, evidence)
        except ValueError as exc:
            raise ProviderReconciliationError(str(exc)) from exc
        if evidence.observed_at < binding.attempt.started_at:
            raise ProviderReconciliationError("provider_evidence.predates_dispatch")

        self.repository.record_provider_reconciliation_evidence(
            evidence,
            datetime.now(UTC),
        )
        return ReconciliationEvidence(
            status=evidence.status,
            source=evidence.source,
            evidence_digest=evidence.evidence_digest,
            observed_at=evidence.observed_at,
            trust_level=evidence.trust_level,
            provider_operation_id=None,
            error_code=evidence.error_code,
        )
