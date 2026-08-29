from __future__ import annotations

from agentguard.domain import ExecutionRecord, ReconciliationEvidence


class DeterministicReconciler:
    """Deterministic evidence source for tests/demos; never dispatches external actions."""

    def __init__(self, evidence: ReconciliationEvidence) -> None:
        self.evidence = evidence
        self.calls: list[str] = []

    def reconcile(self, execution: ExecutionRecord) -> ReconciliationEvidence:
        self.calls.append(execution.execution_id)
        return self.evidence
