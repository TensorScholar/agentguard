from __future__ import annotations

import argparse
import json
from pathlib import Path

from decisionlock.domain import (
    ActionIntent,
    ApprovalReceipt,
    AuditCheckpoint,
    AuditEvent,
    AuthorityAnalysis,
    AuthorityGrant,
    AuthorityReference,
    CapabilityLease,
    CausalExecutionGraph,
    CredentialGrant,
    CredentialRequest,
    DecisionReceipt,
    EvidenceAttestation,
    ExecutionAttestation,
    ExecutionOutcome,
    ExecutionRequest,
    ExecutionResolution,
    FieldProvenanceStatement,
    FieldReleaseReceipt,
    PolicyDecisionAnalysis,
    PolicyDocument,
    PreparedExecution,
    ReconciliationEvidence,
)

ROOT = Path(__file__).parents[1]
MODELS = {
    "action-intent-v1": ActionIntent,
    "policy-v2": PolicyDocument,
    "decision-receipt-v1": DecisionReceipt,
    "approval-receipt-v1": ApprovalReceipt,
    "credential-request-v1": CredentialRequest,
    "credential-grant-v1": CredentialGrant,
    "execution-request-v1": ExecutionRequest,
    "execution-outcome-v1": ExecutionOutcome,
    "audit-event-v1": AuditEvent,
    "audit-checkpoint-v1": AuditCheckpoint,
    "evidence-attestation-v1": EvidenceAttestation,
    "execution-attestation-v1": ExecutionAttestation,
    "reconciliation-evidence-v1": ReconciliationEvidence,
    "execution-resolution-v1": ExecutionResolution,
    "authority-grant-v1": AuthorityGrant,
    "capability-lease-v1": CapabilityLease,
    "authority-reference-v1": AuthorityReference,
    "causal-execution-graph-v1": CausalExecutionGraph,
    "field-provenance-statement-v1": FieldProvenanceStatement,
    "field-release-receipt-v1": FieldReleaseReceipt,
    "prepared-execution-v1": PreparedExecution,
    "authority-analysis-v1": AuthorityAnalysis,
    "policy-decision-analysis-v1": PolicyDecisionAnalysis,
}


def generated_schema(model: type[object]) -> str:
    schema = getattr(model, "model_json_schema")()
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail without modifying files when generated schemas differ from the repository",
    )
    args = parser.parse_args()

    stale: list[str] = []
    for name, model in MODELS.items():
        target = ROOT / "schemas" / f"{name}.schema.json"
        expected = generated_schema(model)
        if args.check:
            if not target.is_file() or target.read_text(encoding="utf-8") != expected:
                stale.append(str(target.relative_to(ROOT)))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(expected, encoding="utf-8")

    if stale:
        raise SystemExit("stale generated schema(s): " + ", ".join(stale))
    verb = "verified" if args.check else "generated"
    print(f"{verb} {len(MODELS)} schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
