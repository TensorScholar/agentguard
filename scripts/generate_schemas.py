import json
from pathlib import Path

from agentguard.domain import (
    ActionIntent,
    ApprovalReceipt,
    AuditEvent,
    CredentialGrant,
    CredentialRequest,
    DecisionReceipt,
    ExecutionOutcome,
    ExecutionRequest,
    PolicyDocument,
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
}

for name, model in MODELS.items():
    target = ROOT / "schemas" / f"{name}.schema.json"
    target.write_text(
        json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
print(f"generated {len(MODELS)} schemas")
