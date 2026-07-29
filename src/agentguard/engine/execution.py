from __future__ import annotations
from datetime import datetime, timezone
from agentguard.domain import ActionIntent, ApprovalReceipt, CredentialGrant, DecisionReceipt, Effect, ExecutionBudget
from agentguard.engine.credentials import verify_credential_grant
from agentguard.engine.receipts import verify_approval_receipt, verify_decision_receipt, verify_intent_binding, ReceiptVerificationError
from agentguard.ports import NonceRepository, SignatureVerifier

class ExecutionGuardError(ValueError): pass

def _check_budget(intent:ActionIntent,b:ExecutionBudget)->None:
    pairs=[
      ("financial_amount",intent.effects.financial_amount_minor,b.maximum_financial_amount_minor),
      ("records_modified",intent.effects.records_modified,b.maximum_records_modified),
      ("external_recipients",intent.effects.external_recipients,b.maximum_external_recipients),
      ("deleted_files",intent.effects.deleted_files,b.maximum_deleted_files),
      ("tool_calls",intent.effects.tool_calls,b.maximum_tool_calls),
      ("execution_seconds",intent.effects.execution_seconds,b.maximum_execution_seconds),
      ("output_bytes",intent.effects.output_bytes,b.maximum_output_bytes),
    ]
    for name,value,maximum in pairs:
        if maximum is not None and (value is None or value>maximum): raise ExecutionGuardError(f"execution.budget.{name}_exceeded")

def authorize_execution(intent:ActionIntent,receipt:DecisionReceipt,grant:CredentialGrant|None,verifier:SignatureVerifier,nonce_repository:NonceRepository,*,approval:ApprovalReceipt|None=None,now:datetime|None=None)->None:
    now=now or datetime.now(timezone.utc)
    try:
        verify_decision_receipt(receipt,verifier,now=now)
        verify_intent_binding(intent,receipt)
    except ReceiptVerificationError as exc:
        raise ExecutionGuardError(str(exc)) from exc
    if receipt.effect==Effect.DENY: raise ExecutionGuardError("execution.decision_not_allow")
    if receipt.effect==Effect.REQUIRE_APPROVAL:
        if approval is None: raise ExecutionGuardError("execution.approval_missing")
        try: verify_approval_receipt(approval,receipt,intent,verifier,now=now)
        except ReceiptVerificationError as exc: raise ExecutionGuardError(str(exc)) from exc
    _check_budget(intent,receipt.execution_budget)
    if receipt.credential_ceiling is not None:
        if grant is None: raise ExecutionGuardError("execution.credential_missing")
        try: verify_credential_grant(receipt,grant,now=now)
        except Exception as exc: raise ExecutionGuardError(str(exc)) from exc
    if not nonce_repository.consume(receipt.nonce,receipt.decision_id,now):
        raise ExecutionGuardError("decision_receipt.replayed")
