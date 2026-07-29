from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4
from agentguard.domain import ActionIntent, ApprovalReceipt, AuditEvent, AuditEventType, CredentialGrant, CredentialRequest, DecisionReceipt, EnforcementMode, PolicyDocument
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import issue_approval_receipt, issue_decision_receipt, verify_approval_receipt
from agentguard.engine.execution import authorize_execution
from agentguard.ports import AuditRepository, CredentialBroker, NonceRepository, Signer, SignatureVerifier

class AgentGuardService:
    def __init__(self,signer:Signer,verifier:SignatureVerifier,state:AuditRepository|NonceRepository):
        self.signer=signer; self.verifier=verifier; self.state=state
    def _event(self,event_type:AuditEventType,intent:ActionIntent,**kw)->AuditEvent:
        return AuditEvent(event_id="evt_"+uuid4().hex,event_type=event_type,timestamp=datetime.now(timezone.utc),trace_id=intent.trace_id,request_id=intent.request_id,source="agentguard",**kw)
    def authorize(self,intent:ActionIntent,policy:PolicyDocument,*,mode:EnforcementMode=EnforcementMode.ENFORCE,ttl_seconds:int=60)->DecisionReceipt:
        self.state.append(self._event(AuditEventType.AUTHORIZATION_REQUESTED,intent))
        evaluation=evaluate_policy(policy,intent)
        receipt=issue_decision_receipt(intent,evaluation,self.signer,ttl_seconds=ttl_seconds,mode=mode)
        self.state.append(self._event(AuditEventType.AUTHORIZATION_DECIDED,intent,decision_id=receipt.decision_id,reason_code=receipt.reason_codes[0],data={"effect":receipt.effect.value,"policy_digest":receipt.policy_digest}))
        return receipt
    def approve(self,intent:ActionIntent,receipt:DecisionReceipt,*,approver_subject:str,reason:str,authentication_level:str|None=None)->ApprovalReceipt:
        approval=issue_approval_receipt(receipt,intent,self.signer,approver_subject=approver_subject,reason=reason,authentication_level=authentication_level)
        self.state.append(self._event(AuditEventType.APPROVAL_GRANTED,intent,decision_id=receipt.decision_id,approval_id=approval.approval_id,data={"approver":approver_subject}))
        return approval
    def request_credential(self,intent:ActionIntent,receipt:DecisionReceipt,request:CredentialRequest,broker:CredentialBroker,approval:ApprovalReceipt|None=None)->CredentialGrant:
        if approval is not None:
            verify_approval_receipt(approval,receipt,intent,self.verifier)
            if request.approval_id!=approval.approval_id: raise ValueError("credential.approval_binding_mismatch")
        self.state.append(self._event(AuditEventType.CREDENTIAL_REQUESTED,intent,decision_id=receipt.decision_id,data={"audience":request.audience,"scope_count":len(request.scopes)}))
        grant=broker.issue(receipt,request,approval)
        self.state.append(self._event(AuditEventType.CREDENTIAL_ISSUED,intent,decision_id=receipt.decision_id,issuance_id=grant.issuance_id,data={"broker":grant.broker,"audience":grant.audience,"scope_count":len(grant.scopes)}))
        return grant
    def guard_execution(self,intent:ActionIntent,receipt:DecisionReceipt,grant:CredentialGrant|None,approval:ApprovalReceipt|None=None)->None:
        authorize_execution(intent,receipt,grant,self.verifier,self.state,approval=approval)
        self.state.append(self._event(AuditEventType.RECEIPT_CONSUMED,intent,decision_id=receipt.decision_id,data={"nonce":receipt.nonce}))
