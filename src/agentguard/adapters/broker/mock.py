from __future__ import annotations
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from agentguard.domain import ApprovalReceipt, CredentialGrant, CredentialRequest, DecisionReceipt
from agentguard.engine.credentials import validate_credential_request

class MockCredentialBroker:
    """Contract-faithful broker used for demos and tests; never holds a real secret."""
    def __init__(self,name:str="mock-loadout") -> None: self.name=name
    def issue(self,receipt:DecisionReceipt,request:CredentialRequest,approval:ApprovalReceipt|None=None)->CredentialGrant:
        validate_credential_request(receipt,request,approval_verified=approval is not None)
        now=datetime.now(timezone.utc)
        return CredentialGrant(
          grant_id="grant_"+uuid4().hex,issuance_id="iss_"+uuid4().hex,
          decision_id=receipt.decision_id,trace_id=receipt.trace_id,mode="opaque_handle",
          credential_handle=f"opaque://{self.name}/{uuid4().hex}",audience=request.audience,
          scopes=request.scopes,tenant_id=request.tenant_id,issued_at=now,
          expires_at=now+timedelta(seconds=request.requested_ttl_seconds),broker=self.name,
        )
