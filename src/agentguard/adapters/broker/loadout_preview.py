from __future__ import annotations
from agentguard.domain import ApprovalReceipt, CredentialGrant, CredentialRequest, DecisionReceipt

class LoadoutIntegrationNotConfigured(RuntimeError): pass

class LoadoutPreviewBroker:
    """Deliberately non-networking preview. Real adapter requires Loadout API contract and sandbox."""
    def issue(self,receipt:DecisionReceipt,request:CredentialRequest,approval:ApprovalReceipt|None=None)->CredentialGrant:
        raise LoadoutIntegrationNotConfigured(
          "Loadout adapter is a contract preview only; configure against reviewed API documentation and sandbox"
        )
