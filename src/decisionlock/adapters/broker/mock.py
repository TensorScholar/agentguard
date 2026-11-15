from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from decisionlock.adapters.crypto import Ed25519BrokerGrantVerifier, Ed25519Signer
from decisionlock.domain import ApprovalReceipt, CredentialGrant, CredentialRequest, DecisionReceipt
from decisionlock.engine.canonical import digest
from decisionlock.engine.credentials import (
    attest_credential_grant,
    validate_credential_request,
)


class MockCredentialBroker:
    """Contract-faithful broker used for demos and tests; never holds a real secret."""

    def __init__(
        self,
        name: str = "mock-broker",
        signer: Ed25519Signer | None = None,
    ) -> None:
        self.name = name
        self._signer = signer or Ed25519Signer.generate("mock-broker-ed25519")

    @property
    def verifier(self) -> Ed25519BrokerGrantVerifier:
        return Ed25519BrokerGrantVerifier(
            {(self.name, self._signer.key_id): self._signer.public_key()}
        )

    def attest_for_testing(self, grant: CredentialGrant) -> CredentialGrant:
        """Re-attest a synthetic grant for negative ceiling tests and the offline demo."""

        return attest_credential_grant(grant, self._signer)

    def issue(
        self,
        receipt: DecisionReceipt,
        request: CredentialRequest,
        approval: ApprovalReceipt | None = None,
    ) -> CredentialGrant:
        validate_credential_request(receipt, request, approval_verified=approval is not None)
        now = datetime.now(UTC)
        handle = f"opaque://{self.name}/{uuid4().hex}"
        grant = CredentialGrant(
            grant_id="grant_" + uuid4().hex,
            issuance_id="iss_" + uuid4().hex,
            decision_id=receipt.decision_id,
            trace_id=receipt.trace_id,
            mode="opaque_handle",
            credential_handle=handle,
            credential_handle_digest=digest(handle),
            audience=request.audience,
            scopes=request.scopes,
            tenant_id=request.tenant_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=request.requested_ttl_seconds),
            broker=self.name,
            broker_key_id=self._signer.key_id,
            attestation="",
        )
        return attest_credential_grant(grant, self._signer)
