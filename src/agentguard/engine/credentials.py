from __future__ import annotations

from datetime import UTC, datetime

from agentguard.domain import CredentialGrant, CredentialRequest, DecisionReceipt, Effect


class CredentialVerificationError(ValueError):
    pass


def validate_credential_request(
    receipt: DecisionReceipt, request: CredentialRequest, *, approval_verified: bool = False
) -> None:
    if receipt.effect == Effect.REQUIRE_APPROVAL and not approval_verified:
        raise CredentialVerificationError("credential.approval_required")
    if receipt.effect not in {Effect.ALLOW, Effect.REQUIRE_APPROVAL}:
        raise CredentialVerificationError("credential.decision_not_allow")
    ceiling = receipt.credential_ceiling
    if ceiling is None:
        raise CredentialVerificationError("credential.no_ceiling")
    if request.decision_id != receipt.decision_id or request.trace_id != receipt.trace_id:
        raise CredentialVerificationError("credential.decision_binding_mismatch")
    if request.audience != ceiling.audience:
        raise CredentialVerificationError("credential.audience_mismatch")
    if not request.scopes.issubset(ceiling.scopes):
        raise CredentialVerificationError("credential.requested_scope_exceeds_decision")
    if request.requested_ttl_seconds > ceiling.maximum_ttl_seconds:
        raise CredentialVerificationError("credential.requested_ttl_exceeds_decision")
    if ceiling.tenant_id is not None and request.tenant_id != ceiling.tenant_id:
        raise CredentialVerificationError("credential.tenant_mismatch")


def verify_credential_grant(
    receipt: DecisionReceipt, grant: CredentialGrant, *, now: datetime | None = None
) -> None:
    now = now or datetime.now(UTC)
    ceiling = receipt.credential_ceiling
    if ceiling is None:
        raise CredentialVerificationError("credential.no_ceiling")
    if grant.decision_id != receipt.decision_id or grant.trace_id != receipt.trace_id:
        raise CredentialVerificationError("credential.grant_binding_mismatch")
    if grant.audience != ceiling.audience:
        raise CredentialVerificationError("credential.audience_mismatch")
    if not grant.scopes.issubset(ceiling.scopes):
        raise CredentialVerificationError("credential.scope_exceeds_decision")
    ttl = (grant.expires_at - grant.issued_at).total_seconds()
    if ttl > ceiling.maximum_ttl_seconds:
        raise CredentialVerificationError("credential.ttl_exceeds_decision")
    if grant.expires_at <= now:
        raise CredentialVerificationError("credential.expired")
    if grant.issued_at > now:
        raise CredentialVerificationError("credential.not_yet_valid")
    if ceiling.tenant_id is not None and grant.tenant_id != ceiling.tenant_id:
        raise CredentialVerificationError("credential.tenant_mismatch")
