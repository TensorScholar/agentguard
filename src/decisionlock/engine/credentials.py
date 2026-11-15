from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from decisionlock.adapters.crypto import decode_signature, encode_signature
from decisionlock.domain import CredentialGrant, CredentialRequest, DecisionReceipt, Effect
from decisionlock.engine.canonical import canonical_bytes, digest
from decisionlock.ports import BrokerGrantVerifier, Signer


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


def credential_grant_attestation_payload(grant: CredentialGrant) -> dict[str, Any]:
    """Return only authenticated grant metadata; never include the opaque handle."""

    return {
        "schema_version": grant.schema_version,
        "grant_id": grant.grant_id,
        "issuance_id": grant.issuance_id,
        "decision_id": grant.decision_id,
        "trace_id": grant.trace_id,
        "mode": grant.mode,
        "credential_handle_digest": grant.credential_handle_digest,
        "audience": grant.audience,
        "scopes": grant.scopes,
        "tenant_id": grant.tenant_id,
        "issued_at": grant.issued_at,
        "expires_at": grant.expires_at,
        "broker": grant.broker,
        "broker_key_id": grant.broker_key_id,
    }


def attest_credential_grant(grant: CredentialGrant, signer: Signer) -> CredentialGrant:
    if grant.broker_key_id != signer.key_id:
        raise CredentialVerificationError("credential.broker_key_binding_mismatch")
    signature = signer.sign(canonical_bytes(credential_grant_attestation_payload(grant)))
    return grant.model_copy(update={"attestation": encode_signature(signature)})


def verify_credential_grant(
    receipt: DecisionReceipt,
    grant: CredentialGrant,
    verifier: BrokerGrantVerifier | None,
    *,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    if (
        now.tzinfo is None
        or now.utcoffset() is None
        or grant.issued_at.tzinfo is None
        or grant.issued_at.utcoffset() is None
        or grant.expires_at.tzinfo is None
        or grant.expires_at.utcoffset() is None
    ):
        raise CredentialVerificationError("credential.timestamp_invalid")
    if verifier is None:
        raise CredentialVerificationError("credential.grant_verifier_unavailable")
    if grant.mode == "opaque_handle":
        if grant.credential_handle is None:
            raise CredentialVerificationError("credential.handle_missing")
        if digest(grant.credential_handle) != grant.credential_handle_digest:
            raise CredentialVerificationError("credential.handle_digest_mismatch")
    elif grant.mode == "brokered_execution":
        # Brokered grants authenticate a non-secret credential-profile binding digest. The actual
        # provider secret does not exist in the grant and is resolved again at dispatch time.
        if grant.credential_handle is not None:
            raise CredentialVerificationError("credential.handle_forbidden")
        if not grant.credential_handle_digest.startswith("sha256:"):
            raise CredentialVerificationError("credential.profile_binding_digest_invalid")
    else:
        raise CredentialVerificationError("credential.mode_invalid")
    try:
        signature = decode_signature(grant.attestation)
    except ValueError as exc:
        raise CredentialVerificationError("credential.grant_attestation_invalid") from exc
    if not verifier.verify(
        grant.broker,
        grant.broker_key_id,
        canonical_bytes(credential_grant_attestation_payload(grant)),
        signature,
    ):
        raise CredentialVerificationError("credential.grant_attestation_invalid")
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
    if grant.issued_at < receipt.not_before or grant.expires_at > receipt.expires_at:
        raise CredentialVerificationError("credential.validity_exceeds_decision")
    if grant.expires_at <= now:
        raise CredentialVerificationError("credential.expired")
    if grant.issued_at > now:
        raise CredentialVerificationError("credential.not_yet_valid")
    if ceiling.tenant_id is not None and grant.tenant_id != ceiling.tenant_id:
        raise CredentialVerificationError("credential.tenant_mismatch")
