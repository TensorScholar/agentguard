from __future__ import annotations

from agentguard.domain import VerifiedCredentialAuthority
from agentguard.domain.provider_contracts import (
    CredentialBinding,
    ExecutionAttemptIdentity,
    ExternalEffectBinding,
    ExternalOperationIdentity,
    ProviderEvidence,
    ProviderIdentity,
)
from agentguard.engine.canonical import digest


def provider_identity_digest(provider: ProviderIdentity) -> str:
    return digest(provider)


def external_operation_identity_digest(operation: ExternalOperationIdentity) -> str:
    return digest(operation)


def credential_binding_digest(binding: CredentialBinding) -> str:
    return digest(binding)


def execution_attempt_identity_digest(attempt: ExecutionAttemptIdentity) -> str:
    return digest(attempt)


def external_effect_binding_digest(binding: ExternalEffectBinding) -> str:
    return digest(binding)


def credential_binding_from_verified_authority(
    authority: VerifiedCredentialAuthority,
) -> CredentialBinding:
    """Project verified authority into the non-secret provider-effect credential contract."""

    return CredentialBinding(
        grant_id=authority.grant_id,
        issuance_id=authority.issuance_id,
        credential_handle_digest=authority.credential_handle_digest,
        audience=authority.audience,
        scopes=authority.scopes,
        tenant_id=authority.tenant_id,
        broker=authority.broker,
        broker_key_id=authority.broker_key_id,
    )


def verify_provider_evidence_binding(
    binding: ExternalEffectBinding,
    evidence: ProviderEvidence,
) -> None:
    """Fail closed when provider evidence is correlated to a different external effect."""

    if evidence.binding_digest != external_effect_binding_digest(binding):
        raise ValueError("provider_evidence.binding_mismatch")
