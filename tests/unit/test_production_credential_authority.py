from __future__ import annotations

from datetime import UTC, datetime

import pytest

from decisionlock.adapters.broker import (
    BrokeredCredentialAuthority,
    CredentialAuthorityError,
    SQLiteCredentialProfileRepository,
)
from decisionlock.adapters.crypto import Ed25519Signer
from decisionlock.domain import (
    CredentialAuthorityProfile,
    CredentialRequest,
    ProviderIdentity,
    VerifiedCredentialAuthority,
)
from decisionlock.engine.canonical import digest
from decisionlock.engine.credentials import verify_credential_grant
from decisionlock.engine.policy import evaluate_policy
from decisionlock.engine.receipts import issue_decision_receipt


class MutableCredentialSource:
    def __init__(self, value: str, source_id: str = "primary") -> None:
        self.value = value
        self.source_id = source_id
        self.read_count = 0

    @property
    def binding_digest(self) -> str:
        return digest({"kind": "test", "id": self.source_id})

    def read(self) -> str:
        self.read_count += 1
        return self.value


def _setup_authority(tmp_path, intent, policy, signer):
    receipt = issue_decision_receipt(intent, evaluate_policy(policy, intent), signer)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    provider = ProviderIdentity(
        provider_id="mcp-filesystem",
        tenant_id=ceiling.tenant_id,
        endpoint_digest=digest("http://127.0.0.1:9010/mcp"),
    )
    source = MutableCredentialSource("secret-v1")
    profile = CredentialAuthorityProfile(
        profile_id="profile-filesystem",
        provider=provider,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        tenant_id=ceiling.tenant_id,
        source_binding_digest=source.binding_digest,
    )
    repository = SQLiteCredentialProfileRepository(tmp_path / "credential-authority.sqlite")
    repository.store_credential_profile(profile)
    broker_signer = Ed25519Signer.generate("credential-authority-key")
    authority = BrokeredCredentialAuthority(
        name="production-broker",
        signer=broker_signer,
        profiles=repository,
        sources={profile.profile_id: source},
    )
    request = CredentialRequest(
        request_id="credential-request",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=min(30, ceiling.maximum_ttl_seconds),
        tenant_id=ceiling.tenant_id,
    )
    return receipt, provider, profile, repository, source, authority, request


def _verified_authority(grant) -> VerifiedCredentialAuthority:
    return VerifiedCredentialAuthority(
        grant_id=grant.grant_id,
        issuance_id=grant.issuance_id,
        mode=grant.mode,
        credential_handle_digest=grant.credential_handle_digest,
        audience=grant.audience,
        scopes=grant.scopes,
        tenant_id=grant.tenant_id,
        expires_at=grant.expires_at,
        broker=grant.broker,
        broker_key_id=grant.broker_key_id,
    )


def test_brokered_grant_resolves_secret_only_at_dispatch(tmp_path, intent, policy, signer) -> None:
    receipt, provider, _, repository, source, authority, request = _setup_authority(
        tmp_path, intent, policy, signer
    )
    grant = authority.issue(receipt, request)
    assert grant.mode == "brokered_execution"
    assert grant.credential_handle is None
    assert source.read_count == 0
    verify_credential_grant(receipt, grant, authority.verifier)

    material = authority.resolve(_verified_authority(grant), provider)
    assert material.header_name == "Authorization"
    assert material.header_value == "Bearer secret-v1"
    assert source.read_count == 1
    assert "secret-v1" not in repr(material)
    assert b"secret-v1" not in repository.path.read_bytes()


def test_secret_rotation_does_not_require_grant_reissue(tmp_path, intent, policy, signer) -> None:
    receipt, provider, _, _, source, authority, request = _setup_authority(
        tmp_path, intent, policy, signer
    )
    grant = authority.issue(receipt, request)
    verified = _verified_authority(grant)
    first = authority.resolve(verified, provider)
    source.value = "secret-v2"
    second = authority.resolve(verified, provider)
    assert first.header_value == "Bearer secret-v1"
    assert second.header_value == "Bearer secret-v2"


def test_revocation_blocks_already_issued_grant_before_material_read(
    tmp_path, intent, policy, signer
) -> None:
    receipt, provider, profile, repository, source, authority, request = _setup_authority(
        tmp_path, intent, policy, signer
    )
    grant = authority.issue(receipt, request)
    repository.revoke_credential_profile(profile.profile_id, datetime.now(UTC), "compromised")
    with pytest.raises(CredentialAuthorityError, match="profile_revoked"):
        authority.resolve(_verified_authority(grant), provider)
    assert source.read_count == 0


def test_provider_substitution_is_rejected_before_secret_read(
    tmp_path, intent, policy, signer
) -> None:
    receipt, _, _, _, source, authority, request = _setup_authority(
        tmp_path, intent, policy, signer
    )
    grant = authority.issue(receipt, request)
    wrong_provider = ProviderIdentity(
        provider_id="other-provider",
        endpoint_digest=digest("https://other.example/mcp"),
    )
    with pytest.raises(CredentialAuthorityError, match="provider_binding_mismatch"):
        authority.resolve(_verified_authority(grant), wrong_provider)
    assert source.read_count == 0


def test_static_secret_scope_attenuation_is_not_faked(tmp_path, intent, policy, signer) -> None:
    receipt, _, _, _, _, authority, request = _setup_authority(tmp_path, intent, policy, signer)
    one_scope = frozenset({next(iter(request.scopes))})
    if one_scope == request.scopes:
        pytest.skip("fixture credential ceiling has only one scope")
    narrowed = request.model_copy(update={"scopes": one_scope})
    with pytest.raises(CredentialAuthorityError, match="profile_scope_mismatch"):
        authority.issue(receipt, narrowed)


def test_runtime_source_substitution_is_rejected(tmp_path, intent, policy, signer) -> None:
    receipt, _, profile, repository, _, _, request = _setup_authority(
        tmp_path, intent, policy, signer
    )
    wrong_source = MutableCredentialSource("secret-v1", source_id="other")
    authority = BrokeredCredentialAuthority(
        name="production-broker",
        signer=Ed25519Signer.generate("credential-authority-key"),
        profiles=repository,
        sources={profile.profile_id: wrong_source},
    )
    with pytest.raises(CredentialAuthorityError, match="source_binding_mismatch"):
        authority.issue(receipt, request)
