from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentguard.adapters.broker import (
    BrokeredCredentialAuthority,
    CredentialAuthorityError,
    EnvironmentCredentialSource,
    SQLiteCredentialProfileRepository,
    credential_profile_binding_digest,
)
from agentguard.adapters.crypto import Ed25519Signer
from agentguard.domain import (
    CredentialAuthorityProfile,
    CredentialAuthorityProfileRecord,
    CredentialProfileStatus,
    CredentialRequest,
    ProviderIdentity,
    VerifiedCredentialAuthority,
)
from agentguard.engine.canonical import digest
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import issue_decision_receipt


class MutableCredentialSource:
    def __init__(self, value: str, source_id: str = "primary") -> None:
        self.value = value
        self.source_id = source_id
        self.read_count = 0

    @property
    def binding_digest(self) -> str:
        return digest({"kind": "edge-test", "id": self.source_id})

    def read(self) -> str:
        self.read_count += 1
        return self.value


def _setup(tmp_path, intent, policy, signer):
    receipt = issue_decision_receipt(intent, evaluate_policy(policy, intent), signer)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="phase6c-edge-request",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=min(30, ceiling.maximum_ttl_seconds),
        tenant_id=ceiling.tenant_id,
    )
    provider = ProviderIdentity(
        provider_id="edge-provider",
        tenant_id=ceiling.tenant_id,
        endpoint_digest=digest("https://provider.example/mcp"),
    )
    source = MutableCredentialSource("secret-v1")
    profile = CredentialAuthorityProfile(
        profile_id="edge-profile",
        provider=provider,
        audience=request.audience,
        scopes=request.scopes,
        tenant_id=request.tenant_id,
        source_binding_digest=source.binding_digest,
    )
    repository = SQLiteCredentialProfileRepository(tmp_path / "credential-authority.sqlite")
    repository.store_credential_profile(profile)
    broker_signer = Ed25519Signer.generate("edge-credential-key")
    authority = BrokeredCredentialAuthority(
        name="edge-broker",
        signer=broker_signer,
        profiles=repository,
        sources={profile.profile_id: source},
    )
    return receipt, request, provider, source, profile, repository, broker_signer, authority


def _verified(grant) -> VerifiedCredentialAuthority:
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


@pytest.mark.parametrize("name", ["", "NAME=value", "BAD\x00NAME"])
def test_environment_source_rejects_invalid_variable_names(name: str) -> None:
    with pytest.raises(ValueError, match="environment_variable_invalid"):
        EnvironmentCredentialSource(name)


def test_environment_source_is_bound_by_name_and_reads_lazily(monkeypatch) -> None:
    source = EnvironmentCredentialSource("AGENTGUARD_EDGE_SECRET")
    assert source.binding_digest == digest(
        {"kind": "environment", "name": "AGENTGUARD_EDGE_SECRET"}
    )
    monkeypatch.delenv("AGENTGUARD_EDGE_SECRET", raising=False)
    with pytest.raises(CredentialAuthorityError, match="source_unavailable"):
        source.read()
    monkeypatch.setenv("AGENTGUARD_EDGE_SECRET", "rotated-secret")
    assert source.read() == "rotated-secret"


def test_profile_repository_idempotency_conflicts_and_lookup(
    tmp_path, intent, policy, signer
) -> None:
    _, request, provider, source, profile, repository, _, _ = _setup(
        tmp_path, intent, policy, signer
    )
    repository.store_credential_profile(profile)
    record = repository.get_credential_profile(profile.profile_id)
    assert record is not None
    assert record.binding_digest == credential_profile_binding_digest(profile)
    assert repository.find_active_credential_profile(request.audience, request.tenant_id) == record
    assert repository.get_credential_profile_by_binding_digest(record.binding_digest) == record
    assert repository.get_credential_profile("missing") is None
    assert repository.find_active_credential_profile("missing", request.tenant_id) is None
    assert repository.get_credential_profile_by_binding_digest("sha256:" + "0" * 64) is None

    changed = profile.model_copy(update={"header_name": "X-Api-Key"})
    with pytest.raises(CredentialAuthorityError, match="profile_conflict"):
        repository.store_credential_profile(changed)

    duplicate_audience = CredentialAuthorityProfile(
        profile_id="other-profile",
        provider=provider,
        audience=profile.audience,
        scopes=profile.scopes,
        tenant_id=profile.tenant_id,
        source_binding_digest=source.binding_digest,
    )
    with pytest.raises(CredentialAuthorityError, match="profile_conflict"):
        repository.store_credential_profile(duplicate_audience)


def test_profile_revocation_validation_and_tombstone(tmp_path, intent, policy, signer) -> None:
    _, _, _, _, profile, repository, _, _ = _setup(tmp_path, intent, policy, signer)
    with pytest.raises(CredentialAuthorityError, match="revocation_timestamp_invalid"):
        repository.revoke_credential_profile(profile.profile_id, datetime.now(), "reason")
    with pytest.raises(CredentialAuthorityError, match="revocation_reason_required"):
        repository.revoke_credential_profile(profile.profile_id, datetime.now(UTC), "")

    revoked = repository.revoke_credential_profile(
        profile.profile_id, datetime.now(UTC), "operator revocation"
    )
    assert revoked.status == CredentialProfileStatus.REVOKED
    assert revoked.revoked_at is not None
    assert revoked.revoke_reason == "operator revocation"
    with pytest.raises(CredentialAuthorityError, match="profile_not_active"):
        repository.revoke_credential_profile(profile.profile_id, datetime.now(UTC), "again")
    with pytest.raises(CredentialAuthorityError, match="profile_revoked"):
        repository.store_credential_profile(profile)
    assert repository.find_active_credential_profile(profile.audience, profile.tenant_id) is None


def test_broker_configuration_and_issuance_fail_closed(tmp_path, intent, policy, signer) -> None:
    receipt, request, _, source, profile, repository, broker_signer, _ = _setup(
        tmp_path, intent, policy, signer
    )
    with pytest.raises(ValueError, match="broker_name_required"):
        BrokeredCredentialAuthority(
            name="",
            signer=broker_signer,
            profiles=repository,
            sources={profile.profile_id: source},
        )

    empty_repository = SQLiteCredentialProfileRepository(tmp_path / "empty.sqlite")
    no_profile = BrokeredCredentialAuthority(
        name="edge-broker",
        signer=broker_signer,
        profiles=empty_repository,
        sources={},
    )
    with pytest.raises(CredentialAuthorityError, match="profile_unavailable"):
        no_profile.issue(receipt, request)

    no_source = BrokeredCredentialAuthority(
        name="edge-broker",
        signer=broker_signer,
        profiles=repository,
        sources={},
    )
    with pytest.raises(CredentialAuthorityError, match="source_binding_mismatch"):
        no_source.issue(receipt, request)

    wrong_source = MutableCredentialSource("secret-v1", source_id="substituted")
    substituted = BrokeredCredentialAuthority(
        name="edge-broker",
        signer=broker_signer,
        profiles=repository,
        sources={profile.profile_id: wrong_source},
    )
    with pytest.raises(CredentialAuthorityError, match="source_binding_mismatch"):
        substituted.issue(receipt, request)


def test_expired_profile_and_expired_receipt_cannot_issue(tmp_path, intent, policy, signer) -> None:
    receipt, request, provider, source, _, _, broker_signer, _ = _setup(
        tmp_path, intent, policy, signer
    )
    expired_profile = CredentialAuthorityProfile(
        profile_id="expired-profile",
        provider=provider,
        audience=request.audience,
        scopes=request.scopes,
        tenant_id=request.tenant_id,
        source_binding_digest=source.binding_digest,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    expired_repository = SQLiteCredentialProfileRepository(tmp_path / "expired.sqlite")
    expired_repository.store_credential_profile(expired_profile)
    expired_authority = BrokeredCredentialAuthority(
        name="edge-broker",
        signer=broker_signer,
        profiles=expired_repository,
        sources={expired_profile.profile_id: source},
    )
    with pytest.raises(CredentialAuthorityError, match="profile_expired"):
        expired_authority.issue(receipt, request)

    fresh_repository = SQLiteCredentialProfileRepository(tmp_path / "fresh.sqlite")
    fresh_profile = expired_profile.model_copy(
        update={"profile_id": "fresh-profile", "expires_at": None}
    )
    fresh_repository.store_credential_profile(fresh_profile)
    fresh_authority = BrokeredCredentialAuthority(
        name="edge-broker",
        signer=broker_signer,
        profiles=fresh_repository,
        sources={fresh_profile.profile_id: source},
    )
    expired_receipt = receipt.model_copy(
        update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    with pytest.raises(CredentialAuthorityError, match="grant_window_invalid"):
        fresh_authority.issue(expired_receipt, request)


def test_resolver_rejects_wrong_mode_broker_expiry_and_missing_profile(
    tmp_path, intent, policy, signer
) -> None:
    receipt, request, provider, _, _, _, _, authority = _setup(tmp_path, intent, policy, signer)
    grant = authority.issue(receipt, request)
    verified = _verified(grant)

    with pytest.raises(CredentialAuthorityError, match="brokered_mode_required"):
        authority.resolve(verified.model_copy(update={"mode": "opaque_handle"}), provider)
    with pytest.raises(CredentialAuthorityError, match="broker_binding_mismatch"):
        authority.resolve(verified.model_copy(update={"broker": "other-broker"}), provider)
    with pytest.raises(CredentialAuthorityError, match="broker_binding_mismatch"):
        authority.resolve(verified.model_copy(update={"broker_key_id": "other-key"}), provider)
    with pytest.raises(CredentialAuthorityError, match="credential.expired"):
        authority.resolve(verified, provider, now=verified.expires_at)
    with pytest.raises(CredentialAuthorityError, match="profile_missing"):
        authority.resolve(
            verified.model_copy(update={"credential_handle_digest": "sha256:" + "0" * 64}),
            provider,
        )


def test_resolver_revalidates_profile_provider_authority_and_source(
    tmp_path, intent, policy, signer
) -> None:
    receipt, request, provider, source, profile, repository, broker_signer, authority = _setup(
        tmp_path, intent, policy, signer
    )
    grant = authority.issue(receipt, request)
    verified = _verified(grant)

    wrong_provider = provider.model_copy(update={"provider_id": "substituted-provider"})
    with pytest.raises(CredentialAuthorityError, match="provider_binding_mismatch"):
        authority.resolve(verified, wrong_provider)
    with pytest.raises(CredentialAuthorityError, match="profile_binding_mismatch"):
        authority.resolve(verified.model_copy(update={"audience": "wrong-audience"}), provider)
    with pytest.raises(CredentialAuthorityError, match="profile_binding_mismatch"):
        authority.resolve(
            verified.model_copy(update={"scopes": frozenset({"wrong-scope"})}), provider
        )
    with pytest.raises(CredentialAuthorityError, match="profile_binding_mismatch"):
        authority.resolve(verified.model_copy(update={"tenant_id": "wrong-tenant"}), provider)

    wrong_source = MutableCredentialSource("secret-v1", source_id="wrong")
    wrong_source_authority = BrokeredCredentialAuthority(
        name="edge-broker",
        signer=broker_signer,
        profiles=repository,
        sources={profile.profile_id: wrong_source},
    )
    with pytest.raises(CredentialAuthorityError, match="source_binding_mismatch"):
        wrong_source_authority.resolve(verified, provider)
    assert wrong_source.read_count == 0
    assert source.read_count == 0


def test_resolver_rechecks_profile_expiry_and_revocation(tmp_path, intent, policy, signer) -> None:
    receipt, request, provider, source, profile, repository, broker_signer, authority = _setup(
        tmp_path, intent, policy, signer
    )
    grant = authority.issue(receipt, request)
    verified = _verified(grant)
    repository.revoke_credential_profile(profile.profile_id, datetime.now(UTC), "compromised")
    with pytest.raises(CredentialAuthorityError, match="profile_revoked"):
        authority.resolve(verified, provider)
    assert source.read_count == 0

    expiring_source = MutableCredentialSource("secret-v2", source_id="expiring")
    expires_at = datetime.now(UTC) + timedelta(minutes=1)
    expiring_profile = CredentialAuthorityProfile(
        profile_id="expiring-profile",
        provider=provider,
        audience=request.audience,
        scopes=request.scopes,
        tenant_id=request.tenant_id,
        source_binding_digest=expiring_source.binding_digest,
        expires_at=expires_at,
    )
    expiring_repository = SQLiteCredentialProfileRepository(tmp_path / "expiring.sqlite")
    expiring_repository.store_credential_profile(expiring_profile)
    expiring_authority = BrokeredCredentialAuthority(
        name="edge-broker",
        signer=broker_signer,
        profiles=expiring_repository,
        sources={expiring_profile.profile_id: expiring_source},
    )
    expiring_grant = expiring_authority.issue(receipt, request)
    expiring_verified = _verified(expiring_grant).model_copy(
        update={"expires_at": expires_at + timedelta(seconds=1)}
    )
    with pytest.raises(CredentialAuthorityError, match="profile_expired"):
        expiring_authority.resolve(expiring_verified, provider, now=expires_at)
    assert expiring_source.read_count == 0


@pytest.mark.parametrize(
    "secret",
    ["", " leading", "trailing ", "line\nbreak", "line\rbreak", "nul\x00byte"],
)
def test_resolver_rejects_unsafe_material(secret, tmp_path, intent, policy, signer) -> None:
    receipt, request, provider, source, _, _, _, authority = _setup(
        tmp_path, intent, policy, signer
    )
    grant = authority.issue(receipt, request)
    source.value = secret
    with pytest.raises(CredentialAuthorityError, match="material_invalid"):
        authority.resolve(_verified(grant), provider)
    assert source.read_count == 1


def test_resolver_can_emit_raw_header_without_scheme(tmp_path, intent, policy, signer) -> None:
    receipt, request, provider, source, profile, _, broker_signer, _ = _setup(
        tmp_path, intent, policy, signer
    )
    raw_profile = profile.model_copy(
        update={"profile_id": "raw-profile", "header_name": "X-Api-Key", "header_scheme": None}
    )
    raw_repository = SQLiteCredentialProfileRepository(tmp_path / "raw.sqlite")
    raw_repository.store_credential_profile(raw_profile)
    authority = BrokeredCredentialAuthority(
        name="edge-broker",
        signer=broker_signer,
        profiles=raw_repository,
        sources={raw_profile.profile_id: source},
    )
    material = authority.resolve(_verified(authority.issue(receipt, request)), provider)
    assert material.header_name == "X-Api-Key"
    assert material.header_value == "secret-v1"
    assert "secret-v1" not in repr(material)


@pytest.mark.parametrize("header_name", ["bad header", "Content-Type", "Mcp-Param-Region"])
def test_profile_rejects_invalid_or_reserved_credential_headers(header_name: str) -> None:
    provider = ProviderIdentity(
        provider_id="provider", endpoint_digest=digest("https://provider.example/mcp")
    )
    with pytest.raises(ValueError):
        CredentialAuthorityProfile(
            profile_id="profile",
            provider=provider,
            audience="audience",
            scopes=frozenset({"scope"}),
            source_binding_digest=digest("source"),
            header_name=header_name,
        )


@pytest.mark.parametrize("scheme", ["", "Bearer token", "Bearer\nInjected"])
def test_profile_rejects_invalid_header_scheme(scheme: str) -> None:
    provider = ProviderIdentity(
        provider_id="provider", endpoint_digest=digest("https://provider.example/mcp")
    )
    with pytest.raises(ValueError):
        CredentialAuthorityProfile(
            profile_id="profile",
            provider=provider,
            audience="audience",
            scopes=frozenset({"scope"}),
            source_binding_digest=digest("source"),
            header_scheme=scheme,
        )


def test_profile_and_record_validate_security_metadata() -> None:
    endpoint_digest = digest("https://provider.example/mcp")
    provider = ProviderIdentity(
        provider_id="provider",
        tenant_id="provider-tenant",
        endpoint_digest=endpoint_digest,
    )
    with pytest.raises(ValueError, match="provider_tenant_mismatch"):
        CredentialAuthorityProfile(
            profile_id="profile",
            provider=provider,
            audience="audience",
            scopes=frozenset({"scope"}),
            tenant_id="other-tenant",
            source_binding_digest=digest("source"),
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        CredentialAuthorityProfile(
            profile_id="profile",
            provider=ProviderIdentity(provider_id="provider", endpoint_digest=endpoint_digest),
            audience="audience",
            scopes=frozenset({"scope"}),
            source_binding_digest=digest("source"),
            expires_at=datetime.now(),
        )

    profile = CredentialAuthorityProfile(
        profile_id="profile",
        provider=ProviderIdentity(provider_id="provider", endpoint_digest=endpoint_digest),
        audience="audience",
        scopes=frozenset({"scope"}),
        source_binding_digest=digest("source"),
    )
    binding = credential_profile_binding_digest(profile)
    with pytest.raises(ValueError, match="active_cannot_be_revoked"):
        CredentialAuthorityProfileRecord(
            profile=profile,
            binding_digest=binding,
            status=CredentialProfileStatus.ACTIVE,
            revoked_at=datetime.now(UTC),
            revoke_reason="unexpected",
        )
    with pytest.raises(ValueError, match="revocation_metadata_required"):
        CredentialAuthorityProfileRecord(
            profile=profile,
            binding_digest=binding,
            status=CredentialProfileStatus.REVOKED,
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        CredentialAuthorityProfileRecord(
            profile=profile,
            binding_digest=binding,
            status=CredentialProfileStatus.REVOKED,
            revoked_at=datetime.now(),
            revoke_reason="reason",
        )
