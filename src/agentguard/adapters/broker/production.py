from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Mapping
from uuid import uuid4

from agentguard.adapters.crypto import Ed25519BrokerGrantVerifier, Ed25519Signer
from agentguard.domain import (
    ApprovalReceipt,
    CredentialAuthorityProfile,
    CredentialAuthorityProfileRecord,
    CredentialGrant,
    CredentialProfileStatus,
    CredentialRequest,
    DecisionReceipt,
    ProviderIdentity,
    VerifiedCredentialAuthority,
)
from agentguard.engine.canonical import digest
from agentguard.engine.credentials import attest_credential_grant, validate_credential_request
from agentguard.ports import (
    CredentialMaterialSource,
    CredentialProfileRepository,
    ResolvedCredentialMaterial,
)
from agentguard.security.files import ensure_private_file


class CredentialAuthorityError(ValueError):
    pass


def credential_profile_binding_digest(profile: CredentialAuthorityProfile) -> str:
    return digest(profile)


class EnvironmentCredentialSource:
    """Resolve a credential from the process environment only at dispatch time."""

    def __init__(self, environment_variable: str) -> None:
        if (
            not environment_variable
            or "=" in environment_variable
            or "\x00" in environment_variable
        ):
            raise ValueError("credential_source.environment_variable_invalid")
        self.environment_variable = environment_variable

    @property
    def binding_digest(self) -> str:
        return digest({"kind": "environment", "name": self.environment_variable})

    def read(self) -> str:
        value = os.environ.get(self.environment_variable)
        if value is None:
            raise CredentialAuthorityError("credential.source_unavailable")
        return value


class SQLiteCredentialProfileRepository:
    """Durable non-secret credential profile and revocation state."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS credential_profiles(
        profile_id TEXT PRIMARY KEY,
        binding_digest TEXT UNIQUE NOT NULL,
        audience TEXT NOT NULL,
        tenant_key TEXT NOT NULL,
        profile_json TEXT NOT NULL,
        status TEXT NOT NULL,
        revoked_at TEXT,
        revoke_reason TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_active_credential_profile_audience_tenant
    ON credential_profiles(audience, tenant_key) WHERE status = 'active';
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        ensure_private_file(path)
        with self._connect() as connection:
            connection.executescript(self._SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA secure_delete=ON")
        return connection

    @staticmethod
    def _tenant_key(tenant_id: str | None) -> str:
        return tenant_id or ""

    @staticmethod
    def _record(row: sqlite3.Row) -> CredentialAuthorityProfileRecord:
        profile = CredentialAuthorityProfile.model_validate_json(str(row["profile_json"]))
        revoked_at = row["revoked_at"]
        return CredentialAuthorityProfileRecord(
            profile=profile,
            binding_digest=str(row["binding_digest"]),
            status=CredentialProfileStatus(str(row["status"])),
            revoked_at=(
                datetime.fromisoformat(str(revoked_at)) if revoked_at is not None else None
            ),
            revoke_reason=(str(row["revoke_reason"]) if row["revoke_reason"] is not None else None),
        )

    def store_credential_profile(self, profile: CredentialAuthorityProfile) -> None:
        binding_digest = credential_profile_binding_digest(profile)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM credential_profiles WHERE profile_id = ?", (profile.profile_id,)
            ).fetchone()
            if existing is not None:
                record = self._record(existing)
                if record.status == CredentialProfileStatus.REVOKED:
                    connection.execute("ROLLBACK")
                    raise CredentialAuthorityError("credential.profile_revoked")
                if record.binding_digest != binding_digest:
                    connection.execute("ROLLBACK")
                    raise CredentialAuthorityError("credential.profile_conflict")
                connection.execute("COMMIT")
                return
            try:
                connection.execute(
                    """
                    INSERT INTO credential_profiles(
                        profile_id,binding_digest,audience,tenant_key,profile_json,status
                    ) VALUES(?,?,?,?,?,?)
                    """,
                    (
                        profile.profile_id,
                        binding_digest,
                        profile.audience,
                        self._tenant_key(profile.tenant_id),
                        profile.model_dump_json(),
                        CredentialProfileStatus.ACTIVE.value,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise CredentialAuthorityError("credential.profile_conflict") from exc
            connection.execute("COMMIT")

    def get_credential_profile(self, profile_id: str) -> CredentialAuthorityProfileRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM credential_profiles WHERE profile_id = ?", (profile_id,)
            ).fetchone()
        return self._record(row) if row is not None else None

    def find_active_credential_profile(
        self, audience: str, tenant_id: str | None
    ) -> CredentialAuthorityProfileRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM credential_profiles
                WHERE audience = ? AND tenant_key = ? AND status = ?
                """,
                (
                    audience,
                    self._tenant_key(tenant_id),
                    CredentialProfileStatus.ACTIVE.value,
                ),
            ).fetchone()
        return self._record(row) if row is not None else None

    def get_credential_profile_by_binding_digest(
        self, binding_digest: str
    ) -> CredentialAuthorityProfileRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM credential_profiles WHERE binding_digest = ?", (binding_digest,)
            ).fetchone()
        return self._record(row) if row is not None else None

    def revoke_credential_profile(
        self, profile_id: str, revoked_at: datetime, reason: str
    ) -> CredentialAuthorityProfileRecord:
        if revoked_at.tzinfo is None or revoked_at.utcoffset() is None:
            raise CredentialAuthorityError("credential.revocation_timestamp_invalid")
        if not reason:
            raise CredentialAuthorityError("credential.revocation_reason_required")
        with self._connect() as connection:
            result = connection.execute(
                """
                UPDATE credential_profiles
                SET status = ?, revoked_at = ?, revoke_reason = ?
                WHERE profile_id = ? AND status = ?
                """,
                (
                    CredentialProfileStatus.REVOKED.value,
                    revoked_at.isoformat(),
                    reason,
                    profile_id,
                    CredentialProfileStatus.ACTIVE.value,
                ),
            )
            if result.rowcount != 1:
                raise CredentialAuthorityError("credential.profile_not_active")
        record = self.get_credential_profile(profile_id)
        if record is None:
            raise CredentialAuthorityError("credential.profile_missing")
        return record


class BrokeredCredentialAuthority:
    """Issue signed non-secret grants and resolve provider credentials only at dispatch time."""

    def __init__(
        self,
        *,
        name: str,
        signer: Ed25519Signer,
        profiles: CredentialProfileRepository,
        sources: Mapping[str, CredentialMaterialSource],
    ) -> None:
        if not name:
            raise ValueError("credential.broker_name_required")
        self.name = name
        self._signer = signer
        self._profiles = profiles
        self._sources = dict(sources)

    @property
    def verifier(self) -> Ed25519BrokerGrantVerifier:
        return Ed25519BrokerGrantVerifier(
            {(self.name, self._signer.key_id): self._signer.public_key()}
        )

    def issue(
        self,
        receipt: DecisionReceipt,
        request: CredentialRequest,
        approval: ApprovalReceipt | None = None,
    ) -> CredentialGrant:
        validate_credential_request(receipt, request, approval_verified=approval is not None)
        record = self._profiles.find_active_credential_profile(request.audience, request.tenant_id)
        if record is None:
            raise CredentialAuthorityError("credential.profile_unavailable")
        profile = record.profile
        if request.scopes != profile.scopes:
            # A static/external secret is not attenuated merely because a caller asks for fewer
            # scopes. Exact equality prevents AgentGuard from claiming least privilege it cannot
            # technically enforce at the provider.
            raise CredentialAuthorityError("credential.profile_scope_mismatch")
        source = self._sources.get(profile.profile_id)
        if source is None or source.binding_digest != profile.source_binding_digest:
            raise CredentialAuthorityError("credential.source_binding_mismatch")
        now = datetime.now(UTC)
        if profile.expires_at is not None and profile.expires_at <= now:
            raise CredentialAuthorityError("credential.profile_expired")
        expires_at = min(
            now + timedelta(seconds=request.requested_ttl_seconds),
            receipt.expires_at,
            *([profile.expires_at] if profile.expires_at is not None else []),
        )
        if expires_at <= now:
            raise CredentialAuthorityError("credential.grant_window_invalid")
        grant = CredentialGrant(
            grant_id="grant_" + uuid4().hex,
            issuance_id="iss_" + uuid4().hex,
            decision_id=receipt.decision_id,
            trace_id=receipt.trace_id,
            mode="brokered_execution",
            credential_handle=None,
            credential_handle_digest=record.binding_digest,
            audience=request.audience,
            scopes=request.scopes,
            tenant_id=request.tenant_id,
            issued_at=now,
            expires_at=expires_at,
            broker=self.name,
            broker_key_id=self._signer.key_id,
            attestation="",
        )
        return attest_credential_grant(grant, self._signer)

    def resolve(
        self,
        authority: VerifiedCredentialAuthority,
        provider: ProviderIdentity,
        *,
        now: datetime | None = None,
    ) -> ResolvedCredentialMaterial:
        now = now or datetime.now(UTC)
        if authority.mode != "brokered_execution":
            raise CredentialAuthorityError("credential.brokered_mode_required")
        if authority.broker != self.name or authority.broker_key_id != self._signer.key_id:
            raise CredentialAuthorityError("credential.broker_binding_mismatch")
        if authority.expires_at <= now:
            raise CredentialAuthorityError("credential.expired")
        record = self._profiles.get_credential_profile_by_binding_digest(
            authority.credential_handle_digest
        )
        if record is None:
            raise CredentialAuthorityError("credential.profile_missing")
        if record.status != CredentialProfileStatus.ACTIVE:
            raise CredentialAuthorityError("credential.profile_revoked")
        profile = record.profile
        if profile.expires_at is not None and profile.expires_at <= now:
            raise CredentialAuthorityError("credential.profile_expired")
        if profile.provider != provider:
            raise CredentialAuthorityError("credential.provider_binding_mismatch")
        if (
            authority.audience != profile.audience
            or authority.scopes != profile.scopes
            or authority.tenant_id != profile.tenant_id
        ):
            raise CredentialAuthorityError("credential.profile_binding_mismatch")
        source = self._sources.get(profile.profile_id)
        if source is None or source.binding_digest != profile.source_binding_digest:
            raise CredentialAuthorityError("credential.source_binding_mismatch")
        secret = source.read()
        if (
            not secret
            or secret != secret.strip()
            or "\r" in secret
            or "\n" in secret
            or "\x00" in secret
        ):
            raise CredentialAuthorityError("credential.material_invalid")
        header_value = f"{profile.header_scheme} {secret}" if profile.header_scheme else secret
        return ResolvedCredentialMaterial(
            profile_id=profile.profile_id,
            header_name=profile.header_name,
            header_value=header_value,
            source_binding_digest=profile.source_binding_digest,
        )
