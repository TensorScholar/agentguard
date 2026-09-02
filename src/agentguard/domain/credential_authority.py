from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .models import StrictModel
from .provider_contracts import ProviderIdentity

_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_FORBIDDEN_CREDENTIAL_HEADERS = frozenset(
    {
        "accept",
        "connection",
        "content-length",
        "content-type",
        "cookie",
        "host",
        "mcp-method",
        "mcp-name",
        "mcp-protocol-version",
        "proxy-authorization",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


class CredentialProfileStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class CredentialAuthorityProfile(StrictModel):
    """Durable non-secret binding from policy credential authority to a provider secret source."""

    schema_version: Literal["1"] = "1"
    profile_id: str = Field(min_length=1, max_length=200)
    provider: ProviderIdentity
    audience: str = Field(min_length=1, max_length=500)
    scopes: frozenset[str] = Field(min_length=1)
    tenant_id: str | None = Field(default=None, max_length=200)
    source_binding_digest: str = Field(pattern=_SHA256_PATTERN)
    header_name: str = Field(default="Authorization", min_length=1, max_length=200)
    header_scheme: str | None = Field(default="Bearer", max_length=100)
    expires_at: datetime | None = None

    @field_validator("header_name")
    @classmethod
    def validate_header_name(cls, value: str) -> str:
        if not _HEADER_NAME_RE.fullmatch(value):
            raise ValueError("credential_profile.header_name_invalid")
        normalized = value.lower()
        if normalized in _FORBIDDEN_CREDENTIAL_HEADERS or normalized.startswith("mcp-param-"):
            raise ValueError("credential_profile.header_name_reserved")
        return value

    @field_validator("header_scheme")
    @classmethod
    def validate_header_scheme(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value
            or any(character.isspace() for character in value)
            or "\r" in value
            or "\n" in value
        ):
            raise ValueError("credential_profile.header_scheme_invalid")
        return value

    @field_validator("expires_at")
    @classmethod
    def aware_expiry(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("credential profile expiry must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_tenant_binding(self) -> "CredentialAuthorityProfile":
        provider_tenant = self.provider.tenant_id
        if provider_tenant is not None and self.tenant_id != provider_tenant:
            raise ValueError("credential_profile.provider_tenant_mismatch")
        return self


class CredentialAuthorityProfileRecord(StrictModel):
    profile: CredentialAuthorityProfile
    binding_digest: str = Field(pattern=_SHA256_PATTERN)
    status: CredentialProfileStatus
    revoked_at: datetime | None = None
    revoke_reason: str | None = Field(default=None, max_length=1000)

    @field_validator("revoked_at")
    @classmethod
    def aware_revoked_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("credential profile revocation timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_revocation_state(self) -> "CredentialAuthorityProfileRecord":
        if self.status == CredentialProfileStatus.ACTIVE:
            if self.revoked_at is not None or self.revoke_reason is not None:
                raise ValueError("credential_profile.active_cannot_be_revoked")
        elif self.revoked_at is None or self.revoke_reason is None:
            raise ValueError("credential_profile.revocation_metadata_required")
        return self
