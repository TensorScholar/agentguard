from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from agentguard.adapters.crypto import decode_signature, encode_signature
from agentguard.domain import (
    ActionIntent,
    AuthorityGrant,
    CapabilityScope,
    Principal,
)
from agentguard.engine.canonical import canonical_bytes, digest
from agentguard.ports import SignatureVerifier, Signer


class AuthorityError(ValueError):
    pass


def _unsigned(grant: AuthorityGrant) -> dict[str, Any]:
    value = grant.model_dump(mode="python")
    value["signature"] = ""
    return value


def verify_authority_grant_signature(
    grant: AuthorityGrant,
    verifier: SignatureVerifier,
) -> None:
    try:
        signature = decode_signature(grant.signature)
    except ValueError as exc:
        raise AuthorityError("authority.signature_invalid") from exc
    if not verifier.verify(grant.key_id, canonical_bytes(_unsigned(grant)), signature):
        raise AuthorityError("authority.signature_invalid")


def issue_root_authority(
    subject: Principal,
    scope: CapabilityScope,
    signer: Signer,
    *,
    issuer: str = "agentguard",
    ttl_seconds: int = 3600,
    now: datetime | None = None,
) -> AuthorityGrant:
    now = now or datetime.now(UTC)
    if ttl_seconds < 1 or ttl_seconds > 86_400:
        raise AuthorityError("authority.ttl_invalid")
    grant = AuthorityGrant(
        grant_id="auth_" + uuid4().hex,
        parent_grant_id=None,
        issuer=issuer,
        subject=subject,
        scope=scope,
        depth=0,
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        key_id=signer.key_id,
        signature="",
    )
    return grant.model_copy(
        update={"signature": encode_signature(signer.sign(canonical_bytes(_unsigned(grant))))}
    )


def _set_is_attenuated(child: frozenset[str] | None, parent: frozenset[str] | None) -> bool:
    if parent is None:
        return True
    if child is None:
        return False
    return child <= parent


def scope_is_attenuated(child: CapabilityScope, parent: CapabilityScope) -> bool:
    if not child.capabilities <= parent.capabilities:
        return False
    for name in (
        "protocols",
        "servers",
        "tools",
        "operations",
        "resource_types",
        "resource_ids",
    ):
        if not _set_is_attenuated(getattr(child, name), getattr(parent, name)):
            return False
    if child.maximum_calls > parent.maximum_calls:
        return False
    if child.maximum_delegation_depth > parent.maximum_delegation_depth:
        return False
    if child.delegable and not parent.delegable:
        return False
    return True


def delegate_authority(
    parent: AuthorityGrant,
    subject: Principal,
    scope: CapabilityScope,
    signer: Signer,
    verifier: SignatureVerifier,
    *,
    ttl_seconds: int = 1800,
    now: datetime | None = None,
) -> AuthorityGrant:
    now = now or datetime.now(UTC)
    verify_authority_grant_signature(parent, verifier)
    if now >= parent.expires_at:
        raise AuthorityError("authority.parent_expired")
    if not parent.scope.delegable:
        raise AuthorityError("authority.parent_not_delegable")
    depth = parent.depth + 1
    if depth > parent.scope.maximum_delegation_depth:
        raise AuthorityError("authority.delegation_depth_exceeded")
    if subject.tenant_id != parent.subject.tenant_id:
        raise AuthorityError("authority.cross_tenant_delegation")
    if not scope_is_attenuated(scope, parent.scope):
        raise AuthorityError("authority.scope_amplification")
    if ttl_seconds < 1:
        raise AuthorityError("authority.ttl_invalid")
    expires_at = min(now + timedelta(seconds=ttl_seconds), parent.expires_at)
    if expires_at <= now:
        raise AuthorityError("authority.ttl_invalid")
    grant = AuthorityGrant(
        grant_id="auth_" + uuid4().hex,
        parent_grant_id=parent.grant_id,
        issuer=parent.subject.agent_id,
        subject=subject,
        scope=scope,
        depth=depth,
        issued_at=now,
        expires_at=expires_at,
        key_id=signer.key_id,
        signature="",
    )
    return grant.model_copy(
        update={"signature": encode_signature(signer.sign(canonical_bytes(_unsigned(grant))))}
    )


def authority_chain_digest(chain: tuple[AuthorityGrant, ...]) -> str:
    return digest(tuple(digest(grant) for grant in chain))


def _matches(value: str | None, allowed: frozenset[str] | None) -> bool:
    return allowed is None or (value is not None and value in allowed)


def scope_allows_intent(scope: CapabilityScope, intent: ActionIntent) -> bool:
    action = intent.action
    if not action.capabilities <= scope.capabilities:
        return False
    if not _matches(action.protocol, scope.protocols):
        return False
    if not _matches(action.server, scope.servers):
        return False
    if not _matches(action.tool, scope.tools):
        return False
    if not _matches(action.operation, scope.operations):
        return False
    if intent.resource is not None:
        if not _matches(intent.resource.type, scope.resource_types):
            return False
        if not _matches(intent.resource.id, scope.resource_ids):
            return False
    elif scope.resource_types is not None or scope.resource_ids is not None:
        return False
    return True


def validate_authority_chain(
    chain: tuple[AuthorityGrant, ...],
    intent: ActionIntent,
    verifier: SignatureVerifier,
    *,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    if not chain:
        raise AuthorityError("authority.chain_missing")
    root = chain[0]
    if root.parent_grant_id is not None or root.depth != 0:
        raise AuthorityError("authority.root_invalid")
    previous: AuthorityGrant | None = None
    for grant in chain:
        verify_authority_grant_signature(grant, verifier)
        if now < grant.issued_at or now >= grant.expires_at:
            raise AuthorityError("authority.grant_expired")
        if previous is not None:
            if grant.parent_grant_id != previous.grant_id:
                raise AuthorityError("authority.chain_parent_mismatch")
            if grant.depth != previous.depth + 1:
                raise AuthorityError("authority.chain_depth_mismatch")
            if grant.subject.tenant_id != previous.subject.tenant_id:
                raise AuthorityError("authority.chain_tenant_mismatch")
            if not previous.scope.delegable:
                raise AuthorityError("authority.parent_not_delegable")
            if grant.depth > previous.scope.maximum_delegation_depth:
                raise AuthorityError("authority.delegation_depth_exceeded")
            if not scope_is_attenuated(grant.scope, previous.scope):
                raise AuthorityError("authority.scope_amplification")
            if grant.expires_at > previous.expires_at:
                raise AuthorityError("authority.child_outlives_parent")
        previous = grant
    leaf = chain[-1]
    if leaf.subject != intent.principal:
        raise AuthorityError("authority.subject_mismatch")
    if not scope_allows_intent(leaf.scope, intent):
        raise AuthorityError("authority.scope_denied")
