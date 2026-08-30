from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from agentguard.adapters.crypto import decode_signature, encode_signature
from agentguard.domain import (
    ActionIntent,
    FieldIntegrityBinding,
    FieldProvenanceStatement,
    FieldReleaseReceipt,
    FieldReleaseType,
    PolicyRule,
    ProvenanceLabel,
)
from agentguard.domain.policy import FieldIntegrityConstraint
from agentguard.ports import SignatureVerifier, Signer

from .canonical import canonical_bytes, digest

MAX_FIELD_PROVENANCE_STATEMENTS = 64
MAX_FIELD_RELEASES = 32
MAX_LINEAGE_DEPTH = 16
MAX_PARENT_FAN_IN = 16
MAX_PROVENANCE_TTL_SECONDS = 3600
MAX_RELEASE_TTL_SECONDS = 900


class FieldIntegrityError(ValueError):
    pass


def _unsigned(model: FieldProvenanceStatement | FieldReleaseReceipt) -> dict[str, Any]:
    data = model.model_dump(mode="python")
    data["signature"] = ""
    return data


def resolve_field_value(document: Any, pointer: str) -> Any:
    if not pointer.startswith("/"):
        raise FieldIntegrityError("field_integrity.pointer_invalid")
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise FieldIntegrityError("field_integrity.field_missing")
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
            except ValueError as exc:
                raise FieldIntegrityError("field_integrity.pointer_invalid") from exc
            if index < 0 or index >= len(current):
                raise FieldIntegrityError("field_integrity.field_missing")
            current = current[index]
        else:
            raise FieldIntegrityError("field_integrity.field_missing")
    return current


def issue_field_provenance_statement(
    *,
    request_id: str,
    trace_id: str,
    tenant_id: str,
    field_path: str,
    value: Any,
    semantic_type: str,
    labels: frozenset[ProvenanceLabel],
    signer: Signer,
    parent_statement_ids: tuple[str, ...] = (),
    transformation: str | None = None,
    now: datetime | None = None,
    ttl_seconds: int = 300,
) -> FieldProvenanceStatement:
    now = now or datetime.now(UTC)
    if ttl_seconds < 1 or ttl_seconds > MAX_PROVENANCE_TTL_SECONDS:
        raise FieldIntegrityError("field_integrity.provenance_ttl_invalid")
    statement = FieldProvenanceStatement(
        statement_id="fps_" + uuid4().hex,
        request_id=request_id,
        trace_id=trace_id,
        tenant_id=tenant_id,
        field_path=field_path,
        value_digest=digest(value),
        semantic_type=semantic_type,
        labels=labels,
        parent_statement_ids=parent_statement_ids,
        transformation=transformation,
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        key_id=signer.key_id,
        signature="",
    )
    signature = encode_signature(signer.sign(canonical_bytes(_unsigned(statement))))
    return statement.model_copy(update={"signature": signature})


def issue_field_release(
    intent: ActionIntent,
    statement: FieldProvenanceStatement,
    *,
    release_type: FieldReleaseType,
    reason: str,
    signer: Signer,
    now: datetime | None = None,
    ttl_seconds: int = 120,
) -> FieldReleaseReceipt:
    now = now or datetime.now(UTC)
    if ttl_seconds < 1 or ttl_seconds > MAX_RELEASE_TTL_SECONDS:
        raise FieldIntegrityError("field_integrity.release_ttl_invalid")
    if statement.request_id != intent.request_id or statement.trace_id != intent.trace_id:
        raise FieldIntegrityError("field_integrity.release_request_binding_mismatch")
    release = FieldReleaseReceipt(
        release_id="rel_" + uuid4().hex,
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        tenant_id=intent.principal.tenant_id,
        principal_digest=digest(intent.principal),
        subject_digest=digest(intent.subject) if intent.subject else None,
        action_digest=digest(intent.action),
        resource_digest=digest(intent.resource) if intent.resource else None,
        field_path=statement.field_path,
        value_digest=statement.value_digest,
        provenance_statement_digest=digest(statement),
        semantic_type=statement.semantic_type,
        release_type=release_type,
        reason=reason,
        issued_at=now,
        expires_at=min(now + timedelta(seconds=ttl_seconds), statement.expires_at),
        key_id=signer.key_id,
        signature="",
    )
    if release.expires_at <= now:
        raise FieldIntegrityError("field_integrity.release_expired")
    signature = encode_signature(signer.sign(canonical_bytes(_unsigned(release))))
    return release.model_copy(update={"signature": signature})


def _verify_signed_artifact(
    model: FieldProvenanceStatement | FieldReleaseReceipt,
    verifier: SignatureVerifier,
    *,
    error_code: str,
) -> None:
    try:
        signature = decode_signature(model.signature)
    except ValueError as exc:
        raise FieldIntegrityError(error_code) from exc
    if not verifier.verify(model.key_id, canonical_bytes(_unsigned(model)), signature):
        raise FieldIntegrityError(error_code)


def _aggregate_constraints(
    matched_rules: tuple[PolicyRule, ...],
) -> tuple[FieldIntegrityConstraint, ...]:
    by_path: dict[str, list[FieldIntegrityConstraint]] = {}
    for rule in matched_rules:
        for constraint in rule.field_integrity:
            by_path.setdefault(constraint.field_path, []).append(constraint)
    aggregated: list[FieldIntegrityConstraint] = []
    for path in sorted(by_path):
        constraints = by_path[path]
        semantic_types = {item.semantic_type for item in constraints}
        if len(semantic_types) != 1:
            raise FieldIntegrityError("field_integrity.policy_conflict.semantic_type")
        required = any(item.provenance_required for item in constraints)
        denied = frozenset().union(*(item.denied_labels for item in constraints))
        allowed_sets = [item.allowed_labels for item in constraints if item.allowed_labels]
        if allowed_sets:
            allowed = frozenset.intersection(*allowed_sets)
            if not allowed:
                raise FieldIntegrityError("field_integrity.policy_conflict.allowed_labels")
        else:
            allowed = frozenset()
        # Release permission is an attenuating capability. Every simultaneously matched
        # constraint must permit the same release type; an empty set on any constraint
        # means that constraint permits no exception at all.
        releases: frozenset[FieldReleaseType]
        if any(not item.permitted_release_types for item in constraints):
            releases = frozenset()
        else:
            release_sets = [item.permitted_release_types for item in constraints]
            releases = frozenset.intersection(*release_sets)
            if not releases:
                raise FieldIntegrityError("field_integrity.policy_conflict.release_types")
        aggregated.append(
            FieldIntegrityConstraint(
                field_path=path,
                semantic_type=next(iter(semantic_types)),
                allowed_labels=allowed,
                denied_labels=denied,
                provenance_required=required,
                permitted_release_types=releases,
            )
        )
    return tuple(aggregated)


def validate_field_integrity(
    intent: ActionIntent,
    matched_rules: tuple[PolicyRule, ...],
    provenance_verifier: SignatureVerifier,
    release_verifier: SignatureVerifier,
    *,
    now: datetime | None = None,
) -> FieldIntegrityBinding:
    now = now or datetime.now(UTC)
    if len(intent.field_provenance) > MAX_FIELD_PROVENANCE_STATEMENTS:
        raise FieldIntegrityError("field_integrity.provenance_limit_exceeded")
    if len(intent.field_releases) > MAX_FIELD_RELEASES:
        raise FieldIntegrityError("field_integrity.release_limit_exceeded")

    constraints = _aggregate_constraints(matched_rules)
    if not constraints:
        return FieldIntegrityBinding(
            integrity_digest=digest({"constraints": [], "statements": []}),
            release_set_digest=digest([]),
            expires_at=None,
            release_ids=(),
            labels=frozenset(),
        )

    statements = {statement.statement_id: statement for statement in intent.field_provenance}
    if len(statements) != len(intent.field_provenance):
        raise FieldIntegrityError("field_integrity.statement_id_conflict")

    for statement in intent.field_provenance:
        if len(statement.parent_statement_ids) > MAX_PARENT_FAN_IN:
            raise FieldIntegrityError("field_integrity.parent_fan_in_exceeded")
        _verify_signed_artifact(
            statement,
            provenance_verifier,
            error_code="field_integrity.provenance_signature_invalid",
        )
        if statement.request_id != intent.request_id or statement.trace_id != intent.trace_id:
            raise FieldIntegrityError("field_integrity.provenance_request_binding_mismatch")
        if statement.tenant_id != intent.principal.tenant_id:
            raise FieldIntegrityError("field_integrity.provenance_tenant_mismatch")
        if statement.issued_at > now:
            raise FieldIntegrityError("field_integrity.provenance_not_yet_valid")
        if statement.expires_at <= now:
            raise FieldIntegrityError("field_integrity.provenance_expired")
        if (
            statement.expires_at - statement.issued_at
        ).total_seconds() > MAX_PROVENANCE_TTL_SECONDS:
            raise FieldIntegrityError("field_integrity.provenance_ttl_invalid")

    memo_labels: dict[str, frozenset[ProvenanceLabel]] = {}
    visiting: set[str] = set()

    def inherited_labels(statement_id: str, depth: int = 0) -> frozenset[ProvenanceLabel]:
        if depth > MAX_LINEAGE_DEPTH:
            raise FieldIntegrityError("field_integrity.lineage_depth_exceeded")
        if statement_id in memo_labels:
            return memo_labels[statement_id]
        if statement_id in visiting:
            raise FieldIntegrityError("field_integrity.lineage_cycle")
        statement = statements.get(statement_id)
        if statement is None:
            raise FieldIntegrityError("field_integrity.lineage_parent_missing")
        visiting.add(statement_id)
        inherited: frozenset[ProvenanceLabel] = frozenset()
        for parent_id in statement.parent_statement_ids:
            inherited = inherited | inherited_labels(parent_id, depth + 1)
        visiting.remove(statement_id)
        if not inherited.issubset(statement.labels):
            raise FieldIntegrityError("field_integrity.label_stripping")
        memo_labels[statement_id] = statement.labels
        return statement.labels

    for statement_id in statements:
        inherited_labels(statement_id)

    for release in intent.field_releases:
        _verify_signed_artifact(
            release,
            release_verifier,
            error_code="field_integrity.release_signature_invalid",
        )
        if (release.expires_at - release.issued_at).total_seconds() > MAX_RELEASE_TTL_SECONDS:
            raise FieldIntegrityError("field_integrity.release_ttl_invalid")
        if release.issued_at > now:
            raise FieldIntegrityError("field_integrity.release_not_yet_valid")
        if release.expires_at <= now:
            raise FieldIntegrityError("field_integrity.release_expired")
        if (
            release.request_id != intent.request_id
            or release.trace_id != intent.trace_id
            or release.tenant_id != intent.principal.tenant_id
            or release.principal_digest != digest(intent.principal)
            or release.subject_digest != (digest(intent.subject) if intent.subject else None)
            or release.action_digest != digest(intent.action)
            or release.resource_digest != (digest(intent.resource) if intent.resource else None)
        ):
            raise FieldIntegrityError("field_integrity.release_context_binding_mismatch")

    used_releases: list[FieldReleaseReceipt] = []
    selected_statements: list[FieldProvenanceStatement] = []
    all_labels: frozenset[ProvenanceLabel] = frozenset()

    for constraint in constraints:
        value = resolve_field_value(intent.arguments, constraint.field_path)
        value_digest = digest(value)
        candidates = [
            statement
            for statement in intent.field_provenance
            if statement.field_path == constraint.field_path
            and statement.value_digest == value_digest
            and statement.semantic_type == constraint.semantic_type
        ]
        if not candidates:
            if constraint.provenance_required:
                raise FieldIntegrityError("field_integrity.provenance_missing")
            continue
        candidate_ids = {candidate.statement_id for candidate in candidates}
        ancestor_ids = {
            parent_id
            for candidate in candidates
            for parent_id in candidate.parent_statement_ids
            if parent_id in candidate_ids
        }
        terminal = [
            candidate for candidate in candidates if candidate.statement_id not in ancestor_ids
        ]
        if len(terminal) != 1:
            raise FieldIntegrityError("field_integrity.provenance_ambiguous")
        statement = terminal[0]
        selected_statements.append(statement)
        all_labels = all_labels | statement.labels

        violates_denied = bool(statement.labels & constraint.denied_labels)
        violates_allowed = bool(constraint.allowed_labels) and not statement.labels.issubset(
            constraint.allowed_labels
        )
        if not (violates_denied or violates_allowed):
            continue

        matching_releases = [
            release
            for release in intent.field_releases
            if release.field_path == constraint.field_path
            and release.value_digest == value_digest
            and release.semantic_type == constraint.semantic_type
            and release.provenance_statement_digest == digest(statement)
            and release.release_type in constraint.permitted_release_types
        ]
        if len(matching_releases) != 1:
            raise FieldIntegrityError("field_integrity.release_required")
        used_releases.append(matching_releases[0])

    release_ids = tuple(sorted({release.release_id for release in used_releases}))
    if len(release_ids) != len(used_releases):
        raise FieldIntegrityError("field_integrity.release_reused_within_intent")
    expiry_candidates = [statement.expires_at for statement in selected_statements] + [
        release.expires_at for release in used_releases
    ]
    binding_payload = {
        "constraints": constraints,
        "selected_statement_digests": sorted(
            digest(statement) for statement in selected_statements
        ),
        "release_digests": sorted(digest(release) for release in used_releases),
        "request_id": intent.request_id,
        "trace_id": intent.trace_id,
        "tenant_id": intent.principal.tenant_id,
    }
    return FieldIntegrityBinding(
        integrity_digest=digest(binding_payload),
        release_set_digest=digest(sorted(digest(release) for release in used_releases)),
        expires_at=min(expiry_candidates) if expiry_candidates else None,
        release_ids=release_ids,
        labels=all_labels,
    )
