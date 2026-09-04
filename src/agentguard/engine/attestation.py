from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from uuid import uuid4

from agentguard.adapters.crypto import decode_signature, encode_signature
from agentguard.domain import (
    AttestationMetadata,
    ExecutionAttestation,
    ExecutionAttestationPayload,
    ExecutionRecord,
    ExecutionResolution,
)
from agentguard.engine.canonical import canonical_bytes, digest
from agentguard.ports import SignatureVerifier, Signer


class AttestationVerificationError(ValueError):
    pass


def issue_execution_attestation(
    execution: ExecutionRecord,
    signer: Signer,
    *,
    policy_digest: str | None = None,
    resolution: ExecutionResolution | None = None,
    previous_attestation_digest: str | None = None,
    now: datetime | None = None,
) -> ExecutionAttestation:
    now = now or datetime.now(UTC)
    payload = ExecutionAttestationPayload(
        attestation_id="att_" + uuid4().hex,
        execution_id=execution.execution_id,
        decision_id=execution.decision_id,
        trace_id=execution.trace_id,
        request_id=execution.request_id,
        intent_digest=execution.intent_digest,
        authority_digest=execution.authority_digest,
        policy_digest=policy_digest,
        field_integrity_digest=execution.field_integrity_digest,
        field_release_set_digest=execution.field_release_set_digest,
        field_integrity_expires_at=execution.field_integrity_expires_at,
        causal_digest=execution.causal_digest,
        causal_depth=execution.causal_depth,
        prepared_id=execution.prepared_id,
        execution_state=execution.state,
        reserved_at=execution.reserved_at,
        dispatching_at=execution.dispatching_at,
        completed_at=execution.completed_at,
        provider_status=execution.provider_status,
        result_digest=execution.result_digest,
        error_code=execution.error_code,
        resolution=resolution,
        previous_attestation_digest=previous_attestation_digest,
        issued_at=now,
    )
    payload_digest = digest(payload)
    signature = encode_signature(signer.sign(canonical_bytes(payload)))
    return ExecutionAttestation(
        payload=payload,
        payload_digest=payload_digest,
        signer_key_id=signer.key_id,
        signature=signature,
    )


def verify_execution_attestation(
    attestation: ExecutionAttestation,
    verifier: SignatureVerifier,
) -> None:
    actual_digest = digest(attestation.payload)
    if actual_digest != attestation.payload_digest:
        raise AttestationVerificationError("attestation.payload_digest_mismatch")
    try:
        signature = decode_signature(attestation.signature)
    except ValueError as exc:
        raise AttestationVerificationError("attestation.signature_invalid") from exc
    if not verifier.verify(
        attestation.signer_key_id,
        canonical_bytes(attestation.payload),
        signature,
    ):
        raise AttestationVerificationError("attestation.signature_invalid")
    if attestation.payload.resolution is not None:
        if attestation.payload.resolution.execution_id != attestation.payload.execution_id:
            raise AttestationVerificationError("attestation.resolution_execution_mismatch")
        if attestation.payload.resolution.original_state != attestation.payload.execution_state:
            raise AttestationVerificationError("attestation.resolution_state_mismatch")


def attestation_metadata(attestation: ExecutionAttestation) -> AttestationMetadata:
    return AttestationMetadata(
        attestation_id=attestation.payload.attestation_id,
        execution_id=attestation.payload.execution_id,
        payload_digest=attestation.payload_digest,
        signature_digest="sha256:" + sha256(attestation.signature.encode("ascii")).hexdigest(),
        signer_key_id=attestation.signer_key_id,
        previous_attestation_digest=attestation.payload.previous_attestation_digest,
        issued_at=attestation.payload.issued_at,
    )


def verify_attestation_chain(
    attestations: tuple[ExecutionAttestation, ...],
    verifier: SignatureVerifier,
) -> None:
    if not attestations:
        raise AttestationVerificationError("attestation.chain_empty")
    previous_digest: str | None = None
    execution_id = attestations[0].payload.execution_id
    for index, attestation in enumerate(attestations):
        verify_execution_attestation(attestation, verifier)
        if attestation.payload.execution_id != execution_id:
            raise AttestationVerificationError("attestation.chain_execution_mismatch")
        if index == 0:
            if attestation.payload.previous_attestation_digest is not None:
                raise AttestationVerificationError("attestation.chain_unexpected_parent")
        elif attestation.payload.previous_attestation_digest != previous_digest:
            raise AttestationVerificationError("attestation.chain_parent_mismatch")
        previous_digest = attestation.payload_digest
