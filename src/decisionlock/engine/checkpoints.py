from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from decisionlock.adapters.crypto import decode_signature, encode_signature
from decisionlock.domain import AuditCheckpoint
from decisionlock.ports import SignatureVerifier, Signer

from .canonical import canonical_bytes


class AuditCheckpointError(ValueError):
    pass


MAX_CHECKPOINT_CLOCK_SKEW_SECONDS = 300


def _unsigned(checkpoint: AuditCheckpoint) -> dict[str, Any]:
    data = checkpoint.model_dump(mode="python")
    data["signature"] = ""
    return data


def issue_audit_checkpoint(
    *,
    ledger_id: str,
    event_count: int,
    head_hash: str,
    signer: Signer,
    now: datetime | None = None,
) -> AuditCheckpoint:
    now = now or datetime.now(UTC)
    checkpoint = AuditCheckpoint(
        checkpoint_id="acp_" + uuid4().hex,
        ledger_id=ledger_id,
        event_count=event_count,
        head_hash=head_hash,
        issued_at=now,
        key_id=signer.key_id,
        signature="",
    )
    signature = signer.sign(canonical_bytes(_unsigned(checkpoint)))
    return checkpoint.model_copy(update={"signature": encode_signature(signature)})


def verify_audit_checkpoint_signature(
    checkpoint: AuditCheckpoint,
    verifier: SignatureVerifier,
    *,
    now: datetime | None = None,
    maximum_clock_skew_seconds: int = MAX_CHECKPOINT_CLOCK_SKEW_SECONDS,
) -> None:
    now = now or datetime.now(UTC)
    if maximum_clock_skew_seconds < 0 or maximum_clock_skew_seconds > 3600:
        raise AuditCheckpointError("checkpoint.clock_skew_invalid")
    if now.tzinfo is None or now.utcoffset() is None:
        raise AuditCheckpointError("checkpoint.timestamp_invalid")
    if checkpoint.issued_at > now + timedelta(seconds=maximum_clock_skew_seconds):
        raise AuditCheckpointError("checkpoint.not_yet_valid")
    try:
        signature = decode_signature(checkpoint.signature)
    except ValueError as exc:
        raise AuditCheckpointError("checkpoint.signature_invalid") from exc
    if not verifier.verify(
        checkpoint.key_id,
        canonical_bytes(_unsigned(checkpoint)),
        signature,
    ):
        raise AuditCheckpointError("checkpoint.signature_invalid")
