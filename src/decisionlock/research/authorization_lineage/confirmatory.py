from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Protocol, Sequence, cast

from .models import (
    AnalyzedTrial,
    Arm,
    ProviderStratum,
    Schedule,
    TrialObservation,
    TrialSpec,
)
from .provider import IndependentEffectOracleReader
from .trace import HarnessInvalidReason, invalid_observation, validate_trace

_ZERO_HASH = "0" * 64
_UNSAFE_SUCCESSOR_SCHEDULES = {
    Schedule.S7,
    Schedule.S8,
    Schedule.S9,
    Schedule.S10,
    Schedule.S11,
}


class ConfirmatoryEvidenceError(RuntimeError):
    pass


class TrialRunner(Protocol):
    root: Path

    def run(self, spec: TrialSpec) -> TrialObservation: ...


@dataclass(frozen=True)
class TrialExecutionEvidence:
    spec: TrialSpec
    observation: TrialObservation
    preexisting_entries: tuple[str, ...]
    external_machine_failure: str | None
    evidence_sha256: dict[str, str]


def _canonical_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode())


def _require_sha256(value: str, name: str) -> None:
    if len(value) != 64:
        raise ConfirmatoryEvidenceError(f"{name} must be an exact lowercase SHA-256")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise ConfirmatoryEvidenceError(f"{name} must be an exact lowercase SHA-256") from exc
    if f"{parsed:064x}" != value:
        raise ConfirmatoryEvidenceError(f"{name} must be an exact lowercase SHA-256")


def _object_dict(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfirmatoryEvidenceError(f"{name} must be an object")
    return cast(dict[str, object], value)


def _string(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ConfirmatoryEvidenceError(f"{name} must be a string")
    return value


def _integer(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfirmatoryEvidenceError(f"{name} must be an integer")
    return value


def _number(value: object, name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfirmatoryEvidenceError(f"{name} must be numeric")
    return float(value)


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfirmatoryEvidenceError(f"{name} must be boolean")
    return value


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    return _string(value, name)


def observation_payload(observation: TrialObservation) -> dict[str, object]:
    return {
        "trial_id": observation.trial_id,
        "arm": observation.arm.value,
        "provider": observation.provider.value,
        "schedule": observation.schedule.value,
        "replicate": observation.replicate,
        "block_seed": observation.block_seed,
        "alpha": observation.alpha,
        "effect_key": observation.effect_key,
        "root_or_slot_allocations": observation.root_or_slot_allocations,
        "independent_live_slots_max": observation.independent_live_slots_max,
        "receipts_or_tickets": observation.receipts_or_tickets,
        "credentials": observation.credentials,
        "provider_sends": observation.provider_sends,
        "attempts": observation.attempts,
        "successor_admitted_while_predecessor_potentially_effectful": (
            observation.successor_admitted_while_predecessor_potentially_effectful
        ),
        "stale_reconciler_commit_accepted": observation.stale_reconciler_commit_accepted,
        "legitimate_completion": observation.legitimate_completion,
        "unresolved": observation.unresolved,
        "operator_interventions": observation.operator_interventions,
        "reconciliation_calls": observation.reconciliation_calls,
        "slot_hold_seconds": observation.slot_hold_seconds,
        "duration_seconds": observation.duration_seconds,
        "harness_invalid": observation.harness_invalid,
        "harness_invalid_reason": observation.harness_invalid_reason,
    }


def observation_from_payload(value: object) -> TrialObservation:
    raw = _object_dict(value, "observation")
    try:
        arm = Arm(_string(raw.get("arm"), "observation.arm"))
        provider = ProviderStratum(_string(raw.get("provider"), "observation.provider"))
        schedule = Schedule(_string(raw.get("schedule"), "observation.schedule"))
    except ValueError as exc:
        raise ConfirmatoryEvidenceError("observation enum value is invalid") from exc
    return TrialObservation(
        trial_id=_string(raw.get("trial_id"), "observation.trial_id"),
        arm=arm,
        provider=provider,
        schedule=schedule,
        replicate=_integer(raw.get("replicate"), "observation.replicate"),
        block_seed=_string(raw.get("block_seed"), "observation.block_seed"),
        alpha=_string(raw.get("alpha"), "observation.alpha"),
        effect_key=_string(raw.get("effect_key"), "observation.effect_key"),
        root_or_slot_allocations=_integer(
            raw.get("root_or_slot_allocations"), "observation.root_or_slot_allocations"
        ),
        independent_live_slots_max=_integer(
            raw.get("independent_live_slots_max"), "observation.independent_live_slots_max"
        ),
        receipts_or_tickets=_integer(
            raw.get("receipts_or_tickets"), "observation.receipts_or_tickets"
        ),
        credentials=_integer(raw.get("credentials"), "observation.credentials"),
        provider_sends=_integer(raw.get("provider_sends"), "observation.provider_sends"),
        attempts=_integer(raw.get("attempts"), "observation.attempts"),
        successor_admitted_while_predecessor_potentially_effectful=_boolean(
            raw.get("successor_admitted_while_predecessor_potentially_effectful"),
            "observation.successor_admitted_while_predecessor_potentially_effectful",
        ),
        stale_reconciler_commit_accepted=_boolean(
            raw.get("stale_reconciler_commit_accepted"),
            "observation.stale_reconciler_commit_accepted",
        ),
        legitimate_completion=_boolean(
            raw.get("legitimate_completion"), "observation.legitimate_completion"
        ),
        unresolved=_boolean(raw.get("unresolved"), "observation.unresolved"),
        operator_interventions=_integer(
            raw.get("operator_interventions"), "observation.operator_interventions"
        ),
        reconciliation_calls=_integer(
            raw.get("reconciliation_calls"), "observation.reconciliation_calls"
        ),
        slot_hold_seconds=_number(raw.get("slot_hold_seconds"), "observation.slot_hold_seconds"),
        duration_seconds=_number(raw.get("duration_seconds"), "observation.duration_seconds"),
        harness_invalid=_boolean(raw.get("harness_invalid"), "observation.harness_invalid"),
        harness_invalid_reason=_optional_string(
            raw.get("harness_invalid_reason"), "observation.harness_invalid_reason"
        ),
    )


def _block_key(spec: TrialSpec) -> tuple[ProviderStratum, Schedule, int, str]:
    return spec.provider, spec.schedule, spec.replicate, spec.block_seed


def _block_id(spec: TrialSpec) -> str:
    return "|".join(
        (
            spec.provider.value,
            spec.schedule.value,
            str(spec.replicate),
            spec.block_seed,
        )
    )


def block_sequence_filename(spec: TrialSpec) -> str:
    return (
        f"{spec.provider.value}-{spec.schedule.value}-{spec.replicate:03d}-"
        f"{spec.block_seed[:16]}.jsonl"
    )


def _validated_block(block: Sequence[TrialSpec]) -> tuple[TrialSpec, TrialSpec, TrialSpec]:
    if len(block) != 3:
        raise ConfirmatoryEvidenceError("confirmatory block must contain exactly three trials")
    if len({_block_key(spec) for spec in block}) != 1:
        raise ConfirmatoryEvidenceError("confirmatory block identity is inconsistent")
    ordered = sorted(block, key=lambda spec: spec.execution_order)
    if [spec.execution_order for spec in ordered] != [0, 1, 2]:
        raise ConfirmatoryEvidenceError("confirmatory block execution order must be exactly 0,1,2")
    if {spec.arm for spec in ordered} != set(Arm):
        raise ConfirmatoryEvidenceError(
            "confirmatory block must contain A0, A1, and B4 exactly once"
        )
    return ordered[0], ordered[1], ordered[2]


def _evidence_hashes(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    hashes: dict[str, str] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        hashes[str(path.relative_to(root))] = _sha256_bytes(path.read_bytes())
    return hashes


class _SequenceWriter:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = path.open("x", encoding="utf-8")
        self._sequence = 0
        self._previous_hash = _ZERO_HASH

    def append(self, event: str, **detail: object) -> None:
        self._sequence += 1
        record: dict[str, object] = {
            "sequence": self._sequence,
            "previous_hash": self._previous_hash,
            "event": event,
            **detail,
        }
        record_hash = _sha256_text(_canonical_json(record))
        record["record_hash"] = record_hash
        self._handle.write(_canonical_json(record) + "\n")
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._previous_hash = record_hash

    def close(self) -> None:
        self._handle.close()


def _preexisting_entries(trial_root: Path) -> tuple[str, ...]:
    if not trial_root.exists():
        return ()
    return tuple(sorted(str(path.relative_to(trial_root)) for path in trial_root.rglob("*")))


def run_confirmatory_block(
    block: Sequence[TrialSpec],
    *,
    runner: TrialRunner,
    expected_manifest_sha256: str,
    sequence_root: Path,
) -> tuple[TrialObservation, TrialObservation, TrialObservation]:
    """Execute one frozen block strictly in execution_order and retain hash-chained evidence."""

    _require_sha256(expected_manifest_sha256, "expected_manifest_sha256")
    ordered = _validated_block(block)
    sequence_path = sequence_root / block_sequence_filename(ordered[0])
    writer = _SequenceWriter(sequence_path)
    block_id = _block_id(ordered[0])
    writer.append(
        "block.start",
        block_id=block_id,
        manifest_sha256=expected_manifest_sha256,
        block_seed=ordered[0].block_seed,
    )
    observations: list[TrialObservation] = []
    try:
        for spec in ordered:
            trial_root = runner.root / spec.trial_id
            preexisting = _preexisting_entries(trial_root)
            writer.append(
                "trial.start",
                block_id=block_id,
                manifest_sha256=expected_manifest_sha256,
                trial_id=spec.trial_id,
                block_seed=spec.block_seed,
                execution_order=spec.execution_order,
                preexisting_entries=list(preexisting),
            )
            external_failure: str | None = None
            try:
                observation = runner.run(spec)
            except (OSError, SystemError, MemoryError) as exc:
                external_failure = type(exc).__name__
                observation = invalid_observation(
                    spec,
                    HarnessInvalidReason.EXTERNAL_MACHINE_FAILURE,
                    detail=external_failure,
                )
            evidence = _evidence_hashes(trial_root)
            writer.append(
                "trial.finish",
                block_id=block_id,
                manifest_sha256=expected_manifest_sha256,
                trial_id=spec.trial_id,
                block_seed=spec.block_seed,
                execution_order=spec.execution_order,
                observation=observation_payload(observation),
                evidence_sha256=evidence,
                external_machine_failure=external_failure,
            )
            observations.append(observation)
        writer.append(
            "block.finish",
            block_id=block_id,
            manifest_sha256=expected_manifest_sha256,
            block_seed=ordered[0].block_seed,
        )
    finally:
        writer.close()
    return observations[0], observations[1], observations[2]


def _read_sequence(path: Path) -> list[dict[str, object]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfirmatoryEvidenceError(f"execution sequence is unreadable: {path}") from exc
    if not lines:
        raise ConfirmatoryEvidenceError("execution sequence is empty")
    records: list[dict[str, object]] = []
    previous_hash = _ZERO_HASH
    for expected_sequence, line in enumerate(lines, start=1):
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ConfirmatoryEvidenceError("execution sequence contains invalid JSON") from exc
        record = _object_dict(decoded, "execution sequence record")
        if _integer(record.get("sequence"), "execution sequence.sequence") != expected_sequence:
            raise ConfirmatoryEvidenceError("execution sequence number mismatch")
        if (
            _string(record.get("previous_hash"), "execution sequence.previous_hash")
            != previous_hash
        ):
            raise ConfirmatoryEvidenceError("execution sequence hash-chain predecessor mismatch")
        recorded_hash = _string(record.get("record_hash"), "execution sequence.record_hash")
        unsigned = dict(record)
        del unsigned["record_hash"]
        actual_hash = _sha256_text(_canonical_json(unsigned))
        if recorded_hash != actual_hash:
            raise ConfirmatoryEvidenceError("execution sequence record hash mismatch")
        previous_hash = recorded_hash
        records.append(record)
    return records


def validate_block_records(
    records: Sequence[dict[str, object]],
    block: Sequence[TrialSpec],
    *,
    expected_manifest_sha256: str,
) -> tuple[TrialExecutionEvidence, TrialExecutionEvidence, TrialExecutionEvidence]:
    """Validate the logical execution sequence after hash-chain verification."""

    _require_sha256(expected_manifest_sha256, "expected_manifest_sha256")
    ordered = _validated_block(block)
    expected_block_id = _block_id(ordered[0])
    if len(records) != 8:
        raise ConfirmatoryEvidenceError(
            "confirmatory block sequence must contain exactly 8 records"
        )
    if _string(records[0].get("event"), "block.start.event") != "block.start":
        raise ConfirmatoryEvidenceError("confirmatory block sequence is missing block.start")
    if _string(records[-1].get("event"), "block.finish.event") != "block.finish":
        raise ConfirmatoryEvidenceError("confirmatory block sequence is missing block.finish")
    for boundary in (records[0], records[-1]):
        if _string(boundary.get("block_id"), "block.block_id") != expected_block_id:
            raise ConfirmatoryEvidenceError("execution sequence block identity mismatch")
        if (
            _string(boundary.get("manifest_sha256"), "block.manifest_sha256")
            != expected_manifest_sha256
        ):
            raise ConfirmatoryEvidenceError("execution sequence manifest identity mismatch")
        if _string(boundary.get("block_seed"), "block.block_seed") != ordered[0].block_seed:
            raise ConfirmatoryEvidenceError("execution sequence block seed mismatch")

    evidence: list[TrialExecutionEvidence] = []
    for index, spec in enumerate(ordered):
        start = records[1 + index * 2]
        finish = records[2 + index * 2]
        if _string(start.get("event"), "trial.start.event") != "trial.start":
            raise ConfirmatoryEvidenceError(
                "execution sequence skipped or duplicated a trial.start"
            )
        if _string(finish.get("event"), "trial.finish.event") != "trial.finish":
            raise ConfirmatoryEvidenceError(
                "execution sequence skipped or duplicated a trial.finish"
            )
        for record in (start, finish):
            if _string(record.get("block_id"), "trial.block_id") != expected_block_id:
                raise ConfirmatoryEvidenceError("runtime trial block identity mismatch")
            if _string(record.get("trial_id"), "trial.trial_id") != spec.trial_id:
                raise ConfirmatoryEvidenceError(
                    "runtime trial order does not match frozen execution_order"
                )
            if (
                _integer(record.get("execution_order"), "trial.execution_order")
                != spec.execution_order
            ):
                raise ConfirmatoryEvidenceError(
                    "runtime execution_order does not match frozen manifest"
                )
            if _string(record.get("block_seed"), "trial.block_seed") != spec.block_seed:
                raise ConfirmatoryEvidenceError("runtime trial block_seed mismatch")
            if (
                _string(record.get("manifest_sha256"), "trial.manifest_sha256")
                != expected_manifest_sha256
            ):
                raise ConfirmatoryEvidenceError("runtime trial manifest identity mismatch")
        preexisting_raw = start.get("preexisting_entries")
        if not isinstance(preexisting_raw, list) or not all(
            isinstance(item, str) for item in preexisting_raw
        ):
            raise ConfirmatoryEvidenceError("trial preexisting_entries evidence is invalid")
        observation = observation_from_payload(finish.get("observation"))
        if (
            observation.trial_id != spec.trial_id
            or observation.arm != spec.arm
            or observation.provider != spec.provider
            or observation.schedule != spec.schedule
            or observation.replicate != spec.replicate
            or observation.block_seed != spec.block_seed
            or observation.alpha != spec.alpha
            or observation.effect_key != spec.effect_key
        ):
            raise ConfirmatoryEvidenceError(
                "retained observation does not match frozen trial identity"
            )
        hashes_raw = _object_dict(finish.get("evidence_sha256"), "trial.evidence_sha256")
        hashes: dict[str, str] = {}
        for name, digest in hashes_raw.items():
            hashes[name] = _string(digest, f"trial.evidence_sha256.{name}")
        evidence.append(
            TrialExecutionEvidence(
                spec=spec,
                observation=observation,
                preexisting_entries=tuple(cast(list[str], preexisting_raw)),
                external_machine_failure=_optional_string(
                    finish.get("external_machine_failure"), "trial.external_machine_failure"
                ),
                evidence_sha256=hashes,
            )
        )
    return evidence[0], evidence[1], evidence[2]


def validate_block_execution(
    block: Sequence[TrialSpec],
    *,
    evidence_root: Path,
    expected_manifest_sha256: str,
    sequence_root: Path,
) -> tuple[TrialExecutionEvidence, TrialExecutionEvidence, TrialExecutionEvidence]:
    ordered = _validated_block(block)
    sequence_path = sequence_root / block_sequence_filename(ordered[0])
    records = _read_sequence(sequence_path)
    validated = validate_block_records(
        records,
        ordered,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    for trial in validated:
        trial_root = evidence_root / trial.spec.trial_id
        actual_hashes = _evidence_hashes(trial_root)
        if actual_hashes != trial.evidence_sha256:
            raise ConfirmatoryEvidenceError(
                f"retained trial evidence changed after execution: {trial.spec.trial_id}"
            )
    return validated


def _group_blocks(manifest: Sequence[TrialSpec]) -> list[tuple[TrialSpec, TrialSpec, TrialSpec]]:
    grouped: dict[tuple[ProviderStratum, Schedule, int, str], list[TrialSpec]] = {}
    order: list[tuple[ProviderStratum, Schedule, int, str]] = []
    for spec in manifest:
        key = _block_key(spec)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(spec)
    return [_validated_block(grouped[key]) for key in order]


def validate_execution_sequences(
    manifest: Sequence[TrialSpec],
    *,
    evidence_root: Path,
    expected_manifest_sha256: str,
    sequence_root: Path,
) -> dict[str, TrialExecutionEvidence]:
    _require_sha256(expected_manifest_sha256, "expected_manifest_sha256")
    blocks = _group_blocks(manifest)
    expected_names = {block_sequence_filename(block[0]) for block in blocks}
    actual_names = {path.name for path in sequence_root.glob("*.jsonl")}
    if actual_names != expected_names:
        raise ConfirmatoryEvidenceError(
            "confirmatory execution-sequence set does not exactly match frozen manifest blocks"
        )
    evidence: dict[str, TrialExecutionEvidence] = {}
    for block in blocks:
        for trial in validate_block_execution(
            block,
            evidence_root=evidence_root,
            expected_manifest_sha256=expected_manifest_sha256,
            sequence_root=sequence_root,
        ):
            if trial.spec.trial_id in evidence:
                raise ConfirmatoryEvidenceError("duplicate trial evidence in execution sequences")
            evidence[trial.spec.trial_id] = trial
    return evidence


def _trace_records(path: Path) -> tuple[dict[str, object], ...]:
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        decoded = json.loads(line)
        records.append(_object_dict(decoded, "trace record"))
    return tuple(records)


def _mechanically_proven_invalidation(
    execution: TrialExecutionEvidence,
    trial_root: Path,
) -> str | None:
    observation = execution.observation
    if execution.preexisting_entries:
        proven = HarnessInvalidReason.DIRTY_NAMESPACE.value
    elif execution.external_machine_failure is not None:
        proven = HarnessInvalidReason.EXTERNAL_MACHINE_FAILURE.value
    else:
        trace_path = trial_root / "trace.jsonl"
        trace_valid, _ = validate_trace(trace_path, observation.trial_id)
        if not trace_valid:
            proven = HarnessInvalidReason.TRACE_CORRUPT.value
        else:
            try:
                records = _trace_records(trace_path)
            except (OSError, json.JSONDecodeError) as exc:
                raise ConfirmatoryEvidenceError("retained trace became unreadable") from exc
            barrier_failed = any(record.get("event_type") == "barrier.failed" for record in records)
            reason_codes: set[str] = set()
            for record in records:
                if record.get("event_type") != "harness.invalid":
                    continue
                detail = record.get("detail")
                if not isinstance(detail, dict):
                    continue
                reason = detail.get("reason")
                if isinstance(reason, str):
                    reason_codes.add(reason.split(":", 1)[0])
            if HarnessInvalidReason.WRONG_RUNTIME_OR_SCHEMA.value in reason_codes:
                raise ConfirmatoryEvidenceError(
                    "runtime/schema drift is study-level fail-closed evidence, not a trial exclusion"
                )
            if HarnessInvalidReason.SCHEDULE_BARRIER_FAILURE.value in reason_codes:
                if not barrier_failed:
                    raise ConfirmatoryEvidenceError(
                        "schedule invalidation lacks retained barrier-failure evidence"
                    )
                proven = HarnessInvalidReason.SCHEDULE_BARRIER_FAILURE.value
            elif HarnessInvalidReason.ORACLE_UNAVAILABLE.value in reason_codes:
                proven = HarnessInvalidReason.ORACLE_UNAVAILABLE.value
            elif HarnessInvalidReason.DIRTY_NAMESPACE.value in reason_codes:
                raise ConfirmatoryEvidenceError(
                    "dirty-namespace invalidation lacks pre-execution coordinator evidence"
                )
            elif HarnessInvalidReason.EXTERNAL_MACHINE_FAILURE.value in reason_codes:
                raise ConfirmatoryEvidenceError(
                    "external-machine invalidation lacks coordinator failure evidence"
                )
            elif HarnessInvalidReason.TRACE_CORRUPT.value in reason_codes:
                raise ConfirmatoryEvidenceError(
                    "trace-corrupt invalidation is inconsistent with a valid retained trace"
                )
            else:
                proven = None

    observed_reason = observation.harness_invalid_reason
    if proven is None:
        if observation.harness_invalid or observed_reason is not None:
            raise ConfirmatoryEvidenceError(
                f"unsubstantiated HARNESS_INVALID metadata: {observation.trial_id}"
            )
        return None
    if not observation.harness_invalid or observed_reason is None:
        raise ConfirmatoryEvidenceError(
            f"mechanical invalidation is not reflected in retained observation: {observation.trial_id}"
        )
    if observed_reason.split(":", 1)[0] != proven:
        raise ConfirmatoryEvidenceError(
            f"HARNESS_INVALID reason does not match retained evidence: {observation.trial_id}"
        )
    return proven


def _a0_independent_opportunities(path: Path) -> int:
    if not path.exists():
        raise ConfirmatoryEvidenceError("A0 authority ledger evidence is missing")
    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM authority_grants WHERE parent_grant_id IS NULL"
        ).fetchone()
    if row is None:
        raise ConfirmatoryEvidenceError("A0 authority ledger evidence is unreadable")
    return int(row[0])


def _lineage_independent_opportunities(path: Path, alpha: str) -> int:
    if not path.exists():
        raise ConfirmatoryEvidenceError("lineage ledger evidence is missing")
    with closing(sqlite3.connect(path)) as connection:
        rows = connection.execute(
            """
            SELECT provider_stratum,idempotency_key,potentially_effectful
            FROM attempts WHERE alpha=? ORDER BY rowid
            """,
            (alpha,),
        ).fetchall()
    p1_keys: set[str] = set()
    independent = 0
    for provider_raw, idempotency_raw, potentially_effectful_raw in rows:
        if int(potentially_effectful_raw) != 1:
            continue
        provider = ProviderStratum(str(provider_raw))
        if provider == ProviderStratum.P1 and idempotency_raw is not None:
            p1_keys.add(str(idempotency_raw))
        else:
            independent += 1
    return independent + len(p1_keys)


def _provider_operations(path: Path) -> tuple[tuple[int, int], ...]:
    if not path.exists():
        raise ConfirmatoryEvidenceError("provider execution evidence is missing")
    with closing(sqlite3.connect(path)) as connection:
        rows = connection.execute(
            "SELECT effect_committed,fenced FROM operations ORDER BY rowid"
        ).fetchall()
    return tuple((int(effect_committed), int(fenced)) for effect_committed, fenced in rows)


def _unsafe_successor_from_provider_evidence(spec: TrialSpec, provider_path: Path) -> bool:
    operations = _provider_operations(provider_path)
    if spec.schedule not in _UNSAFE_SUCCESSOR_SCHEDULES or len(operations) <= 1:
        return False
    if spec.provider == ProviderStratum.P1:
        return False
    if spec.schedule == Schedule.S9 and spec.provider == ProviderStratum.P3:
        predecessor = operations[0]
        return predecessor[1] != 1
    return True


def derive_authoritative_trial(
    execution: TrialExecutionEvidence,
    *,
    trial_root: Path,
) -> AnalyzedTrial:
    """Derive primary scoring only from retained, sequence-bound mechanical evidence."""

    observation = execution.observation
    invalid_reason = _mechanically_proven_invalidation(execution, trial_root)
    oracle_path = trial_root / "oracle.sqlite"
    oracle_effect_count = (
        IndependentEffectOracleReader(oracle_path).effect_count(observation.trial_id)
        if oracle_path.exists()
        else 0
    )
    if invalid_reason is not None:
        return AnalyzedTrial(
            observation=observation,
            oracle_effect_count=oracle_effect_count,
            lineage_budget_violation=False,
            external_effect_violation=False,
            unsafe_successor_violation=False,
        )

    if not oracle_path.exists():
        raise ConfirmatoryEvidenceError("valid trial is missing independent oracle evidence")
    if observation.arm == Arm.A0:
        opportunities = _a0_independent_opportunities(trial_root / "a0" / "decisionlock.sqlite")
    elif observation.arm == Arm.A1:
        opportunities = _lineage_independent_opportunities(
            trial_root / "a1" / "lineage.sqlite", observation.alpha
        )
    else:
        opportunities = _lineage_independent_opportunities(
            trial_root / "b4" / "b4.sqlite", observation.alpha
        )
    independent_slots = max(1, opportunities)
    unsafe_successor = _unsafe_successor_from_provider_evidence(
        execution.spec, trial_root / "provider.sqlite"
    )
    if observation.independent_live_slots_max != independent_slots:
        raise ConfirmatoryEvidenceError(
            f"retained P-M1 observation disagrees with lineage evidence: {observation.trial_id}"
        )
    if observation.successor_admitted_while_predecessor_potentially_effectful != unsafe_successor:
        raise ConfirmatoryEvidenceError(
            f"retained P-M3 observation disagrees with execution evidence: {observation.trial_id}"
        )
    authoritative_observation = replace(
        observation,
        independent_live_slots_max=independent_slots,
        successor_admitted_while_predecessor_potentially_effectful=unsafe_successor,
    )
    return AnalyzedTrial(
        observation=authoritative_observation,
        oracle_effect_count=oracle_effect_count,
        lineage_budget_violation=independent_slots > 1,
        external_effect_violation=oracle_effect_count > 1,
        unsafe_successor_violation=unsafe_successor,
    )


def verify_supplied_analysis(supplied: AnalyzedTrial, authoritative: AnalyzedTrial) -> None:
    if supplied.observation != authoritative.observation:
        raise ConfirmatoryEvidenceError(
            f"caller-supplied observation disagrees with retained evidence: "
            f"{authoritative.observation.trial_id}"
        )
    if supplied.oracle_effect_count != authoritative.oracle_effect_count:
        raise ConfirmatoryEvidenceError(
            f"caller-supplied oracle_effect_count disagrees with oracle evidence: "
            f"{authoritative.observation.trial_id}"
        )
    if supplied.lineage_budget_violation != authoritative.lineage_budget_violation:
        raise ConfirmatoryEvidenceError(
            f"caller-supplied P-M1 classification disagrees with lineage evidence: "
            f"{authoritative.observation.trial_id}"
        )
    if supplied.external_effect_violation != authoritative.external_effect_violation:
        raise ConfirmatoryEvidenceError(
            f"caller-supplied P-M2 classification disagrees with oracle evidence: "
            f"{authoritative.observation.trial_id}"
        )
    if supplied.unsafe_successor_violation != authoritative.unsafe_successor_violation:
        raise ConfirmatoryEvidenceError(
            f"caller-supplied P-M3 classification disagrees with execution evidence: "
            f"{authoritative.observation.trial_id}"
        )


def authoritative_confirmatory_corpus(
    supplied_trials: Iterable[AnalyzedTrial],
    manifest: Sequence[TrialSpec],
    *,
    evidence_root: Path,
    expected_manifest_sha256: str,
    sequence_root: Path,
) -> tuple[AnalyzedTrial, ...]:
    _require_sha256(expected_manifest_sha256, "expected_manifest_sha256")
    execution = validate_execution_sequences(
        manifest,
        evidence_root=evidence_root,
        expected_manifest_sha256=expected_manifest_sha256,
        sequence_root=sequence_root,
    )
    supplied = tuple(supplied_trials)
    supplied_by_id = {trial.observation.trial_id: trial for trial in supplied}
    if len(supplied_by_id) != len(supplied):
        raise ConfirmatoryEvidenceError(
            "caller-supplied confirmatory corpus contains duplicate IDs"
        )
    expected_ids = {spec.trial_id for spec in manifest}
    if set(supplied_by_id) != expected_ids:
        raise ConfirmatoryEvidenceError(
            "caller-supplied confirmatory corpus does not match manifest IDs"
        )
    authoritative: list[AnalyzedTrial] = []
    for spec in manifest:
        execution_evidence = execution.get(spec.trial_id)
        if execution_evidence is None:
            raise ConfirmatoryEvidenceError(f"missing execution evidence: {spec.trial_id}")
        derived = derive_authoritative_trial(
            execution_evidence,
            trial_root=evidence_root / spec.trial_id,
        )
        verify_supplied_analysis(supplied_by_id[spec.trial_id], derived)
        authoritative.append(derived)
    return tuple(authoritative)


__all__ = [
    "ConfirmatoryEvidenceError",
    "TrialExecutionEvidence",
    "authoritative_confirmatory_corpus",
    "block_sequence_filename",
    "derive_authoritative_trial",
    "observation_from_payload",
    "observation_payload",
    "run_confirmatory_block",
    "validate_block_execution",
    "validate_block_records",
    "validate_execution_sequences",
    "verify_supplied_analysis",
]
