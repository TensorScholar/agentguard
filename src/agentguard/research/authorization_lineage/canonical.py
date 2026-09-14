from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Protocol, Sequence, cast

from .confirmatory import (
    ConfirmatoryEvidenceError,
    TrialExecutionEvidence,
    derive_authoritative_trial,
    observation_from_payload,
    observation_payload,
)
from .harness import DevTrialHarness
from .models import (
    PROTOCOL_ID,
    AnalyzedTrial,
    Arm,
    ProviderStratum,
    Schedule,
    TrialObservation,
    TrialSpec,
)
from .preflight import preflight_digest, run_confirmatory_preflight
from .trace import HarnessInvalidReason, invalid_observation, validate_trace

_ZERO_SHA1 = "0" * 40
_STUDY_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_OUTCOME_EVENTS = {
    "sut.rejection",
    "s4.worker.result",
    "s6.reserved",
    "successor.pressure",
    "reconciliation.evidence",
    "s11.current-resolution",
    "s11.successor",
    "trial.observation",
}


class ConfirmatorySessionError(RuntimeError):
    pass


class ConfirmatoryStudyInvalidError(ConfirmatorySessionError):
    pass


class ReplacementRequiredError(ConfirmatorySessionError):
    pass


class ReplacementExhaustedError(ConfirmatoryStudyInvalidError):
    pass


class AttemptDisposition(str, Enum):
    VALID = "valid"
    INVALID_NON_INTERPRETABLE = "invalid_non_interpretable"
    INVALID_INTERPRETABLE = "invalid_interpretable"
    STUDY_INVALID = "study_invalid"


@dataclass(frozen=True)
class PhaseEvidence:
    effect_capable_started: bool
    interpretable_state_reached: bool
    trace_valid: bool
    trace_error: str | None
    outcome_recorded: bool
    harness_reason_codes: tuple[str, ...]
    provider_operation_count: int
    sut_state_present: bool


@dataclass(frozen=True)
class CanonicalAttempt:
    attempt_id: str
    attempt_number: int
    trial_identity_sha256: str
    trial_identity: dict[str, object]
    block_id: str
    preflight_digest: str
    boundary_preflight_digest: str
    disposition: AttemptDisposition
    invalidation_reason: str | None
    phase: PhaseEvidence
    evidence_tree_sha256: str
    evidence_commitment_sha256: str
    durable_finish_oid: str
    observation: TrialObservation
    trial_root: Path


@dataclass(frozen=True)
class CanonicalStudyRecord:
    protocol: str
    candidate_git_commit: str
    candidate_git_tree: str
    manifest_sha256: str
    preflight_digest: str
    runtime_lock_sha256: str
    git_objects: dict[str, str]
    clarification_sha256: str
    clarification_git_blob: str
    study_execution_id: str
    canonical_study_root: str
    durable_commitment_ref: str
    registration_commitment_oid: str
    block_identity_sha256: str
    block_count: int
    trial_count: int


_SESSION_TOKEN = object()
_ATTEMPT_TOKEN = object()


@dataclass(frozen=True, init=False)
class ConfirmatoryReport:
    protocol: str
    study_execution_id: str
    candidate_git_commit: str
    candidate_git_tree: str
    manifest_sha256: str
    preflight_digest: str
    clarification_sha256: str
    durable_commitment_head: str
    complete_trial_evidence_commitment: str
    analysis_sha256: str
    _analysis_json: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise ConfirmatorySessionError(
            "ConfirmatoryReport may only be emitted by a validated CanonicalStudySession"
        )

    @property
    def analysis(self) -> dict[str, object]:
        decoded = json.loads(self._analysis_json)
        if not isinstance(decoded, dict):
            raise ConfirmatorySessionError("canonical report analysis payload is malformed")
        return cast(dict[str, object], decoded)

    def as_dict(self) -> dict[str, object]:
        return {
            "artifact_type": "AG-LINEAGE-CONFIRMATORY-REPORT-v1",
            "protocol": self.protocol,
            "study_execution_id": self.study_execution_id,
            "candidate_git_commit": self.candidate_git_commit,
            "candidate_git_tree": self.candidate_git_tree,
            "manifest_sha256": self.manifest_sha256,
            "preflight_digest": self.preflight_digest,
            "clarification_sha256": self.clarification_sha256,
            "durable_commitment_head": self.durable_commitment_head,
            "complete_trial_evidence_commitment": self.complete_trial_evidence_commitment,
            "analysis_sha256": self.analysis_sha256,
            "analysis": self.analysis,
        }


def _build_confirmatory_report(
    *,
    protocol: str,
    study_execution_id: str,
    candidate_git_commit: str,
    candidate_git_tree: str,
    manifest_sha256: str,
    preflight_digest_value: str,
    clarification_sha256: str,
    durable_commitment_head: str,
    complete_trial_evidence_commitment: str,
    analysis: dict[str, object],
) -> ConfirmatoryReport:
    report = object.__new__(ConfirmatoryReport)
    for name, value in {
        "protocol": protocol,
        "study_execution_id": study_execution_id,
        "candidate_git_commit": candidate_git_commit,
        "candidate_git_tree": candidate_git_tree,
        "manifest_sha256": manifest_sha256,
        "preflight_digest": preflight_digest_value,
        "clarification_sha256": clarification_sha256,
        "durable_commitment_head": durable_commitment_head,
        "complete_trial_evidence_commitment": complete_trial_evidence_commitment,
    }.items():
        object.__setattr__(report, name, value)
    analysis_json = _canonical_json(analysis)
    object.__setattr__(report, "_analysis_json", analysis_json)
    object.__setattr__(report, "analysis_sha256", _sha256_bytes(analysis_json.encode()))
    return report


class TrialRunner(Protocol):
    root: Path

    def run(self, spec: TrialSpec) -> TrialObservation: ...


class CommitmentStore(Protocol):
    ref_name: str

    def append(self, event: str, payload: dict[str, object]) -> str: ...

    def head(self) -> str: ...

    def verify(self) -> tuple[dict[str, object], ...]: ...


def _canonical_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_json(value).encode())


def _fsync_dir(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json_exclusive(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_dir(path.parent)


def _append_jsonl(path: Path, payload: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = _canonical_json(payload)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, (rendered + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_dir(path.parent)
    return _sha256_bytes(rendered.encode())


def _read_json(path: Path) -> dict[str, object]:
    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfirmatorySessionError(f"unreadable canonical JSON: {path}") from exc
    if not isinstance(decoded, dict):
        raise ConfirmatorySessionError(f"canonical JSON must be an object: {path}")
    return cast(dict[str, object], decoded)


def _int_value(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfirmatorySessionError(f"{name} must be an integer")
    return value


def _read_jsonl(path: Path) -> tuple[dict[str, object], ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfirmatorySessionError(f"unreadable canonical ledger: {path}") from exc
    records: list[dict[str, object]] = []
    for line in lines:
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ConfirmatorySessionError(f"invalid canonical ledger JSON: {path}") from exc
        if not isinstance(decoded, dict):
            raise ConfirmatorySessionError(f"canonical ledger entry must be an object: {path}")
        records.append(cast(dict[str, object], decoded))
    return tuple(records)


def canonical_trial_identity(spec: TrialSpec) -> dict[str, object]:
    return {
        "trial_id": spec.trial_id,
        "arm": spec.arm.value,
        "provider": spec.provider.value,
        "schedule": spec.schedule.value,
        "replicate": spec.replicate,
        "block_seed": spec.block_seed,
        "execution_order": spec.execution_order,
        "alpha": spec.alpha,
        "effect_key": spec.effect_key,
    }


def trial_spec_from_identity(value: object) -> TrialSpec:
    if not isinstance(value, dict):
        raise ConfirmatorySessionError("manifest trial identity must be an object")
    raw = cast(dict[str, object], value)
    try:
        return TrialSpec(
            trial_id=str(raw["trial_id"]),
            arm=Arm(str(raw["arm"])),
            provider=ProviderStratum(str(raw["provider"])),
            schedule=Schedule(str(raw["schedule"])),
            replicate=_int_value(raw["replicate"], "trial.replicate"),
            block_seed=str(raw["block_seed"]),
            execution_order=_int_value(raw["execution_order"], "trial.execution_order"),
            alpha=str(raw["alpha"]),
            effect_key=str(raw["effect_key"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfirmatorySessionError("manifest trial identity is malformed") from exc


def trial_identity_sha256(spec: TrialSpec) -> str:
    return _sha256_json(canonical_trial_identity(spec))


def manifest_identity_sha256(manifest: Sequence[TrialSpec]) -> str:
    return _sha256_json([canonical_trial_identity(spec) for spec in manifest])


def canonical_study_execution_id(
    *,
    candidate_git_commit: str,
    candidate_git_tree: str,
    manifest_sha256: str,
    preflight_digest_value: str,
    clarification_sha256: str,
) -> str:
    material = {
        "protocol": PROTOCOL_ID,
        "candidate_git_commit": candidate_git_commit,
        "candidate_git_tree": candidate_git_tree,
        "manifest_sha256": manifest_sha256,
        "preflight_digest": preflight_digest_value,
        "clarification_sha256": clarification_sha256,
    }
    return "ag-lineage-v1-" + _sha256_json(material)[:32]


def _block_identity(spec: TrialSpec) -> dict[str, object]:
    return {
        "provider": spec.provider.value,
        "schedule": spec.schedule.value,
        "replicate": spec.replicate,
        "block_seed": spec.block_seed,
    }


def block_id(spec: TrialSpec) -> str:
    return _sha256_json(_block_identity(spec))[:32]


def _ordered_block(block: Sequence[TrialSpec]) -> tuple[TrialSpec, TrialSpec, TrialSpec]:
    if len(block) != 3:
        raise ConfirmatorySessionError(
            "canonical confirmatory block must contain exactly three arms"
        )
    ordered = tuple(sorted(block, key=lambda item: item.execution_order))
    if tuple(item.execution_order for item in ordered) != (0, 1, 2):
        raise ConfirmatorySessionError("canonical block execution order must be exactly 0,1,2")
    if {item.arm for item in ordered} != {Arm.A0, Arm.A1, Arm.B4}:
        raise ConfirmatorySessionError("canonical block must contain A0, A1, and B4 exactly once")
    if len({_sha256_json(_block_identity(item)) for item in ordered}) != 1:
        raise ConfirmatorySessionError("canonical block identity is inconsistent")
    return cast(tuple[TrialSpec, TrialSpec, TrialSpec], ordered)


def _hash_tree(root: Path) -> tuple[str, dict[str, str]]:
    hashes: dict[str, str] = {}
    if root.exists():
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            hashes[str(path.relative_to(root))] = _sha256_bytes(path.read_bytes())
    return _sha256_json(hashes), hashes


def _sqlite_row_count(path: Path, table: str) -> int:
    if not path.exists():
        return 0
    try:
        with sqlite3.connect(path) as connection:
            row = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()
    except sqlite3.Error:
        return 0
    return int(row[0]) if row is not None else 0


def _sqlite_has_user_rows(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        with sqlite3.connect(path) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            for (name,) in tables:
                row = connection.execute(
                    f'SELECT 1 FROM "{str(name).replace(chr(34), chr(34) * 2)}" LIMIT 1'
                ).fetchone()
                if row is not None:
                    return True
    except sqlite3.Error:
        return False
    return False


def _trace_phase(trial_root: Path, trial_id: str) -> tuple[bool, str | None, set[str], set[str]]:
    trace_path = trial_root / "trace.jsonl"
    valid, error = validate_trace(trace_path, trial_id)
    events: set[str] = set()
    reasons: set[str] = set()
    if not trace_path.exists():
        return valid, error, events, reasons
    try:
        lines = trace_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False, error or "trace_read_failed", events, reasons
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        event = record.get("event_type")
        if isinstance(event, str):
            events.add(event)
        if event == "harness.invalid":
            detail = record.get("detail")
            if isinstance(detail, dict):
                reason = detail.get("reason")
                if isinstance(reason, str):
                    reasons.add(reason.split(":", 1)[0])
    return valid, error, events, reasons


def phase_evidence(trial_root: Path, trial_id: str) -> PhaseEvidence:
    trace_valid, trace_error, events, reasons = _trace_phase(trial_root, trial_id)
    provider_operations = _sqlite_row_count(trial_root / "provider.sqlite", "operations")
    sut_candidates = (
        trial_root / "a0" / "agentguard.sqlite",
        trial_root / "a1" / "agentguard.sqlite",
        trial_root / "a1" / "lineage.sqlite",
        trial_root / "b4" / "b4.sqlite",
        trial_root / "b4-fence.sqlite",
    )
    sut_state_present = any(_sqlite_has_user_rows(path) for path in sut_candidates)
    # Durable setup/registration rows alone are not a scheduled SUT outcome.
    # Interpretability requires retained outcome-phase trace evidence or provider admission.
    interpretable = bool(events & _OUTCOME_EVENTS) or provider_operations > 0
    return PhaseEvidence(
        effect_capable_started=provider_operations > 0,
        interpretable_state_reached=interpretable,
        trace_valid=trace_valid,
        trace_error=trace_error,
        outcome_recorded="trial.observation" in events,
        harness_reason_codes=tuple(sorted(reasons)),
        provider_operation_count=provider_operations,
        sut_state_present=sut_state_present,
    )


class GitRefCommitmentStore:
    """CAS-appended content-addressed commitments stored outside the mutable evidence tree."""

    def __init__(self, repo_root: Path, study_execution_id: str) -> None:
        if _STUDY_ID.fullmatch(study_execution_id) is None:
            raise ConfirmatorySessionError("invalid study_execution_id")
        self.repo_root = repo_root.resolve()
        self.study_execution_id = study_execution_id
        self.ref_name = f"refs/agentguard-confirmatory/{study_execution_id}"

    def _run(
        self, *args: str, input_text: str | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo_root,
            input=input_text,
            text=True,
            check=check,
            capture_output=True,
        )

    def _current(self) -> str | None:
        result = self._run("rev-parse", "--verify", "-q", self.ref_name, check=False)
        return result.stdout.strip() if result.returncode == 0 else None

    def _load_object(self, oid: str) -> dict[str, object]:
        result = self._run("cat-file", "blob", oid)
        try:
            decoded = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ConfirmatorySessionError("durable commitment object is invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise ConfirmatorySessionError("durable commitment object must be an object")
        return cast(dict[str, object], decoded)

    def append(self, event: str, payload: dict[str, object]) -> str:
        current = self._current()
        if event == "study.register" and current is not None:
            raise ConfirmatorySessionError(
                "study execution ID already owns a durable commitment namespace"
            )
        if event != "study.register" and current is None:
            raise ConfirmatorySessionError("durable commitment chain is not registered")
        previous_sequence = 0
        if current is not None:
            previous = self._load_object(current)
            previous_sequence = _int_value(previous.get("sequence", 0), "commitment.sequence")
        unsigned: dict[str, object] = {
            "version": 1,
            "study_execution_id": self.study_execution_id,
            "sequence": previous_sequence + 1,
            "event": event,
            "previous_oid": current,
            "payload": payload,
        }
        unsigned["record_sha256"] = _sha256_json(unsigned)
        rendered = _canonical_json(unsigned) + "\n"
        oid = self._run("hash-object", "-w", "--stdin", input_text=rendered).stdout.strip()
        if not oid:
            raise ConfirmatorySessionError("git failed to create durable commitment object")
        old = current if current is not None else "0" * len(oid)
        self._run("update-ref", self.ref_name, oid, old)
        return oid

    def head(self) -> str:
        current = self._current()
        if current is None:
            raise ConfirmatorySessionError("durable commitment ref is missing")
        return current

    def verify(self) -> tuple[dict[str, object], ...]:
        current = self.head()
        reversed_records: list[dict[str, object]] = []
        seen: set[str] = set()
        while current:
            if current in seen:
                raise ConfirmatorySessionError("durable commitment chain contains a cycle")
            seen.add(current)
            record = self._load_object(current)
            if record.get("study_execution_id") != self.study_execution_id:
                raise ConfirmatorySessionError("cross-study durable commitment reuse")
            recorded_digest = record.get("record_sha256")
            unsigned = dict(record)
            unsigned.pop("record_sha256", None)
            if recorded_digest != _sha256_json(unsigned):
                raise ConfirmatorySessionError("durable commitment digest mismatch")
            record["oid"] = current
            reversed_records.append(record)
            previous = record.get("previous_oid")
            if previous is None:
                current = ""
            elif isinstance(previous, str):
                current = previous
            else:
                raise ConfirmatorySessionError("durable commitment previous_oid is invalid")
        records = tuple(reversed(reversed_records))
        for expected, record in enumerate(records, start=1):
            if record.get("sequence") != expected:
                raise ConfirmatorySessionError("durable commitment sequence is not contiguous")
        return records


class MemoryCommitmentStore:
    """DEV-only commitment adapter; canonical report generation rejects it."""

    def __init__(self, study_execution_id: str) -> None:
        self.study_execution_id = study_execution_id
        self.ref_name = f"memory://{study_execution_id}"
        self._records: list[dict[str, object]] = []

    def append(self, event: str, payload: dict[str, object]) -> str:
        if event == "study.register" and self._records:
            raise ConfirmatorySessionError("DEV study execution ID is already registered")
        if event != "study.register" and not self._records:
            raise ConfirmatorySessionError("DEV commitment chain is not registered")
        previous = self._records[-1]["oid"] if self._records else None
        record: dict[str, object] = {
            "version": 1,
            "study_execution_id": self.study_execution_id,
            "sequence": len(self._records) + 1,
            "event": event,
            "previous_oid": previous,
            "payload": payload,
        }
        record["record_sha256"] = _sha256_json(record)
        record["oid"] = "dev-" + _sha256_json(record)
        self._records.append(record)
        return str(record["oid"])

    def head(self) -> str:
        if not self._records:
            raise ConfirmatorySessionError("DEV commitment store is empty")
        return str(self._records[-1]["oid"])

    def verify(self) -> tuple[dict[str, object], ...]:
        return tuple(dict(item) for item in self._records)


def _record_from_json(payload: dict[str, object]) -> CanonicalStudyRecord:
    try:
        return CanonicalStudyRecord(
            protocol=str(payload["protocol"]),
            candidate_git_commit=str(payload["candidate_git_commit"]),
            candidate_git_tree=str(payload["candidate_git_tree"]),
            manifest_sha256=str(payload["manifest_sha256"]),
            preflight_digest=str(payload["preflight_digest"]),
            runtime_lock_sha256=str(payload["runtime_lock_sha256"]),
            git_objects={
                str(k): str(v)
                for k, v in cast(dict[object, object], payload["git_objects"]).items()
            },
            clarification_sha256=str(payload["clarification_sha256"]),
            clarification_git_blob=str(payload["clarification_git_blob"]),
            study_execution_id=str(payload["study_execution_id"]),
            canonical_study_root=str(payload["canonical_study_root"]),
            durable_commitment_ref=str(payload["durable_commitment_ref"]),
            registration_commitment_oid=str(payload["registration_commitment_oid"]),
            block_identity_sha256=str(payload["block_identity_sha256"]),
            block_count=_int_value(payload["block_count"], "study.block_count"),
            trial_count=_int_value(payload["trial_count"], "study.trial_count"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfirmatorySessionError("canonical study record is malformed") from exc


def _block_groups(
    manifest: Sequence[TrialSpec],
) -> tuple[tuple[TrialSpec, TrialSpec, TrialSpec], ...]:
    grouped: dict[str, list[TrialSpec]] = {}
    order: list[str] = []
    for spec in manifest:
        identifier = block_id(spec)
        if identifier not in grouped:
            grouped[identifier] = []
            order.append(identifier)
        grouped[identifier].append(spec)
    return tuple(_ordered_block(grouped[item]) for item in order)


class CanonicalStudySession:
    def __init__(
        self,
        *,
        repo_root: Path,
        study_root: Path,
        manifest: Sequence[TrialSpec],
        record: CanonicalStudyRecord,
        commitment_store: CommitmentStore,
        _session_token: object | None = None,
    ) -> None:
        if _session_token is not _SESSION_TOKEN:
            raise ConfirmatorySessionError(
                "CanonicalStudySession must be created or loaded through a canonical factory"
            )
        self.repo_root = repo_root.resolve()
        self.study_root = study_root.resolve()
        self.manifest = tuple(manifest)
        self.record = record
        self.commitments = commitment_store
        self.attempt_ledger = self.study_root / "attempt-ledger.jsonl"
        self.sequence_ledger = self.study_root / "execution-sequence.jsonl"
        self.blocks_root = self.study_root / "blocks"
        self._manifest_by_id = {spec.trial_id: spec for spec in self.manifest}

    @classmethod
    def create_confirmatory(
        cls,
        *,
        repo_root: Path,
        study_parent: Path,
        manifest: Sequence[TrialSpec],
        expected_manifest_sha256: str,
        expected_git_commit: str,
    ) -> CanonicalStudySession:
        repo_root = repo_root.resolve()
        study_parent = study_parent.resolve()
        if study_parent == repo_root or repo_root in study_parent.parents:
            raise ConfirmatorySessionError(
                "canonical confirmatory evidence must live outside repository"
            )
        from .analysis import validate_confirmatory_manifest

        try:
            frozen_manifest = validate_confirmatory_manifest(manifest)
        except Exception as exc:
            raise ConfirmatorySessionError(
                "canonical confirmatory session requires the exact full frozen manifest"
            ) from exc
        manifest = frozen_manifest
        if manifest_identity_sha256(manifest) != expected_manifest_sha256:
            raise ConfirmatorySessionError("canonical session manifest digest mismatch")
        preflight = run_confirmatory_preflight(
            repo_root=repo_root,
            expected_git_commit=expected_git_commit,
        )
        digest = preflight_digest(preflight)
        commit = str(preflight["actual_git_commit"])
        tree = str(preflight["actual_git_tree"])
        clarification_sha = str(preflight["clarification_sha256"])
        clarification_blob = str(
            cast(dict[str, str], preflight["git_objects"])["protocol_clarification"]
        )
        study_execution_id = canonical_study_execution_id(
            candidate_git_commit=commit,
            candidate_git_tree=tree,
            manifest_sha256=expected_manifest_sha256,
            preflight_digest_value=digest,
            clarification_sha256=clarification_sha,
        )
        root = study_parent / study_execution_id
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
        _fsync_dir(root.parent)
        _write_json_exclusive(
            root / "manifest.json",
            {
                "manifest_sha256": expected_manifest_sha256,
                "trials": [canonical_trial_identity(spec) for spec in manifest],
            },
        )
        _write_json_exclusive(root / "preflight.json", {"digest": digest, "report": preflight})
        blocks = _block_groups(manifest)
        block_payload = [_block_identity(block[0]) for block in blocks]
        store = GitRefCommitmentStore(repo_root, study_execution_id)
        registration_payload = {
            "protocol": PROTOCOL_ID,
            "candidate_git_commit": commit,
            "candidate_git_tree": tree,
            "manifest_sha256": expected_manifest_sha256,
            "preflight_digest": digest,
            "runtime_lock_sha256": str(preflight["runtime_lock_sha256"]),
            "git_objects": cast(dict[str, str], preflight["git_objects"]),
            "clarification_sha256": clarification_sha,
            "clarification_git_blob": clarification_blob,
            "study_execution_id": study_execution_id,
            "canonical_study_root": str(root),
            "block_identity_sha256": _sha256_json(block_payload),
            "block_count": len(blocks),
            "trial_count": len(manifest),
        }
        registration_oid = store.append("study.register", registration_payload)
        record = CanonicalStudyRecord(
            protocol=PROTOCOL_ID,
            candidate_git_commit=commit,
            candidate_git_tree=tree,
            manifest_sha256=expected_manifest_sha256,
            preflight_digest=digest,
            runtime_lock_sha256=str(preflight["runtime_lock_sha256"]),
            git_objects=dict(cast(dict[str, str], preflight["git_objects"])),
            clarification_sha256=clarification_sha,
            clarification_git_blob=clarification_blob,
            study_execution_id=study_execution_id,
            canonical_study_root=str(root),
            durable_commitment_ref=store.ref_name,
            registration_commitment_oid=registration_oid,
            block_identity_sha256=_sha256_json(block_payload),
            block_count=len(blocks),
            trial_count=len(manifest),
        )
        _write_json_exclusive(root / "study.json", record.__dict__)
        return cls(
            repo_root=repo_root,
            study_root=root,
            manifest=manifest,
            record=record,
            commitment_store=store,
            _session_token=_SESSION_TOKEN,
        )

    @classmethod
    def load_confirmatory(
        cls,
        *,
        repo_root: Path,
        study_root: Path,
    ) -> CanonicalStudySession:
        repo_root = repo_root.resolve()
        root = study_root.resolve()
        record = _record_from_json(_read_json(root / "study.json"))
        if record.protocol != PROTOCOL_ID:
            raise ConfirmatorySessionError("canonical study protocol mismatch")
        if Path(record.canonical_study_root).resolve() != root:
            raise ConfirmatorySessionError("canonical study root substitution")
        manifest_payload = _read_json(root / "manifest.json")
        raw_trials = manifest_payload.get("trials")
        if not isinstance(raw_trials, list):
            raise ConfirmatorySessionError("canonical manifest snapshot is malformed")
        manifest = tuple(trial_spec_from_identity(item) for item in raw_trials)
        if manifest_payload.get("manifest_sha256") != record.manifest_sha256:
            raise ConfirmatorySessionError("canonical manifest record mismatch")
        if manifest_identity_sha256(manifest) != record.manifest_sha256:
            raise ConfirmatorySessionError("canonical manifest snapshot digest mismatch")
        from .analysis import validate_confirmatory_manifest

        try:
            manifest = validate_confirmatory_manifest(manifest)
        except Exception as exc:
            raise ConfirmatorySessionError(
                "canonical confirmatory study does not contain the exact full frozen manifest"
            ) from exc
        store = GitRefCommitmentStore(repo_root, record.study_execution_id)
        if store.ref_name != record.durable_commitment_ref:
            raise ConfirmatorySessionError("durable commitment ref substitution")
        session = cls(
            repo_root=repo_root,
            study_root=root,
            manifest=manifest,
            record=record,
            commitment_store=store,
            _session_token=_SESSION_TOKEN,
        )
        session._verify_lifecycle_prefix()
        return session

    @classmethod
    def create_dev(
        cls,
        *,
        study_root: Path,
        study_execution_id: str,
        manifest: Sequence[TrialSpec],
        preflight_report: dict[str, object],
    ) -> CanonicalStudySession:
        root = study_root.resolve()
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
        digest = preflight_digest(preflight_report)
        manifest_sha = manifest_identity_sha256(manifest)
        blocks = _block_groups(manifest)
        block_payload = [_block_identity(block[0]) for block in blocks]
        store = MemoryCommitmentStore(study_execution_id)
        registration_payload = {
            "protocol": PROTOCOL_ID,
            "candidate_git_commit": str(preflight_report["actual_git_commit"]),
            "candidate_git_tree": str(preflight_report["actual_git_tree"]),
            "manifest_sha256": manifest_sha,
            "preflight_digest": digest,
            "runtime_lock_sha256": str(preflight_report["runtime_lock_sha256"]),
            "git_objects": cast(dict[str, str], preflight_report["git_objects"]),
            "clarification_sha256": str(preflight_report["clarification_sha256"]),
            "clarification_git_blob": str(
                cast(dict[str, str], preflight_report["git_objects"])["protocol_clarification"]
            ),
            "study_execution_id": study_execution_id,
            "canonical_study_root": str(root),
            "block_identity_sha256": _sha256_json(block_payload),
            "block_count": len(blocks),
            "trial_count": len(manifest),
        }
        registration_oid = store.append("study.register", registration_payload)
        record = CanonicalStudyRecord(
            protocol=PROTOCOL_ID,
            candidate_git_commit=str(preflight_report["actual_git_commit"]),
            candidate_git_tree=str(preflight_report["actual_git_tree"]),
            manifest_sha256=manifest_sha,
            preflight_digest=digest,
            runtime_lock_sha256=str(preflight_report["runtime_lock_sha256"]),
            git_objects=dict(cast(dict[str, str], preflight_report["git_objects"])),
            clarification_sha256=str(preflight_report["clarification_sha256"]),
            clarification_git_blob=str(
                cast(dict[str, str], preflight_report["git_objects"])["protocol_clarification"]
            ),
            study_execution_id=study_execution_id,
            canonical_study_root=str(root),
            durable_commitment_ref=store.ref_name,
            registration_commitment_oid=registration_oid,
            block_identity_sha256=_sha256_json(block_payload),
            block_count=len(blocks),
            trial_count=len(manifest),
        )
        _write_json_exclusive(
            root / "manifest.json",
            {
                "manifest_sha256": manifest_sha,
                "trials": [canonical_trial_identity(spec) for spec in manifest],
            },
        )
        _write_json_exclusive(
            root / "preflight.json", {"digest": digest, "report": preflight_report}
        )
        _write_json_exclusive(root / "study.json", record.__dict__)
        return cls(
            repo_root=Path("."),
            study_root=root,
            manifest=manifest,
            record=record,
            commitment_store=store,
            _session_token=_SESSION_TOKEN,
        )

    def _append_lifecycle(self, event: str, payload: dict[str, object]) -> str:
        local = {
            "event": event,
            "study_execution_id": self.record.study_execution_id,
            "payload": payload,
        }
        local_sha = _append_jsonl(self.attempt_ledger, local)
        durable_payload = dict(payload)
        durable_payload["local_ledger_record_sha256"] = local_sha
        return self.commitments.append(event, durable_payload)

    def _append_sequence(self, event: str, payload: dict[str, object]) -> str:
        existing = _read_jsonl(self.sequence_ledger) if self.sequence_ledger.exists() else ()
        previous_hash = str(existing[-1].get("record_sha256")) if existing else "0" * 64
        unsigned = {
            "sequence": len(existing) + 1,
            "previous_hash": previous_hash,
            "event": event,
            "study_execution_id": self.record.study_execution_id,
            "payload": payload,
        }
        record_hash = _sha256_json(unsigned)
        _append_jsonl(self.sequence_ledger, {**unsigned, "record_sha256": record_hash})
        return record_hash

    def _verify_sequence_chain(self) -> tuple[dict[str, object], ...]:
        records = _read_jsonl(self.sequence_ledger) if self.sequence_ledger.exists() else ()
        previous_hash = "0" * 64
        for expected, record in enumerate(records, start=1):
            if record.get("sequence") != expected:
                raise ConfirmatorySessionError("execution sequence numbering is not contiguous")
            if record.get("previous_hash") != previous_hash:
                raise ConfirmatorySessionError("execution sequence predecessor hash mismatch")
            if record.get("study_execution_id") != self.record.study_execution_id:
                raise ConfirmatorySessionError("cross-study execution sequence reuse")
            recorded = record.get("record_sha256")
            unsigned = dict(record)
            unsigned.pop("record_sha256", None)
            if recorded != _sha256_json(unsigned):
                raise ConfirmatorySessionError("execution sequence record hash mismatch")
            previous_hash = str(recorded)
        return records

    def _verify_study_snapshots(self) -> None:
        study_payload = _read_json(self.study_root / "study.json")
        if study_payload != self.record.__dict__:
            raise ConfirmatorySessionError("canonical study record file drift")

        manifest_payload = _read_json(self.study_root / "manifest.json")
        expected_trials = [canonical_trial_identity(spec) for spec in self.manifest]
        if manifest_payload.get("manifest_sha256") != self.record.manifest_sha256:
            raise ConfirmatorySessionError("canonical manifest snapshot identity drift")
        if manifest_payload.get("trials") != expected_trials:
            raise ConfirmatorySessionError("canonical manifest snapshot trial drift")
        if manifest_identity_sha256(self.manifest) != self.record.manifest_sha256:
            raise ConfirmatorySessionError("canonical manifest in-memory identity drift")
        blocks = _block_groups(self.manifest)
        if self.record.trial_count != len(self.manifest):
            raise ConfirmatorySessionError("canonical study trial count drift")
        if self.record.block_count != len(blocks):
            raise ConfirmatorySessionError("canonical study block count drift")
        expected_block_identity = _sha256_json([_block_identity(block[0]) for block in blocks])
        if self.record.block_identity_sha256 != expected_block_identity:
            raise ConfirmatorySessionError("canonical study block identity drift")

        preflight_payload = _read_json(self.study_root / "preflight.json")
        if preflight_payload.get("digest") != self.record.preflight_digest:
            raise ConfirmatorySessionError("registered preflight digest file drift")
        raw_report = preflight_payload.get("report")
        if not isinstance(raw_report, dict):
            raise ConfirmatorySessionError("registered preflight report is malformed")
        report = cast(dict[str, object], raw_report)
        if preflight_digest(report) != self.record.preflight_digest:
            raise ConfirmatorySessionError("registered preflight report content drift")
        if report.get("actual_git_commit") != self.record.candidate_git_commit:
            raise ConfirmatorySessionError("registered preflight commit identity drift")
        if report.get("actual_git_tree") != self.record.candidate_git_tree:
            raise ConfirmatorySessionError("registered preflight tree identity drift")
        if report.get("runtime_lock_sha256") != self.record.runtime_lock_sha256:
            raise ConfirmatorySessionError("registered preflight runtime-lock identity drift")
        if report.get("git_objects") != self.record.git_objects:
            raise ConfirmatorySessionError("registered preflight Git-object identity drift")
        if report.get("clarification_sha256") != self.record.clarification_sha256:
            raise ConfirmatorySessionError("registered preflight clarification identity drift")

    def _verify_lifecycle_prefix(self) -> None:
        self._verify_study_snapshots()
        if self.commitments.ref_name != self.record.durable_commitment_ref:
            raise ConfirmatorySessionError("durable commitment adapter/ref substitution")
        durable = self.commitments.verify()
        if not durable or durable[0].get("event") != "study.register":
            raise ConfirmatorySessionError("durable chain lacks study.register")
        if durable[0].get("oid") != self.record.registration_commitment_oid:
            raise ConfirmatorySessionError("study registration commitment mismatch")
        registration = durable[0].get("payload")
        if not isinstance(registration, dict):
            raise ConfirmatorySessionError("study registration payload is malformed")
        expected_registration = {
            "protocol": self.record.protocol,
            "candidate_git_commit": self.record.candidate_git_commit,
            "candidate_git_tree": self.record.candidate_git_tree,
            "manifest_sha256": self.record.manifest_sha256,
            "preflight_digest": self.record.preflight_digest,
            "runtime_lock_sha256": self.record.runtime_lock_sha256,
            "git_objects": self.record.git_objects,
            "clarification_sha256": self.record.clarification_sha256,
            "clarification_git_blob": self.record.clarification_git_blob,
            "study_execution_id": self.record.study_execution_id,
            "canonical_study_root": self.record.canonical_study_root,
            "block_identity_sha256": self.record.block_identity_sha256,
            "block_count": self.record.block_count,
            "trial_count": self.record.trial_count,
        }
        if registration != expected_registration:
            raise ConfirmatorySessionError("study registration payload drift")
        local = _read_jsonl(self.attempt_ledger) if self.attempt_ledger.exists() else ()
        lifecycle = durable[1:]
        if len(local) != len(lifecycle):
            raise ConfirmatorySessionError(
                "local lifecycle ledger does not match durable commitment count"
            )
        for local_record, durable_record in zip(local, lifecycle, strict=True):
            if local_record.get("event") != durable_record.get("event"):
                raise ConfirmatorySessionError("local/durable lifecycle event mismatch")
            local_payload = local_record.get("payload")
            durable_payload = durable_record.get("payload")
            if not isinstance(local_payload, dict) or not isinstance(durable_payload, dict):
                raise ConfirmatorySessionError("local/durable lifecycle payload is malformed")
            durable_copy = dict(durable_payload)
            local_digest = durable_copy.pop("local_ledger_record_sha256", None)
            if local_digest != _sha256_json(local_record):
                raise ConfirmatorySessionError(
                    "local lifecycle ledger was rewritten after durable commitment"
                )
            if durable_copy != local_payload:
                raise ConfirmatorySessionError(
                    "local lifecycle payload differs from durable commitment"
                )

    def _verify_durable_execution_order(self) -> None:
        records = self.commitments.verify()
        sequence_records = self._verify_sequence_chain()
        durable_sequence_records = [
            record
            for record in records
            if record.get("event") in {"block.start", "trial.start", "trial.finish", "block.finish"}
        ]
        if len(durable_sequence_records) != len(sequence_records):
            raise ConfirmatorySessionError("durable/local execution sequence length mismatch")
        for durable, local in zip(durable_sequence_records, sequence_records, strict=True):
            if durable.get("event") != local.get("event"):
                raise ConfirmatorySessionError("durable/local execution sequence event mismatch")
            payload = durable.get("payload")
            if not isinstance(payload, dict):
                raise ConfirmatorySessionError("durable execution-sequence payload is malformed")
            if payload.get("sequence_commitment_sha256") != local.get("record_sha256"):
                raise ConfirmatorySessionError(
                    "durable commitment does not bind local execution sequence"
                )
        expected_by_block = {block_id(block[0]): block for block in _block_groups(self.manifest)}
        active_block: str | None = None
        seen_positions: dict[str, list[int]] = {key: [] for key in expected_by_block}
        finished_blocks: set[str] = set()
        for record in records:
            event = record.get("event")
            payload = record.get("payload")
            if not isinstance(payload, dict):
                continue
            if event == "block.start":
                identifier = payload.get("block_id")
                if not isinstance(identifier, str) or identifier not in expected_by_block:
                    raise ConfirmatorySessionError(
                        "durable block.start uses unknown block identity"
                    )
                if active_block is not None or identifier in finished_blocks:
                    raise ConfirmatorySessionError(
                        "durable block lifecycle is duplicated or interleaved"
                    )
                active_block = identifier
            elif event == "trial.start":
                if active_block is None:
                    raise ConfirmatorySessionError(
                        "durable trial.start is outside a registered block"
                    )
                identity = payload.get("trial_identity")
                if not isinstance(identity, dict):
                    raise ConfirmatorySessionError(
                        "durable trial.start lacks full logical identity"
                    )
                order_value = identity.get("execution_order")
                if not isinstance(order_value, int) or isinstance(order_value, bool):
                    raise ConfirmatorySessionError("durable trial.start execution_order is invalid")
                expected = (
                    expected_by_block[active_block][order_value] if 0 <= order_value <= 2 else None
                )
                if expected is None or identity != canonical_trial_identity(expected):
                    raise ConfirmatorySessionError(
                        "durable trial.start does not match frozen block identity"
                    )
                positions = seen_positions[active_block]
                if not positions and order_value != 0:
                    raise ConfirmatorySessionError(
                        "physical execution did not start at frozen order 0"
                    )
                if positions and order_value < positions[-1]:
                    raise ConfirmatorySessionError(
                        "physical execution order regressed after a later arm"
                    )
                if positions.count(order_value) >= 2:
                    raise ConfirmatorySessionError(
                        "durable execution contains more than one replacement"
                    )
                if positions and order_value > positions[-1] + 1:
                    raise ConfirmatorySessionError(
                        "physical execution skipped a frozen arm position"
                    )
                positions.append(order_value)
            elif event == "block.finish":
                identifier = payload.get("block_id")
                if not isinstance(identifier, str) or identifier != active_block:
                    raise ConfirmatorySessionError(
                        "durable block.finish does not match active block"
                    )
                positions = seen_positions[identifier]
                if not positions or set(positions) != {0, 1, 2}:
                    raise ConfirmatorySessionError(
                        "durable block.finish lacks complete 0,1,2 execution"
                    )
                finished_blocks.add(identifier)
                active_block = None
        if active_block is not None:
            # A paused invalid replicate may leave a block open during execution, but not at report time.
            raise ConfirmatorySessionError("durable execution contains an unfinished block")
        if finished_blocks != set(expected_by_block):
            raise ConfirmatorySessionError("durable execution does not contain every frozen block")

    def _boundary_preflight(self) -> tuple[str, dict[str, object]]:
        if type(self.commitments) is not GitRefCommitmentStore:
            preflight_payload = _read_json(self.study_root / "preflight.json")
            report = cast(dict[str, object], preflight_payload["report"])
            return str(preflight_payload["digest"]), report
        report = run_confirmatory_preflight(
            repo_root=self.repo_root,
            expected_git_commit=self.record.candidate_git_commit,
        )
        digest = preflight_digest(report)
        if digest != self.record.preflight_digest:
            raise ConfirmatoryStudyInvalidError(
                "execution-boundary preflight differs from registered preflight"
            )
        if str(report.get("actual_git_tree")) != self.record.candidate_git_tree:
            raise ConfirmatoryStudyInvalidError("execution-boundary Git tree drift")
        if str(report.get("clarification_sha256")) != self.record.clarification_sha256:
            raise ConfirmatoryStudyInvalidError("execution-boundary clarification drift")
        return digest, report

    def _attempt_records(self, spec: TrialSpec) -> tuple[dict[str, object], ...]:
        if not self.attempt_ledger.exists():
            return ()
        identity_sha = trial_identity_sha256(spec)
        return tuple(
            record
            for record in _read_jsonl(self.attempt_ledger)
            if isinstance(record.get("payload"), dict)
            and cast(dict[str, object], record["payload"]).get("trial_identity_sha256")
            == identity_sha
        )

    def _finished_attempts(self, spec: TrialSpec) -> tuple[dict[str, object], ...]:
        return tuple(
            record
            for record in self._attempt_records(spec)
            if record.get("event") == "trial.finish"
        )

    def _next_attempt_number(self, spec: TrialSpec) -> int:
        finished = self._finished_attempts(spec)
        if not finished:
            return 1
        if len(finished) == 1:
            payload = cast(dict[str, object], finished[0]["payload"])
            if payload.get("disposition") != AttemptDisposition.INVALID_NON_INTERPRETABLE.value:
                raise ConfirmatorySessionError(
                    "replacement is forbidden after an interpretable or valid attempt"
                )
            return 2
        raise ReplacementExhaustedError("maximum one replacement attempt is allowed")

    def _attempt_root(self, spec: TrialSpec, attempt_number: int) -> Path:
        return (
            self.blocks_root
            / block_id(spec)
            / "trials"
            / trial_identity_sha256(spec)
            / f"attempt-{attempt_number}"
        )

    def _classify_invalidation(
        self,
        *,
        spec: TrialSpec,
        observation: TrialObservation,
        trial_root: Path,
        external_machine_failure: str | None,
    ) -> tuple[AttemptDisposition, str | None, PhaseEvidence]:
        phase = phase_evidence(trial_root, spec.trial_id)
        reason = observation.harness_invalid_reason
        reason_code = reason.split(":", 1)[0] if reason else None
        if external_machine_failure is not None:
            if observation.harness_invalid and reason_code not in {
                None,
                HarnessInvalidReason.EXTERNAL_MACHINE_FAILURE.value,
            }:
                raise ConfirmatorySessionError(
                    "machine failure conflicts with retained invalidation metadata"
                )
            if phase.interpretable_state_reached:
                return AttemptDisposition.STUDY_INVALID, "late_external_machine_failure", phase
            return (
                AttemptDisposition.INVALID_NON_INTERPRETABLE,
                HarnessInvalidReason.EXTERNAL_MACHINE_FAILURE.value,
                phase,
            )
        if not observation.harness_invalid:
            if reason is not None:
                raise ConfirmatorySessionError(
                    "non-invalid observation carries invalidation metadata"
                )
            return AttemptDisposition.VALID, None, phase
        if reason_code is None:
            raise ConfirmatorySessionError("HARNESS_INVALID lacks reason")
        if (
            reason_code not in phase.harness_reason_codes
            and reason_code != HarnessInvalidReason.TRACE_CORRUPT.value
        ):
            raise ConfirmatorySessionError(
                "HARNESS_INVALID lacks matching retained mechanical trace evidence"
            )
        if reason_code == HarnessInvalidReason.WRONG_RUNTIME_OR_SCHEMA.value:
            return AttemptDisposition.STUDY_INVALID, reason_code, phase
        if reason_code == HarnessInvalidReason.DIRTY_NAMESPACE.value:
            raise ConfirmatorySessionError(
                "canonical namespace cannot admit dirty-namespace trial evidence"
            )
        if reason_code == HarnessInvalidReason.ORACLE_UNAVAILABLE.value:
            if phase.effect_capable_started or phase.outcome_recorded:
                return AttemptDisposition.STUDY_INVALID, "late_oracle_integrity_failure", phase
            if phase.interpretable_state_reached:
                return AttemptDisposition.INVALID_INTERPRETABLE, reason_code, phase
            return AttemptDisposition.INVALID_NON_INTERPRETABLE, reason_code, phase
        if reason_code == HarnessInvalidReason.EXTERNAL_MACHINE_FAILURE.value:
            raise ConfirmatorySessionError(
                "external-machine invalidation lacks coordinator-captured failure"
            )
        if reason_code == HarnessInvalidReason.SCHEDULE_BARRIER_FAILURE.value:
            if "barrier.failed" not in _trace_phase(trial_root, spec.trial_id)[2]:
                raise ConfirmatorySessionError("barrier invalidation lacks barrier.failed evidence")
            disposition = (
                AttemptDisposition.INVALID_INTERPRETABLE
                if phase.interpretable_state_reached
                else AttemptDisposition.INVALID_NON_INTERPRETABLE
            )
            return disposition, reason_code, phase
        if reason_code == HarnessInvalidReason.TRACE_CORRUPT.value:
            if phase.trace_valid:
                raise ConfirmatorySessionError(
                    "trace-corrupt invalidation conflicts with valid trace"
                )
            disposition = (
                AttemptDisposition.INVALID_INTERPRETABLE
                if phase.interpretable_state_reached
                else AttemptDisposition.INVALID_NON_INTERPRETABLE
            )
            return disposition, reason_code, phase
        raise ConfirmatorySessionError("non-preregistered invalidation reason")

    def _run_attempt(
        self,
        spec: TrialSpec,
        *,
        runner_factory: Callable[[Path], TrialRunner],
        _attempt_token: object | None = None,
    ) -> CanonicalAttempt:
        if _attempt_token is not _ATTEMPT_TOKEN:
            raise ConfirmatorySessionError(
                "attempt execution is internal to CanonicalStudySession.run_block"
            )
        if spec.trial_id not in self._manifest_by_id or self._manifest_by_id[spec.trial_id] != spec:
            raise ConfirmatorySessionError(
                "attempt spec does not exactly match frozen manifest identity"
            )
        attempt_number = self._next_attempt_number(spec)
        attempt_id = f"{spec.trial_id}:attempt:{attempt_number}"
        attempt_root = self._attempt_root(spec, attempt_number)
        attempt_root.mkdir(parents=True, mode=0o700, exist_ok=False)
        _fsync_dir(attempt_root.parent)
        trial_identity = canonical_trial_identity(spec)
        identity_sha = trial_identity_sha256(spec)
        context = {
            "protocol": PROTOCOL_ID,
            "study_execution_id": self.record.study_execution_id,
            "candidate_git_commit": self.record.candidate_git_commit,
            "candidate_git_tree": self.record.candidate_git_tree,
            "manifest_sha256": self.record.manifest_sha256,
            "runtime_lock_sha256": self.record.runtime_lock_sha256,
            "clarification_git_blob": self.record.clarification_git_blob,
            "block_id": block_id(spec),
            "attempt_id": attempt_id,
            "attempt_number": attempt_number,
            "trial_identity": trial_identity,
            "trial_identity_sha256": identity_sha,
            "preflight_digest": self.record.preflight_digest,
            "clarification_sha256": self.record.clarification_sha256,
        }
        _write_json_exclusive(attempt_root / "attempt-context.json", context)
        initial_register_payload = {**context, "attempt_root": str(attempt_root)}
        self._append_lifecycle("attempt.register", initial_register_payload)
        boundary_digest, _ = self._boundary_preflight()
        register_payload = {
            **initial_register_payload,
            "boundary_preflight_digest": boundary_digest,
        }
        self._append_lifecycle("attempt.boundary", register_payload)
        sequence_start_sha = self._append_sequence(
            "trial.start",
            {
                "block_id": block_id(spec),
                "attempt_id": attempt_id,
                "trial_identity_sha256": identity_sha,
                "execution_order": spec.execution_order,
            },
        )
        start_payload = {
            **register_payload,
            "sequence_commitment_sha256": sequence_start_sha,
        }
        start_oid = self._append_lifecycle("trial.start", start_payload)
        runner_root = attempt_root / "runner"
        runner_root.mkdir(mode=0o700)
        runner = runner_factory(runner_root)
        if Path(runner.root).resolve() != runner_root.resolve():
            raise ConfirmatorySessionError("runner root is outside canonical attempt namespace")
        external_failure: str | None = None
        observation: TrialObservation
        try:
            observation = runner.run(spec)
        except (OSError, SystemError, MemoryError) as exc:
            external_failure = type(exc).__name__
            observation = invalid_observation(
                spec,
                HarnessInvalidReason.EXTERNAL_MACHINE_FAILURE,
                detail=external_failure,
            )
        trial_root = runner_root / spec.trial_id
        try:
            disposition, invalidation_reason, phase = self._classify_invalidation(
                spec=spec,
                observation=observation,
                trial_root=trial_root,
                external_machine_failure=external_failure,
            )
            evidence_tree_sha, evidence_files = _hash_tree(attempt_root)
        except OSError as exc:
            phase = phase_evidence(trial_root, spec.trial_id)
            if phase.interpretable_state_reached:
                disposition = AttemptDisposition.STUDY_INVALID
                invalidation_reason = "late_external_machine_failure"
                evidence_tree_sha, evidence_files = _hash_tree(attempt_root)
            else:
                disposition = AttemptDisposition.INVALID_NON_INTERPRETABLE
                invalidation_reason = HarnessInvalidReason.EXTERNAL_MACHINE_FAILURE.value
                evidence_tree_sha, evidence_files = _hash_tree(attempt_root)
            external_failure = type(exc).__name__
        evidence_commitment = _sha256_json(
            {
                "study_execution_id": self.record.study_execution_id,
                "manifest_sha256": self.record.manifest_sha256,
                "attempt_id": attempt_id,
                "trial_identity_sha256": identity_sha,
                "evidence_tree_sha256": evidence_tree_sha,
                "evidence_files": evidence_files,
                "start_commitment_oid": start_oid,
            }
        )
        finish_payload: dict[str, object] = {
            **register_payload,
            "observation": observation_payload(observation),
            "external_machine_failure": external_failure,
            "disposition": disposition.value,
            "invalidation_reason": invalidation_reason,
            "phase": {
                "effect_capable_started": phase.effect_capable_started,
                "interpretable_state_reached": phase.interpretable_state_reached,
                "trace_valid": phase.trace_valid,
                "trace_error": phase.trace_error,
                "outcome_recorded": phase.outcome_recorded,
                "harness_reason_codes": list(phase.harness_reason_codes),
                "provider_operation_count": phase.provider_operation_count,
                "sut_state_present": phase.sut_state_present,
            },
            "evidence_tree_sha256": evidence_tree_sha,
            "evidence_files": evidence_files,
            "evidence_commitment_sha256": evidence_commitment,
            "start_commitment_oid": start_oid,
        }
        sequence_finish_sha = self._append_sequence(
            "trial.finish",
            {
                "block_id": block_id(spec),
                "attempt_id": attempt_id,
                "trial_identity_sha256": identity_sha,
                "execution_order": spec.execution_order,
                "evidence_commitment_sha256": evidence_commitment,
            },
        )
        finish_payload["sequence_commitment_sha256"] = sequence_finish_sha
        finish_oid = self._append_lifecycle("trial.finish", finish_payload)
        attempt = CanonicalAttempt(
            attempt_id=attempt_id,
            attempt_number=attempt_number,
            trial_identity_sha256=identity_sha,
            trial_identity=trial_identity,
            block_id=block_id(spec),
            preflight_digest=self.record.preflight_digest,
            boundary_preflight_digest=boundary_digest,
            disposition=disposition,
            invalidation_reason=invalidation_reason,
            phase=phase,
            evidence_tree_sha256=evidence_tree_sha,
            evidence_commitment_sha256=evidence_commitment,
            durable_finish_oid=finish_oid,
            observation=observation,
            trial_root=trial_root,
        )
        if disposition == AttemptDisposition.STUDY_INVALID:
            self._append_lifecycle(
                "study.fail",
                {
                    "attempt_id": attempt_id,
                    "trial_identity_sha256": identity_sha,
                    "reason": invalidation_reason,
                },
            )
            raise ConfirmatoryStudyInvalidError(str(invalidation_reason))
        if attempt_number == 2 and disposition != AttemptDisposition.VALID:
            self._append_lifecycle(
                "study.fail",
                {
                    "attempt_id": attempt_id,
                    "trial_identity_sha256": identity_sha,
                    "reason": "replacement_exhausted",
                },
            )
            raise ReplacementExhaustedError(
                "the single authorized replacement did not produce a valid trial"
            )
        return attempt

    def _finished_payloads(self, spec: TrialSpec) -> tuple[dict[str, object], ...]:
        payloads: list[dict[str, object]] = []
        for record in self._finished_attempts(spec):
            payload = record.get("payload")
            if isinstance(payload, dict):
                payloads.append(cast(dict[str, object], payload))
        return tuple(payloads)

    def selected_attempt_payload(self, spec: TrialSpec) -> dict[str, object]:
        attempts = self._finished_payloads(spec)
        if len(attempts) == 1:
            if attempts[0].get("disposition") == AttemptDisposition.VALID.value:
                return attempts[0]
            raise ReplacementRequiredError("logical trial requires its one authorized replacement")
        if len(attempts) == 2:
            if attempts[0].get("disposition") != AttemptDisposition.INVALID_NON_INTERPRETABLE.value:
                raise ConfirmatorySessionError(
                    "replacement exists without eligible invalid original"
                )
            if attempts[1].get("disposition") != AttemptDisposition.VALID.value:
                raise ReplacementExhaustedError("replacement is not valid")
            if attempts[0].get("trial_identity_sha256") != attempts[1].get("trial_identity_sha256"):
                raise ConfirmatorySessionError("replacement changed frozen logical trial identity")
            return attempts[1]
        if len(attempts) > 2:
            raise ConfirmatorySessionError("more than one replacement attempt is present")
        raise ConfirmatorySessionError("logical trial has no canonical attempt")

    def run_block(
        self,
        block: Sequence[TrialSpec],
        *,
        runner_factory: Callable[[Path], TrialRunner] | None = None,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        self._verify_lifecycle_prefix()
        is_confirmatory = self.record.durable_commitment_ref.startswith(
            "refs/agentguard-confirmatory/"
        )
        if is_confirmatory:
            if type(self.commitments) is not GitRefCommitmentStore:
                raise ConfirmatorySessionError(
                    "canonical confirmatory execution requires the GitRef durable adapter"
                )
            if runner_factory is not None:
                raise ConfirmatorySessionError(
                    "canonical confirmatory execution does not accept caller-supplied runners"
                )
            selected_runner_factory: Callable[[Path], TrialRunner] = DevTrialHarness
        else:
            if not self.record.durable_commitment_ref.startswith("memory://"):
                raise ConfirmatorySessionError("unknown canonical session commitment mode")
            if type(self.commitments) is not MemoryCommitmentStore:
                raise ConfirmatorySessionError("DEV session commitment adapter substitution")
            if runner_factory is None:
                raise ConfirmatorySessionError("DEV canonical execution requires a runner_factory")
            selected_runner_factory = runner_factory
        ordered = _ordered_block(block)
        for spec in ordered:
            frozen = self._manifest_by_id.get(spec.trial_id)
            if frozen != spec:
                raise ConfirmatorySessionError(
                    "block contains non-manifest or relabeled logical trial"
                )
        identifier = block_id(ordered[0])
        block_root = self.blocks_root / identifier
        start_marker = block_root / "block-start.json"
        if not start_marker.exists():
            block_root.mkdir(parents=True, mode=0o700, exist_ok=False)
            boundary_digest, _ = self._boundary_preflight()
            payload = {
                "block_id": identifier,
                "block_seed": ordered[0].block_seed,
                "manifest_sha256": self.record.manifest_sha256,
                "preflight_digest": self.record.preflight_digest,
                "boundary_preflight_digest": boundary_digest,
                "ordered_trial_identities": [canonical_trial_identity(spec) for spec in ordered],
            }
            sequence_start_sha = self._append_sequence("block.start", payload)
            durable_payload = {**payload, "sequence_commitment_sha256": sequence_start_sha}
            start_oid = self._append_lifecycle("block.start", durable_payload)
            _write_json_exclusive(start_marker, {**durable_payload, "durable_start_oid": start_oid})
        selected: list[dict[str, object]] = []
        for spec in ordered:
            try:
                selected.append(self.selected_attempt_payload(spec))
                continue
            except ConfirmatorySessionError as exc:
                if not isinstance(exc, ReplacementRequiredError) and self._finished_payloads(spec):
                    raise
            attempt = self._run_attempt(
                spec,
                runner_factory=selected_runner_factory,
                _attempt_token=_ATTEMPT_TOKEN,
            )
            if attempt.disposition == AttemptDisposition.INVALID_NON_INTERPRETABLE:
                raise ReplacementRequiredError(
                    f"{spec.trial_id} requires its one authorized replacement before block may continue"
                )
            if attempt.disposition == AttemptDisposition.INVALID_INTERPRETABLE:
                self._append_lifecycle(
                    "study.fail",
                    {
                        "attempt_id": attempt.attempt_id,
                        "trial_identity_sha256": attempt.trial_identity_sha256,
                        "reason": "invalid_attempt_after_interpretable_state",
                    },
                )
                raise ConfirmatoryStudyInvalidError(
                    f"invalid attempt produced interpretable state and cannot be replaced: {spec.trial_id}"
                )
            selected.append(self.selected_attempt_payload(spec))
        finish_marker = block_root / "block-finish.json"
        if not finish_marker.exists():
            complete = _sha256_json(
                [
                    {
                        "trial_identity_sha256": item["trial_identity_sha256"],
                        "attempt_id": item["attempt_id"],
                        "evidence_commitment_sha256": item["evidence_commitment_sha256"],
                    }
                    for item in selected
                ]
            )
            payload = {
                "block_id": identifier,
                "block_seed": ordered[0].block_seed,
                "manifest_sha256": self.record.manifest_sha256,
                "selected_attempt_ids": [str(item["attempt_id"]) for item in selected],
                "block_evidence_commitment_sha256": complete,
            }
            sequence_finish_sha = self._append_sequence("block.finish", payload)
            durable_payload = {**payload, "sequence_commitment_sha256": sequence_finish_sha}
            finish_oid = self._append_lifecycle("block.finish", durable_payload)
            _write_json_exclusive(
                finish_marker, {**durable_payload, "durable_finish_oid": finish_oid}
            )
        return cast(tuple[dict[str, object], dict[str, object], dict[str, object]], tuple(selected))

    def _verify_payload_identity(self, spec: TrialSpec, payload: dict[str, object]) -> None:
        expected_identity = canonical_trial_identity(spec)
        if payload.get("trial_identity") != expected_identity:
            raise ConfirmatorySessionError("retained attempt logical trial identity mismatch")
        if payload.get("trial_identity_sha256") != trial_identity_sha256(spec):
            raise ConfirmatorySessionError(
                "retained attempt logical trial identity digest mismatch"
            )
        if payload.get("manifest_sha256") != self.record.manifest_sha256:
            raise ConfirmatorySessionError("cross-manifest attempt reuse")
        if payload.get("preflight_digest") != self.record.preflight_digest:
            raise ConfirmatorySessionError("attempt preflight identity mismatch")
        if payload.get("clarification_sha256") != self.record.clarification_sha256:
            raise ConfirmatorySessionError("attempt clarification identity mismatch")

    def authoritative_trials(self) -> tuple[AnalyzedTrial, ...]:
        self._verify_lifecycle_prefix()
        seen_evidence: set[str] = set()
        trials: list[AnalyzedTrial] = []
        for spec in self.manifest:
            payload = self.selected_attempt_payload(spec)
            self._verify_payload_identity(spec, payload)
            attempt_number = _int_value(payload["attempt_number"], "attempt.attempt_number")
            attempt_root = self._attempt_root(spec, attempt_number)
            if str(payload.get("attempt_root")) != str(attempt_root):
                raise ConfirmatorySessionError("attempt evidence namespace substitution")
            current_tree_sha, current_files = _hash_tree(attempt_root)
            if current_tree_sha != payload.get("evidence_tree_sha256"):
                raise ConfirmatorySessionError(
                    "retained attempt evidence changed after durable finish"
                )
            if current_files != payload.get("evidence_files"):
                raise ConfirmatorySessionError("retained attempt evidence file set changed")
            evidence_commitment = str(payload["evidence_commitment_sha256"])
            if evidence_commitment in seen_evidence:
                raise ConfirmatorySessionError("cross-attempt evidence commitment reuse")
            seen_evidence.add(evidence_commitment)
            observation = observation_from_payload(payload["observation"])
            trial_root = attempt_root / "runner" / spec.trial_id
            execution = TrialExecutionEvidence(
                spec=spec,
                observation=observation,
                preexisting_entries=(),
                external_machine_failure=cast(str | None, payload.get("external_machine_failure")),
                evidence_sha256=cast(dict[str, str], payload["evidence_files"]),
            )
            try:
                trials.append(derive_authoritative_trial(execution, trial_root=trial_root))
            except ConfirmatoryEvidenceError as exc:
                raise ConfirmatorySessionError(str(exc)) from exc
        return tuple(trials)

    def finalize(self) -> str:
        if any(record.get("event") == "study.fail" for record in self.commitments.verify()):
            raise ConfirmatoryStudyInvalidError(
                "canonical study contains a terminal study.fail record"
            )
        selected: list[dict[str, object]] = []
        for spec in self.manifest:
            selected.append(self.selected_attempt_payload(spec))
        expected_block_finishes = {block_id(block[0]) for block in _block_groups(self.manifest)}
        actual_block_finishes = (
            {path.parent.name for path in self.blocks_root.glob("*/block-finish.json")}
            if self.blocks_root.exists()
            else set()
        )
        if actual_block_finishes != expected_block_finishes:
            raise ConfirmatorySessionError(
                "canonical study cannot finalize before every block is complete"
            )
        durable_block_finishes = {
            cast(dict[str, object], record["payload"]).get("block_id")
            for record in self.commitments.verify()
            if record.get("event") == "block.finish" and isinstance(record.get("payload"), dict)
        }
        if durable_block_finishes != expected_block_finishes:
            raise ConfirmatorySessionError(
                "durable chain does not contain every canonical block.finish"
            )
        complete = _sha256_json(
            [
                {
                    "trial_identity_sha256": item["trial_identity_sha256"],
                    "attempt_id": item["attempt_id"],
                    "evidence_commitment_sha256": item["evidence_commitment_sha256"],
                }
                for item in selected
            ]
        )
        completion_path = self.study_root / "study-finish.json"
        if completion_path.exists():
            existing = _read_json(completion_path)
            if existing.get("complete_trial_evidence_commitment") != complete:
                raise ConfirmatorySessionError("study completion commitment drift")
            return complete
        payload = {
            "manifest_sha256": self.record.manifest_sha256,
            "preflight_digest": self.record.preflight_digest,
            "clarification_sha256": self.record.clarification_sha256,
            "complete_trial_evidence_commitment": complete,
            "selected_attempt_ids": [str(item["attempt_id"]) for item in selected],
        }
        oid = self._append_lifecycle("study.finish", payload)
        _write_json_exclusive(completion_path, {**payload, "durable_finish_oid": oid})
        return complete

    def validate_for_report(self) -> tuple[str, str]:
        if type(self.commitments) is not GitRefCommitmentStore:
            raise ConfirmatorySessionError("DEV commitment adapters cannot emit ConfirmatoryReport")
        from .analysis import validate_confirmatory_manifest

        try:
            validate_confirmatory_manifest(self.manifest)
        except Exception as exc:
            raise ConfirmatorySessionError(
                "ConfirmatoryReport requires the exact full frozen manifest"
            ) from exc
        if Path(self.record.canonical_study_root).resolve() != self.study_root:
            raise ConfirmatorySessionError("canonical study root mismatch")
        if manifest_identity_sha256(self.manifest) != self.record.manifest_sha256:
            raise ConfirmatorySessionError("canonical manifest drift")
        boundary_digest, report = self._boundary_preflight()
        if boundary_digest != self.record.preflight_digest:
            raise ConfirmatorySessionError("analysis preflight identity mismatch")
        if str(report.get("clarification_sha256")) != self.record.clarification_sha256:
            raise ConfirmatorySessionError("analysis clarification identity mismatch")
        self._verify_lifecycle_prefix()
        self._verify_durable_execution_order()
        records = self.commitments.verify()
        if any(record.get("event") == "study.fail" for record in records):
            raise ConfirmatoryStudyInvalidError(
                "canonical study contains a terminal study.fail record"
            )
        completion = _read_json(self.study_root / "study-finish.json")
        if records[-1].get("event") != "study.finish":
            raise ConfirmatorySessionError("durable chain is not terminally bound to study.finish")
        if records[-1].get("oid") != completion.get("durable_finish_oid"):
            raise ConfirmatorySessionError("terminal study commitment mismatch")
        self.authoritative_trials()
        return str(completion["complete_trial_evidence_commitment"]), self.commitments.head()

    def emit_report(self) -> ConfirmatoryReport:
        """Recompute analysis internally and emit the only canonical report type."""

        complete_evidence, durable_head = self.validate_for_report()
        from .statistics import analyze_study

        corpus = self.authoritative_trials()
        analysis = analyze_study(corpus)
        analysis["confirmatory_corpus"] = {
            "exact_manifest_match": True,
            "manifest_sha256": self.record.manifest_sha256,
            "logical_trials": len(self.manifest),
            "corpus_trials": len(corpus),
            "silent_omissions": 0,
            "attempt_selection": "canonical-append-only-attempt-ledger",
            "authoritative_scoring": "retained-evidence-recomputed",
            "execution_order_evidence": "durable-pre-invocation-commitments",
            "clarification_sha256": self.record.clarification_sha256,
            "preflight_digest": self.record.preflight_digest,
        }
        return _build_confirmatory_report(
            protocol=self.record.protocol,
            study_execution_id=self.record.study_execution_id,
            candidate_git_commit=self.record.candidate_git_commit,
            candidate_git_tree=self.record.candidate_git_tree,
            manifest_sha256=self.record.manifest_sha256,
            preflight_digest_value=self.record.preflight_digest,
            clarification_sha256=self.record.clarification_sha256,
            durable_commitment_head=durable_head,
            complete_trial_evidence_commitment=complete_evidence,
            analysis=analysis,
        )


__all__ = [
    "AttemptDisposition",
    "CanonicalAttempt",
    "CanonicalStudyRecord",
    "CanonicalStudySession",
    "CommitmentStore",
    "ConfirmatoryReport",
    "ConfirmatorySessionError",
    "ConfirmatoryStudyInvalidError",
    "PhaseEvidence",
    "ReplacementExhaustedError",
    "ReplacementRequiredError",
    "block_id",
    "canonical_study_execution_id",
    "canonical_trial_identity",
    "manifest_identity_sha256",
    "phase_evidence",
    "trial_identity_sha256",
    "trial_spec_from_identity",
]
