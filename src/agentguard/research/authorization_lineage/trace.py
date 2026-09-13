from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .models import AnalyzedTrial, TrialObservation, TrialSpec


class HarnessInvalidReason(str, Enum):
    WRONG_RUNTIME_OR_SCHEMA = "wrong_executable_commit_or_schema"
    DIRTY_NAMESPACE = "provider_or_oracle_namespace_not_clean"
    ORACLE_UNAVAILABLE = "oracle_process_unavailable_before_effect_capable_operation"
    SCHEDULE_BARRIER_FAILURE = "schedule_required_barrier_or_partial_order_not_established"
    TRACE_CORRUPT = "corrupted_or_missing_harness_trace"
    EXTERNAL_MACHINE_FAILURE = "external_machine_failure_outside_injected_schedule"


class TrialTraceRecorder:
    """Append-only schedule trace used to reproduce harness ordering independently of SUT state."""

    def __init__(self, path: Path, spec: TrialSpec) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.spec = spec
        self._sequence = 0
        self._lock = threading.Lock()
        self._handle = path.open("x", encoding="utf-8")
        self.event(
            "trial.start",
            arm=spec.arm.value,
            provider=spec.provider.value,
            schedule=spec.schedule.value,
            replicate=spec.replicate,
            block_seed=spec.block_seed,
            execution_order=spec.execution_order,
        )

    def event(self, event_type: str, **detail: object) -> None:
        with self._lock:
            self._sequence += 1
            payload = {
                "sequence": self._sequence,
                "timestamp": datetime.now(UTC).isoformat(),
                "trial_id": self.spec.trial_id,
                "alpha": self.spec.alpha,
                "effect_key": self.spec.effect_key,
                "event_type": event_type,
                "detail": detail,
            }
            self._handle.write(json.dumps(payload, sort_keys=True, default=str) + "\n")
            self._handle.flush()

    def close(self) -> None:
        if not self._handle.closed:
            self._handle.close()


def validate_trace(path: Path, trial_id: str) -> tuple[bool, str | None]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return False, f"trace_read_failed:{type(exc).__name__}"
    if not lines:
        return False, "trace_empty"
    for expected, line in enumerate(lines, start=1):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return False, f"trace_json_invalid:{expected}"
        if payload.get("sequence") != expected:
            return False, f"trace_sequence_gap:{expected}"
        if payload.get("trial_id") != trial_id:
            return False, f"trace_trial_mismatch:{expected}"
    try:
        first = json.loads(lines[0])
    except json.JSONDecodeError:
        return False, "trace_first_record_invalid"
    if first.get("event_type") != "trial.start":
        return False, "trace_missing_start"
    return True, None


def invalid_observation(
    spec: TrialSpec, reason: HarnessInvalidReason, *, detail: str | None = None
) -> TrialObservation:
    rendered_reason = reason.value if detail is None else f"{reason.value}:{detail}"
    return TrialObservation(
        trial_id=spec.trial_id,
        arm=spec.arm,
        provider=spec.provider,
        schedule=spec.schedule,
        replicate=spec.replicate,
        block_seed=spec.block_seed,
        execution_order=spec.execution_order,
        alpha=spec.alpha,
        effect_key=spec.effect_key,
        root_or_slot_allocations=0,
        independent_live_slots_max=0,
        receipts_or_tickets=0,
        credentials=0,
        provider_sends=0,
        attempts=0,
        successor_admitted_while_predecessor_potentially_effectful=False,
        stale_reconciler_commit_accepted=False,
        legitimate_completion=False,
        unresolved=False,
        operator_interventions=0,
        reconciliation_calls=0,
        slot_hold_seconds=0.0,
        duration_seconds=0.0,
        harness_invalid=True,
        harness_invalid_reason=rendered_reason,
    )


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def _sqlite_snapshot(path: Path) -> dict[str, object]:
    snapshot: dict[str, object] = {"path": str(path.name), "tables": {}}
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        tables: dict[str, object] = {}
        for table_row in table_rows:
            table = str(table_row[0])
            if table.startswith("sqlite_"):
                continue
            safe_table = table.replace('"', '""')
            rows = connection.execute(f'SELECT * FROM "{safe_table}"').fetchall()
            tables[table] = [_jsonable(dict(row)) for row in rows]
        snapshot["tables"] = tables
    return snapshot


def build_forensic_bundle(trial_root: Path, analyzed: AnalyzedTrial) -> dict[str, object]:
    """Collect retained harness/SUT/provider/oracle evidence for a primary violation."""

    trace_path = trial_root / "trace.jsonl"
    trace_records: list[object] = []
    if trace_path.exists():
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            trace_records.append(json.loads(line))
    databases: dict[str, object] = {}
    for database in sorted(trial_root.rglob("*.sqlite")):
        relative = str(database.relative_to(trial_root))
        databases[relative] = _sqlite_snapshot(database)
    return {
        "protocol": "AG-LINEAGE-PREREG-v1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "analyzed_trial": _jsonable(asdict(analyzed)),
        "harness_trace": trace_records,
        "sqlite_evidence": databases,
    }


def write_forensic_bundle(trial_root: Path, analyzed: AnalyzedTrial) -> Path | None:
    if not analyzed.primary_violation or analyzed.observation.harness_invalid:
        return None
    output = trial_root / "forensic-primary-violation.json"
    with output.open("x", encoding="utf-8") as handle:
        json.dump(build_forensic_bundle(trial_root, analyzed), handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output
