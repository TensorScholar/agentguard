from __future__ import annotations

import gc
import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Iterator

import pytest

from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.research.authorization_lineage.canonical import (
    CanonicalStudySession,
    ConfirmatorySessionError,
    ReplacementExhaustedError,
    ReplacementRequiredError,
    _hash_tree,
)
from agentguard.research.authorization_lineage.harness import DevTrialHarness
from agentguard.research.authorization_lineage.ledger import AuthorizationInstanceLedger
from agentguard.research.authorization_lineage.models import (
    Arm,
    ProviderStratum,
    Schedule,
    TrialObservation,
    TrialSpec,
)
from agentguard.research.authorization_lineage.trace import (
    HarnessInvalidReason,
    TrialTraceRecorder,
    invalid_observation,
)


@pytest.fixture
def gc_disabled() -> Iterator[None]:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


@pytest.fixture
def cyclic_connection_tracker(monkeypatch):
    original_connect = sqlite3.connect
    live: dict[int, sqlite3.Connection] = {}

    class TrackingConnection(sqlite3.Connection):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self._tracker_cycle = self
            self._tracker_closed = False
            live[id(self)] = self

        def close(self) -> None:
            if not self._tracker_closed:
                self._tracker_closed = True
                live.pop(id(self), None)
                self._tracker_cycle = None
            super().close()

    def tracking_connect(*args, **kwargs):
        if "factory" in kwargs:
            raise AssertionError("unexpected sqlite3.connect factory override")
        return original_connect(*args, factory=TrackingConnection, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", tracking_connect)
    return live, original_connect


def _preflight() -> dict[str, object]:
    return {
        "protocol": "AG-LINEAGE-PREREG-v1.0",
        "status": "PASS",
        "expected_git_commit": "a" * 40,
        "actual_git_commit": "a" * 40,
        "actual_git_tree": "b" * 40,
        "runtime_identity_sha256": "c" * 64,
        "runtime_lock_sha256": "d" * 64,
        "runtime_dependencies": {"demo": "1"},
        "git_objects": {
            "schemas": "e" * 40,
            "protocol_clarification": "f" * 40,
        },
        "clarification_sha256": "1" * 64,
        "clarification_git_blob": "f" * 40,
        "runtime": {"python_version": "DEV"},
        "import_provenance": {"pythonpath": "", "sys_path": []},
    }


def _block(
    *,
    schedule: Schedule = Schedule.S3,
    provider: ProviderStratum = ProviderStratum.P2,
    prefix: str = "dev-sqlite-lifecycle",
) -> tuple[TrialSpec, TrialSpec, TrialSpec]:
    seed = hashlib.sha256(f"{prefix}|{provider.value}|{schedule.value}".encode()).hexdigest()
    common = {
        "provider": provider,
        "schedule": schedule,
        "replicate": 0,
        "block_seed": seed,
        "alpha": f"alpha-{prefix}",
        "effect_key": f"effect-{prefix}",
    }
    return (
        TrialSpec(
            trial_id=f"{prefix}-a0",
            arm=Arm.A0,
            execution_order=0,
            **common,
        ),
        TrialSpec(
            trial_id=f"{prefix}-a1",
            arm=Arm.A1,
            execution_order=1,
            **common,
        ),
        TrialSpec(
            trial_id=f"{prefix}-b4",
            arm=Arm.B4,
            execution_order=2,
            **common,
        ),
    )


def _observation(spec: TrialSpec) -> TrialObservation:
    return TrialObservation(
        trial_id=spec.trial_id,
        arm=spec.arm,
        provider=spec.provider,
        schedule=spec.schedule,
        replicate=spec.replicate,
        block_seed=spec.block_seed,
        alpha=spec.alpha,
        effect_key=spec.effect_key,
        root_or_slot_allocations=1,
        independent_live_slots_max=1,
        receipts_or_tickets=1,
        credentials=1,
        provider_sends=1,
        attempts=1,
        successor_admitted_while_predecessor_potentially_effectful=False,
        stale_reconciler_commit_accepted=False,
        legitimate_completion=True,
        unresolved=False,
        operator_interventions=0,
        reconciliation_calls=0,
        slot_hold_seconds=0.01,
        duration_seconds=0.01,
    )


class _ValidRunner:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, spec: TrialSpec) -> TrialObservation:
        trial_root = self.root / spec.trial_id
        trial_root.mkdir(parents=True)
        (trial_root / "evidence.txt").write_text(spec.trial_id, encoding="utf-8")
        return _observation(spec)


class _OracleStartupFailureRunner:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, spec: TrialSpec) -> TrialObservation:
        trial_root = self.root / spec.trial_id
        trial_root.mkdir(parents=True)
        trace = TrialTraceRecorder(trial_root / "trace.jsonl", spec)
        trace.event("harness.invalid", reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value)
        trace.close()
        return invalid_observation(spec, HarnessInvalidReason.ORACLE_UNAVAILABLE)


def _dev_session(
    root: Path,
    *,
    schedule: Schedule = Schedule.S3,
    provider: ProviderStratum = ProviderStratum.P2,
    prefix: str = "dev-sqlite-lifecycle",
) -> tuple[CanonicalStudySession, tuple[TrialSpec, TrialSpec, TrialSpec]]:
    block = _block(schedule=schedule, provider=provider, prefix=prefix)
    session = CanonicalStudySession.create_dev(
        study_root=root,
        study_execution_id=f"study-{prefix}",
        manifest=block,
        preflight_report=_preflight(),
    )
    return session, block


def _sidecars(root: Path) -> tuple[Path, ...]:
    return tuple(
        sorted(
            path
            for path in root.rglob("*")
            if path.is_file() and path.name.endswith(("-wal", "-shm", "-journal"))
        )
    )


def _row_count(connect, path: Path, table: str) -> int:
    with closing(connect(path)) as connection:
        row = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()
    assert row is not None
    return int(row[0])


def test_connection_helpers_explicitly_close_with_cyclic_gc_disabled(
    tmp_path,
    cyclic_connection_tracker,
    gc_disabled,
):
    live, _ = cyclic_connection_tracker

    state = SQLiteState(tmp_path / "state.sqlite")
    assert not live
    with state._connect() as connection:
        connection.execute("SELECT 1").fetchone()
    assert not live

    ledger = AuthorizationInstanceLedger(tmp_path / "lineage.sqlite")
    assert not live
    with ledger._connect() as connection:
        connection.execute("SELECT 1").fetchone()
    assert not live


def test_real_wal_trial_is_settled_and_authoritative_rehash_is_stable(
    tmp_path,
    cyclic_connection_tracker,
    gc_disabled,
):
    live, original_connect = cyclic_connection_tracker
    study_root = tmp_path / "study"
    session, block = _dev_session(study_root)

    selected = session.run_block(block, runner_factory=DevTrialHarness)

    assert not live
    assert _sidecars(study_root) == ()

    commitments = [
        (Path(str(payload["attempt_root"])), str(payload["evidence_tree_sha256"]))
        for payload in selected
    ]
    for attempt_root, expected in commitments:
        assert _hash_tree(attempt_root)[0] == expected

    agentguard_rows = sum(
        _row_count(original_connect, path, "authority_grants")
        for path in study_root.rglob("agentguard.sqlite")
    )
    provider_rows = sum(
        _row_count(original_connect, path, "operations")
        for path in study_root.rglob("provider.sqlite")
    )
    lineage_rows = sum(
        _row_count(original_connect, path, "authorization_instances")
        for path in study_root.rglob("lineage.sqlite")
    )
    oracle_rows = sum(
        _row_count(original_connect, path, "effects")
        for path in study_root.rglob("oracle.sqlite")
    )

    assert agentguard_rows > 0
    assert provider_rows > 0
    assert lineage_rows > 0
    assert oracle_rows > 0

    authoritative = session.authoritative_trials()
    assert len(authoritative) == 3
    assert not live
    assert _sidecars(study_root) == ()

    del authoritative
    del selected

    for attempt_root, expected in commitments:
        assert _hash_tree(attempt_root)[0] == expected

    assert len(session.authoritative_trials()) == 3
    assert not live
    assert _sidecars(study_root) == ()

    session.finalize()
    with pytest.raises(ConfirmatorySessionError, match="DEV commitment adapters") as exc:
        session.validate_for_report()
    assert "retained attempt evidence changed after durable finish" not in str(exc.value)


def test_replacement_cardinality_is_unchanged(tmp_path):
    session, block = _dev_session(tmp_path / "replacement", prefix="replacement")

    with pytest.raises(ReplacementRequiredError):
        session.run_block(block, runner_factory=_OracleStartupFailureRunner)

    with pytest.raises(ReplacementExhaustedError):
        session.run_block(block, runner_factory=_OracleStartupFailureRunner)


def test_tampered_retained_evidence_is_still_rejected(tmp_path):
    session, block = _dev_session(tmp_path / "tamper", prefix="tamper")
    session.run_block(block, runner_factory=_ValidRunner)

    selected = session.selected_attempt_payload(block[0])
    attempt_root = Path(str(selected["attempt_root"]))
    evidence = attempt_root / "runner" / block[0].trial_id / "evidence.txt"
    evidence.write_text("tampered", encoding="utf-8")

    with pytest.raises(ConfirmatorySessionError, match="retained attempt evidence changed"):
        session.authoritative_trials()


def test_s11_fenced_reconciliation_closes_all_parent_connections(
    tmp_path,
    cyclic_connection_tracker,
    gc_disabled,
):
    live, _ = cyclic_connection_tracker
    spec = TrialSpec(
        trial_id="dev-sqlite-s11-a0",
        arm=Arm.A0,
        provider=ProviderStratum.P2,
        schedule=Schedule.S11,
        replicate=0,
        block_seed=hashlib.sha256(b"dev-sqlite-s11").hexdigest(),
        execution_order=0,
        alpha="alpha-dev-sqlite-s11",
        effect_key="effect-dev-sqlite-s11",
    )

    observation = DevTrialHarness(tmp_path / "s11").run(spec)

    assert observation.stale_reconciler_commit_accepted is False
    assert not live
    assert _sidecars(tmp_path / "s11") == ()


def test_real_trial_settlement_repeats_ten_times_without_cyclic_gc(
    tmp_path,
    cyclic_connection_tracker,
    gc_disabled,
):
    live, _ = cyclic_connection_tracker

    for iteration in range(10):
        spec = TrialSpec(
            trial_id=f"dev-sqlite-repeat-{iteration}",
            arm=Arm.A0,
            provider=ProviderStratum.P2,
            schedule=Schedule.S0,
            replicate=iteration,
            block_seed=hashlib.sha256(f"repeat-{iteration}".encode()).hexdigest(),
            execution_order=0,
            alpha=f"alpha-repeat-{iteration}",
            effect_key=f"effect-repeat-{iteration}",
        )
        root = tmp_path / f"repeat-{iteration}"
        observation = DevTrialHarness(root).run(spec)
        assert observation.harness_invalid is False
        assert not live
        assert _sidecars(root) == ()
