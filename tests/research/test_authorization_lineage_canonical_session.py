from __future__ import annotations

import hashlib
import json
import random
import shutil
import sqlite3
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from decisionlock.research.authorization_lineage.canonical import (
    CanonicalStudySession,
    ConfirmatorySessionError,
    ConfirmatoryStudyInvalidError,
    GitRefCommitmentStore,
    MemoryCommitmentStore,
    ReplacementExhaustedError,
    ReplacementRequiredError,
    block_id,
    canonical_study_execution_id,
    canonical_trial_identity,
    manifest_identity_sha256,
    trial_identity_sha256,
)
from decisionlock.research.authorization_lineage.models import (
    APPLICABLE_STRATA,
    Arm,
    ProviderStratum,
    Schedule,
    TrialObservation,
    TrialSpec,
)
from decisionlock.research.authorization_lineage.trace import (
    HarnessInvalidReason,
    TrialTraceRecorder,
    invalid_observation,
)


def _block() -> tuple[TrialSpec, TrialSpec, TrialSpec]:
    seed = hashlib.sha256(b"DEV-CANONICAL-BLOCK").hexdigest()
    common = {
        "provider": ProviderStratum.P2,
        "schedule": Schedule.S3,
        "replicate": 0,
        "block_seed": seed,
        "alpha": "alpha-dev-canonical",
        "effect_key": "effect-dev-canonical",
    }
    return (
        TrialSpec(trial_id="dev-canonical-a0", arm=Arm.A0, execution_order=0, **common),
        TrialSpec(trial_id="dev-canonical-a1", arm=Arm.A1, execution_order=1, **common),
        TrialSpec(trial_id="dev-canonical-b4", arm=Arm.B4, execution_order=2, **common),
    )


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


class _TraceValidRunner(_ValidRunner):
    def run(self, spec: TrialSpec) -> TrialObservation:
        observation = super().run(spec)
        trial_root = self.root / spec.trial_id
        trace = TrialTraceRecorder(trial_root / "trace.jsonl", spec)
        trace.event("trial.observation", harness_invalid=False)
        trace.close()
        return observation


class _UnfavorableValidRunner(_TraceValidRunner):
    def run(self, spec: TrialSpec) -> TrialObservation:
        observation = super().run(spec)
        return replace(observation, independent_live_slots_max=2)


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


class _LateOracleFailureRunner:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, spec: TrialSpec) -> TrialObservation:
        trial_root = self.root / spec.trial_id
        trial_root.mkdir(parents=True)
        with sqlite3.connect(trial_root / "provider.sqlite") as connection:
            connection.execute(
                "CREATE TABLE operations(attempt_id TEXT PRIMARY KEY,effect_committed INTEGER,fenced INTEGER)"
            )
            connection.execute("INSERT INTO operations VALUES('a',0,0)")
        trace = TrialTraceRecorder(trial_root / "trace.jsonl", spec)
        trace.event("trial.observation", harness_invalid=False)
        trace.event("harness.invalid", reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value)
        trace.close()
        return replace(
            _observation(spec),
            harness_invalid=True,
            harness_invalid_reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value,
        )


class _OraclePreEffectFailureRunner:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, spec: TrialSpec) -> TrialObservation:
        trial_root = self.root / spec.trial_id
        trial_root.mkdir(parents=True)
        (trial_root / "a1").mkdir()
        with sqlite3.connect(trial_root / "a1" / "lineage.sqlite") as connection:
            connection.execute("CREATE TABLE registrations(alpha TEXT)")
            connection.execute("INSERT INTO registrations VALUES(?)", (spec.alpha,))
        trace = TrialTraceRecorder(trial_root / "trace.jsonl", spec)
        trace.event("schedule.enter", schedule=spec.schedule.value)
        trace.event("harness.invalid", reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value)
        trace.close()
        return invalid_observation(spec, HarnessInvalidReason.ORACLE_UNAVAILABLE)


class _OracleInterpretablePreEffectFailureRunner:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, spec: TrialSpec) -> TrialObservation:
        trial_root = self.root / spec.trial_id
        trial_root.mkdir(parents=True)
        (trial_root / "a1").mkdir()
        with sqlite3.connect(trial_root / "a1" / "lineage.sqlite") as connection:
            connection.execute("CREATE TABLE registrations(alpha TEXT)")
            connection.execute("INSERT INTO registrations VALUES(?)", (spec.alpha,))
        trace = TrialTraceRecorder(trial_root / "trace.jsonl", spec)
        trace.event("schedule.enter", schedule=spec.schedule.value)
        trace.event("sut.rejection", phase="pre-dispatch")
        trace.event("harness.invalid", reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value)
        trace.close()
        return invalid_observation(spec, HarnessInvalidReason.ORACLE_UNAVAILABLE)


class _OracleShutdownFailureRunner:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, spec: TrialSpec) -> TrialObservation:
        trial_root = self.root / spec.trial_id
        trial_root.mkdir(parents=True)
        trace = TrialTraceRecorder(trial_root / "trace.jsonl", spec)
        trace.event("trial.observation", harness_invalid=False)
        trace.event("harness.invalid", reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value)
        trace.close()
        return replace(
            _observation(spec),
            harness_invalid=True,
            harness_invalid_reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value,
        )


class _MachineFailureRunner:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, spec: TrialSpec) -> TrialObservation:
        raise OSError("dev machine failure")


class _LateMachineFailureRunner:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run(self, spec: TrialSpec) -> TrialObservation:
        trial_root = self.root / spec.trial_id
        trial_root.mkdir(parents=True)
        trace = TrialTraceRecorder(trial_root / "trace.jsonl", spec)
        trace.event("trial.observation", harness_invalid=False)
        trace.close()
        raise OSError("late dev machine failure")


def _session(
    tmp_path: Path,
) -> tuple[CanonicalStudySession, tuple[TrialSpec, TrialSpec, TrialSpec]]:
    block = _block()
    session = CanonicalStudySession.create_dev(
        study_root=tmp_path / "study",
        study_execution_id="dev-study-0001",
        manifest=block,
        preflight_report=_preflight(),
    )
    return session, block


def _full_synthetic_manifest() -> tuple[TrialSpec, ...]:
    trials: list[TrialSpec] = []
    for schedule in Schedule:
        for provider in APPLICABLE_STRATA[schedule]:
            for replicate in range(100):
                block_seed = hashlib.sha256(
                    f"DEV-PROD-BLOCK|{provider.value}|{schedule.value}|{replicate:03d}".encode()
                ).hexdigest()
                arms = list(Arm)
                random.Random(int(block_seed, 16)).shuffle(arms)
                alpha = f"DEV-PROD-ALPHA-{provider.value}-{schedule.value}-{replicate:03d}"
                effect_key = f"DEV-PROD-EFFECT-{provider.value}-{schedule.value}-{replicate:03d}"
                for execution_order, arm in enumerate(arms):
                    trials.append(
                        TrialSpec(
                            trial_id=(
                                f"dev-prod-{provider.value}-{schedule.value}-{replicate:03d}-"
                                f"{execution_order}-{arm.value}"
                            ),
                            arm=arm,
                            provider=provider,
                            schedule=schedule,
                            replicate=replicate,
                            block_seed=block_seed,
                            execution_order=execution_order,
                            alpha=alpha,
                            effect_key=effect_key,
                        )
                    )
    assert len(trials) == 10_800
    return tuple(trials)


def _production_target_block(
    manifest: tuple[TrialSpec, ...],
) -> tuple[TrialSpec, TrialSpec, TrialSpec]:
    block = tuple(
        spec
        for spec in manifest
        if spec.provider == ProviderStratum.P2
        and spec.schedule == Schedule.S3
        and spec.replicate == 0
    )
    assert len(block) == 3
    return tuple(sorted(block, key=lambda spec: spec.execution_order))  # type: ignore[return-value]


def _production_session(
    tmp_path: Path,
    monkeypatch,
    *,
    boundary_report: dict[str, object] | None = None,
) -> tuple[CanonicalStudySession, tuple[TrialSpec, TrialSpec, TrialSpec]]:
    import decisionlock.research.authorization_lineage.canonical as canonical

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    manifest = _full_synthetic_manifest()
    block = _production_target_block(manifest)
    registered = _preflight()
    calls = {"count": 0}

    def fake_preflight(**_kwargs):
        calls["count"] += 1
        if calls["count"] == 1 or boundary_report is None:
            return dict(registered)
        return dict(boundary_report)

    monkeypatch.setattr(canonical, "run_confirmatory_preflight", fake_preflight)
    session = CanonicalStudySession.create_confirmatory(
        repo_root=repo,
        study_parent=tmp_path / "canonical-studies",
        manifest=manifest,
        expected_manifest_sha256=manifest_identity_sha256(manifest),
        expected_git_commit="a" * 40,
    )
    return session, block


def test_complete_logical_trial_identity_is_bound():
    spec = _block()[0]
    identity = canonical_trial_identity(spec)
    assert set(identity) == {
        "trial_id",
        "arm",
        "provider",
        "schedule",
        "replicate",
        "block_seed",
        "execution_order",
        "alpha",
        "effect_key",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("alpha", "wrong-alpha"),
        ("effect_key", "wrong-effect"),
        ("arm", Arm.A1),
        ("provider", ProviderStratum.P3),
        ("schedule", Schedule.S7),
        ("block_seed", "0" * 64),
        ("execution_order", 2),
    ],
)
def test_same_trial_id_with_changed_frozen_identity_is_rejected(tmp_path, field, value):
    session, block = _session(tmp_path)
    forged = replace(block[0], **{field: value})
    with pytest.raises(ConfirmatorySessionError, match="manifest|block"):
        session.run_block((forged, block[1], block[2]), runner_factory=_ValidRunner)


def test_canonical_executor_runs_physical_zero_one_two(tmp_path):
    session, block = _session(tmp_path)
    selected = session.run_block((block[2], block[0], block[1]), runner_factory=_ValidRunner)
    assert [item["trial_identity"]["execution_order"] for item in selected] == [0, 1, 2]
    sequence = [json.loads(line) for line in session.sequence_ledger.read_text().splitlines()]
    starts = [item for item in sequence if item["event"] == "trial.start"]
    assert [item["payload"]["execution_order"] for item in starts] == [0, 1, 2]


def test_direct_runner_execution_is_not_admissible_confirmatory_evidence(tmp_path):
    session, block = _session(tmp_path)
    _ValidRunner(tmp_path / "rogue").run(block[0])
    with pytest.raises(ConfirmatorySessionError, match="no canonical attempt"):
        session.selected_attempt_payload(block[0])


def test_reconstructed_local_sequence_cannot_override_durable_lifecycle(tmp_path):
    session, block = _session(tmp_path)
    session.run_block(block, runner_factory=_ValidRunner)
    text = session.attempt_ledger.read_text(encoding="utf-8")
    session.attempt_ledger.write_text(
        text.replace("dev-canonical-a0", "forged-a0", 1), encoding="utf-8"
    )
    with pytest.raises(ConfirmatorySessionError, match="rewritten|payload"):
        session.run_block(block, runner_factory=_ValidRunner)


def test_copied_study_root_is_not_canonical(tmp_path):
    session, block = _session(tmp_path)
    session.run_block(block, runner_factory=_ValidRunner)
    copied = tmp_path / "copied-study"
    shutil.copytree(session.study_root, copied)
    with pytest.raises(ConfirmatorySessionError, match="root substitution"):
        CanonicalStudySession.load_confirmatory(
            repo_root=tmp_path,
            study_root=copied,
        )


def test_pre_effect_oracle_failure_allows_exactly_one_replacement(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(ReplacementRequiredError):
        session.run_block(block, runner_factory=_OracleStartupFailureRunner)
    original = session._finished_payloads(block[0])
    assert len(original) == 1
    assert original[0]["disposition"] == "invalid_non_interpretable"

    selected = session.run_block(block, runner_factory=_ValidRunner)
    assert len(session._finished_payloads(block[0])) == 2
    assert selected[0]["attempt_number"] == 2
    assert selected[0]["trial_identity_sha256"] == trial_identity_sha256(block[0])
    assert session._finished_payloads(block[0])[0]["attempt_id"].endswith(":attempt:1")


def test_second_replacement_is_rejected(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(ReplacementRequiredError):
        session.run_block(block, runner_factory=_OracleStartupFailureRunner)
    with pytest.raises(ReplacementExhaustedError):
        session.run_block(block, runner_factory=_OracleStartupFailureRunner)
    assert len(session._finished_payloads(block[0])) == 2


def test_replacement_after_valid_or_unfavorable_valid_result_is_rejected(tmp_path):
    session, block = _session(tmp_path)
    session.run_block(block, runner_factory=_ValidRunner)
    with pytest.raises(ConfirmatorySessionError, match="replacement|forbidden"):
        session._next_attempt_number(block[0])


def test_replacement_after_unfavorable_but_valid_result_is_rejected(tmp_path):
    session, block = _session(tmp_path)
    session.run_block(block, runner_factory=_UnfavorableValidRunner)
    assert session._finished_payloads(block[0])[0]["disposition"] == "valid"
    with pytest.raises(ConfirmatorySessionError, match="replacement|forbidden"):
        session._next_attempt_number(block[0])


def test_authorized_replacement_cannot_change_logical_identity(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(ReplacementRequiredError):
        session.run_block(block, runner_factory=_OracleStartupFailureRunner)
    forged = replace(block[0], alpha="different-alpha")
    with pytest.raises(ConfirmatorySessionError, match="manifest|block"):
        session.run_block((forged, block[1], block[2]), runner_factory=_ValidRunner)


def test_late_oracle_failure_is_study_level_not_selective_invalidation(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(ConfirmatoryStudyInvalidError, match="late_oracle"):
        session.run_block(block, runner_factory=_LateOracleFailureRunner)


def test_pre_interpretable_machine_failure_may_be_replaced(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(ReplacementRequiredError):
        session.run_block(block, runner_factory=_MachineFailureRunner)
    payload = session._finished_payloads(block[0])[0]
    assert payload["disposition"] == "invalid_non_interpretable"
    assert payload["phase"]["interpretable_state_reached"] is False


def test_post_interpretable_machine_failure_is_study_level(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(ConfirmatoryStudyInvalidError, match="late_external"):
        session.run_block(block, runner_factory=_LateMachineFailureRunner)


def test_forged_oracle_invalid_metadata_without_trace_evidence_is_rejected(tmp_path):
    class ForgedRunner(_ValidRunner):
        def run(self, spec: TrialSpec) -> TrialObservation:
            observation = super().run(spec)
            return replace(
                observation,
                harness_invalid=True,
                harness_invalid_reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value,
            )

    session, block = _session(tmp_path)
    with pytest.raises(ConfirmatorySessionError, match="mechanical trace evidence"):
        session.run_block(block, runner_factory=ForgedRunner)


def test_dev_session_cannot_emit_canonical_confirmatory_report(tmp_path):
    session, block = _session(tmp_path)
    session.run_block(block, runner_factory=_ValidRunner)
    session.finalize()
    with pytest.raises(ConfirmatorySessionError, match="DEV commitment adapters"):
        session.validate_for_report()


def test_git_ref_commitment_chain_is_compare_and_swap_append_only(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    store = GitRefCommitmentStore(repo, "dev-durable-study")
    first = store.append("study.register", {"x": 1})
    second = store.append("trial.start", {"x": 2})
    assert first != second
    records = store.verify()
    assert [record["event"] for record in records] == ["study.register", "trial.start"]
    assert records[1]["previous_oid"] == first
    assert store.head() == second


def test_manifest_identity_changes_when_any_scientific_identity_field_changes():
    block = _block()
    baseline = manifest_identity_sha256(block)
    assert manifest_identity_sha256((replace(block[0], alpha="other"), *block[1:])) != baseline
    assert manifest_identity_sha256((replace(block[0], effect_key="other"), *block[1:])) != baseline


def test_finalization_machine_failure_after_interpretable_state_is_study_level(
    tmp_path, monkeypatch
):
    import decisionlock.research.authorization_lineage.canonical as canonical

    session, block = _session(tmp_path)
    real_hash_tree = canonical._hash_tree
    calls = {"count": 0}

    def fail_once(root):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("finalization failure")
        return real_hash_tree(root)

    monkeypatch.setattr(canonical, "_hash_tree", fail_once)
    with pytest.raises(ConfirmatoryStudyInvalidError, match="late_external"):
        session.run_block(block, runner_factory=_TraceValidRunner)


def test_registered_preflight_file_tampering_is_rejected(tmp_path):
    session, block = _session(tmp_path)
    payload = json.loads((session.study_root / "preflight.json").read_text(encoding="utf-8"))
    payload["report"]["actual_git_tree"] = "9" * 40
    (session.study_root / "preflight.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ConfirmatorySessionError, match="preflight"):
        session.run_block(block, runner_factory=_ValidRunner)


def test_cross_study_attempt_ledger_stitching_is_rejected(tmp_path):
    first, block = _session(tmp_path / "first")
    first.run_block(block, runner_factory=_ValidRunner)
    second = CanonicalStudySession.create_dev(
        study_root=tmp_path / "second" / "study",
        study_execution_id="dev-study-0002",
        manifest=block,
        preflight_report=_preflight(),
    )
    shutil.copyfile(first.attempt_ledger, second.attempt_ledger)
    with pytest.raises(ConfirmatorySessionError, match="lifecycle|durable"):
        second.authoritative_trials()


def test_strict_analysis_has_no_arbitrary_evidence_or_sequence_root_api():
    import inspect

    from decisionlock.research.authorization_lineage.analysis import analyze_confirmatory_study

    parameters = inspect.signature(analyze_confirmatory_study).parameters
    assert "evidence_root" not in parameters
    assert "sequence_root" not in parameters


def test_boundary_preflight_drift_fails_before_runner_invocation(tmp_path, monkeypatch):
    drifted = dict(_preflight())
    drifted["actual_git_tree"] = "9" * 40
    session, block = _production_session(
        tmp_path,
        monkeypatch,
        boundary_report=drifted,
    )

    with pytest.raises(ConfirmatoryStudyInvalidError, match="preflight|tree"):
        session.run_block(block)

    assert not any(session.blocks_root.rglob("attempt-*"))
    events = [record["event"] for record in session.commitments.verify()]
    assert events == ["study.register"]


def test_boundary_preflight_unchanged_allows_execution(tmp_path, monkeypatch):
    session, block = _production_session(tmp_path, monkeypatch)
    selected = session.run_block(block)
    assert len(selected) == 3
    assert [item["trial_identity"]["execution_order"] for item in selected] == [0, 1, 2]


def test_canonical_session_constructor_cannot_bypass_factories(tmp_path):
    session, _ = _session(tmp_path)
    with pytest.raises(ConfirmatorySessionError, match="canonical factory"):
        CanonicalStudySession(
            repo_root=Path("."),
            study_root=tmp_path / "forged-session",
            manifest=session.manifest,
            record=session.record,
            commitment_store=session.commitments,
        )


def test_real_confirmatory_session_rejects_caller_supplied_runner(tmp_path, monkeypatch):
    session, block = _production_session(tmp_path, monkeypatch)
    with pytest.raises(ConfirmatorySessionError, match="does not accept caller-supplied runners"):
        session.run_block(block, runner_factory=_ValidRunner)


def test_dev_session_allows_injectable_runner(tmp_path):
    session, block = _session(tmp_path)
    selected = session.run_block(block, runner_factory=_ValidRunner)
    assert len(selected) == 3


def test_real_study_execution_id_is_deterministic_and_not_caller_overridable(tmp_path, monkeypatch):
    import inspect

    from decisionlock.research.authorization_lineage.analysis import create_confirmatory_session

    report = _preflight()
    session, _ = _production_session(tmp_path, monkeypatch)
    expected = canonical_study_execution_id(
        candidate_git_commit=str(report["actual_git_commit"]),
        candidate_git_tree=str(report["actual_git_tree"]),
        manifest_sha256=manifest_identity_sha256(session.manifest),
        preflight_digest_value=__import__(
            "decisionlock.research.authorization_lineage.preflight", fromlist=["preflight_digest"]
        ).preflight_digest(report),
        clarification_sha256=str(report["clarification_sha256"]),
    )
    assert session.record.study_execution_id == expected
    assert (
        "study_execution_id"
        not in inspect.signature(CanonicalStudySession.create_confirmatory).parameters
    )
    assert "study_execution_id" not in inspect.signature(create_confirmatory_session).parameters

    same = canonical_study_execution_id(
        candidate_git_commit="a" * 40,
        candidate_git_tree="b" * 40,
        manifest_sha256="c" * 64,
        preflight_digest_value="d" * 64,
        clarification_sha256="e" * 64,
    )
    assert same == canonical_study_execution_id(
        candidate_git_commit="a" * 40,
        candidate_git_tree="b" * 40,
        manifest_sha256="c" * 64,
        preflight_digest_value="d" * 64,
        clarification_sha256="e" * 64,
    )
    assert same != canonical_study_execution_id(
        candidate_git_commit="a" * 40,
        candidate_git_tree="b" * 40,
        manifest_sha256="f" * 64,
        preflight_digest_value="d" * 64,
        clarification_sha256="e" * 64,
    )


def test_caller_cannot_select_preferred_attempt_by_api(tmp_path):
    import inspect

    parameters = inspect.signature(CanonicalStudySession.selected_attempt_payload).parameters
    assert "attempt_id" not in parameters
    assert "attempt_number" not in parameters


def test_real_runner_ownership_cannot_be_weakened_by_commitment_store_swap(tmp_path, monkeypatch):
    session, block = _production_session(tmp_path, monkeypatch)
    forged = MemoryCommitmentStore(session.record.study_execution_id)
    registration = session.commitments.verify()[0]
    payload = dict(registration["payload"])
    payload.pop("local_ledger_record_sha256", None)
    forged.append("study.register", payload)
    session.commitments = forged
    with pytest.raises(ConfirmatorySessionError, match="adapter/ref substitution|GitRef"):
        session.run_block(block, runner_factory=_ValidRunner)


def test_attempt_execution_helper_cannot_be_called_outside_run_block(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(
        ConfirmatorySessionError, match="internal to CanonicalStudySession.run_block"
    ):
        session._run_attempt(block[0], runner_factory=_ValidRunner)


def test_confirmatory_report_caller_cannot_supply_analysis_payload():
    import inspect

    parameters = inspect.signature(CanonicalStudySession.emit_report).parameters
    assert set(parameters) == {"self"}


def test_confirmatory_report_has_no_caller_factory_bypass():
    from decisionlock.research.authorization_lineage.canonical import ConfirmatoryReport

    assert not hasattr(ConfirmatoryReport, "_from_canonical")


def test_partial_manifest_cannot_register_real_confirmatory_session(tmp_path, monkeypatch):
    import decisionlock.research.authorization_lineage.canonical as canonical

    repo = tmp_path / "repo-partial"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    monkeypatch.setattr(canonical, "run_confirmatory_preflight", lambda **_kwargs: _preflight())
    block = _block()
    with pytest.raises(ConfirmatorySessionError, match="exact full frozen manifest"):
        CanonicalStudySession.create_confirmatory(
            repo_root=repo,
            study_parent=tmp_path / "partial-studies",
            manifest=block,
            expected_manifest_sha256=manifest_identity_sha256(block),
            expected_git_commit="a" * 40,
        )


def test_confirmatory_report_cannot_be_constructed_by_dev_caller():
    from decisionlock.research.authorization_lineage.canonical import ConfirmatoryReport

    with pytest.raises(ConfirmatorySessionError, match="validated CanonicalStudySession"):
        ConfirmatoryReport(
            protocol="AG-LINEAGE-PREREG-v1.0",
            study_execution_id="dev-study",
            candidate_git_commit="a" * 40,
            candidate_git_tree="b" * 40,
            manifest_sha256="c" * 64,
            preflight_digest="d" * 64,
            clarification_sha256="e" * 64,
            durable_commitment_head="f" * 40,
            complete_trial_evidence_commitment="1" * 64,
            analysis={},
        )


def test_alternate_root_restart_cannot_re_register_same_durable_study_id(tmp_path):
    repo = tmp_path / "repo-alt"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    first = GitRefCommitmentStore(repo, "same-study-0001")
    first.append("study.register", {"root": "/first"})
    second = GitRefCommitmentStore(repo, "same-study-0001")
    with pytest.raises(ConfirmatorySessionError, match="already owns"):
        second.append("study.register", {"root": "/second"})


def test_replaced_evidence_plus_regenerated_local_hashes_still_fails_durable_binding(tmp_path):
    session, block = _session(tmp_path)
    session.run_block(block, runner_factory=_ValidRunner)
    attempt_root = session._attempt_root(block[0], 1)
    evidence = attempt_root / "runner" / block[0].trial_id / "evidence.txt"
    evidence.write_text("replaced", encoding="utf-8")
    with pytest.raises(ConfirmatorySessionError, match="evidence changed|rewritten|payload"):
        session.authoritative_trials()


def test_oracle_failure_immediately_before_effect_capable_operation_is_replaceable(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(ReplacementRequiredError):
        session.run_block(block, runner_factory=_OraclePreEffectFailureRunner)
    payload = session._finished_payloads(block[0])[0]
    assert payload["phase"]["effect_capable_started"] is False
    assert payload["disposition"] == "invalid_non_interpretable"


def test_pre_effect_oracle_failure_after_interpretable_state_cannot_be_replaced(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(ConfirmatoryStudyInvalidError, match="interpretable state"):
        session.run_block(block, runner_factory=_OracleInterpretablePreEffectFailureRunner)
    payload = session._finished_payloads(block[0])[0]
    assert payload["phase"]["effect_capable_started"] is False
    assert payload["phase"]["interpretable_state_reached"] is True
    assert payload["disposition"] == "invalid_interpretable"


def test_oracle_shutdown_failure_after_interpretable_outcome_is_study_level(tmp_path):
    session, block = _session(tmp_path)
    with pytest.raises(ConfirmatoryStudyInvalidError, match="late_oracle"):
        session.run_block(block, runner_factory=_OracleShutdownFailureRunner)


def test_physical_two_zero_one_then_reconstructed_sequence_is_rejected(tmp_path):
    session, block = _session(tmp_path)
    block_payload = {
        "block_id": block_id(block[0]),
        "block_seed": block[0].block_seed,
        "manifest_sha256": session.record.manifest_sha256,
    }
    block_sequence_sha = session._append_sequence("block.start", block_payload)
    session.commitments.append(
        "block.start",
        {**block_payload, "sequence_commitment_sha256": block_sequence_sha},
    )
    wrong_start = {
        "block_id": block_id(block[0]),
        "attempt_id": f"{block[2].trial_id}:attempt:1",
        "trial_identity_sha256": trial_identity_sha256(block[2]),
        "execution_order": 2,
    }
    wrong_sequence_sha = session._append_sequence("trial.start", wrong_start)
    session.commitments.append(
        "trial.start",
        {
            "trial_identity": canonical_trial_identity(block[2]),
            "trial_identity_sha256": trial_identity_sha256(block[2]),
            "sequence_commitment_sha256": wrong_sequence_sha,
        },
    )
    with pytest.raises(ConfirmatorySessionError, match="frozen order 0"):
        session._verify_durable_execution_order()
