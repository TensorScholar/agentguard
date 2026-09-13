from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.research.authorization_lineage.analysis import analyze_trial
from agentguard.research.authorization_lineage.confirmatory import (
    ConfirmatoryEvidenceError,
    TrialExecutionEvidence,
    block_sequence_filename,
    derive_authoritative_trial,
    run_confirmatory_block,
    validate_block_execution,
    validate_block_records,
    verify_supplied_analysis,
)
from agentguard.research.authorization_lineage.harness import DevTrialHarness
from agentguard.research.authorization_lineage.models import (
    AnalyzedTrial,
    Arm,
    ProviderStratum,
    Schedule,
    TrialObservation,
    TrialSpec,
)
from agentguard.research.authorization_lineage.provider import IndependentEffectOracleReader
from agentguard.research.authorization_lineage.trace import HarnessInvalidReason


def _spec(
    arm: Arm,
    provider: ProviderStratum,
    schedule: Schedule,
    suffix: str,
    *,
    execution_order: int = 0,
    block_seed: str = "DEV-BLOCK",
) -> TrialSpec:
    return TrialSpec(
        trial_id=f"dev-confirmatory-{suffix}-{execution_order}-{arm.value}",
        arm=arm,
        provider=provider,
        schedule=schedule,
        replicate=0,
        block_seed=block_seed,
        execution_order=execution_order,
        alpha=f"alpha-dev-{suffix}",
        effect_key=f"effect-dev-{suffix}",
    )


def _execution(spec: TrialSpec, observation: TrialObservation) -> TrialExecutionEvidence:
    return TrialExecutionEvidence(
        spec=spec,
        observation=observation,
        preexisting_entries=(),
        external_machine_failure=None,
        evidence_sha256={},
    )


def _run_and_derive(tmp_path: Path, spec: TrialSpec) -> tuple[TrialObservation, AnalyzedTrial]:
    observation = DevTrialHarness(tmp_path).run(spec)
    trial_root = tmp_path / spec.trial_id
    authoritative = derive_authoritative_trial(
        _execution(spec, observation),
        trial_root=trial_root,
    )
    return observation, authoritative


def test_forged_p_m1_classification_is_rejected(tmp_path):
    spec = _spec(Arm.A0, ProviderStratum.P1, Schedule.S3, "pm1")
    _, authoritative = _run_and_derive(tmp_path, spec)
    assert authoritative.lineage_budget_violation
    forged = replace(authoritative, lineage_budget_violation=False)
    with pytest.raises(ConfirmatoryEvidenceError, match="P-M1"):
        verify_supplied_analysis(forged, authoritative)


def test_forged_p_m2_classification_is_rejected(tmp_path):
    spec = _spec(Arm.A0, ProviderStratum.P2, Schedule.S3, "pm2")
    _, authoritative = _run_and_derive(tmp_path, spec)
    assert authoritative.external_effect_violation
    forged = replace(authoritative, external_effect_violation=False)
    with pytest.raises(ConfirmatoryEvidenceError, match="P-M2"):
        verify_supplied_analysis(forged, authoritative)


def test_forged_p_m3_classification_is_rejected(tmp_path):
    spec = _spec(Arm.A0, ProviderStratum.P2, Schedule.S8, "pm3")
    _, authoritative = _run_and_derive(tmp_path, spec)
    assert authoritative.unsafe_successor_violation
    forged = replace(authoritative, unsafe_successor_violation=False)
    with pytest.raises(ConfirmatoryEvidenceError, match="P-M3"):
        verify_supplied_analysis(forged, authoritative)


def test_forged_oracle_effect_count_is_rejected(tmp_path):
    spec = _spec(Arm.A0, ProviderStratum.P1, Schedule.S3, "oracle")
    _, authoritative = _run_and_derive(tmp_path, spec)
    forged = replace(authoritative, oracle_effect_count=authoritative.oracle_effect_count + 1)
    with pytest.raises(ConfirmatoryEvidenceError, match="oracle_effect_count"):
        verify_supplied_analysis(forged, authoritative)


def test_authoritative_recomputation_matches_valid_retained_evidence(tmp_path):
    spec = _spec(Arm.A0, ProviderStratum.P2, Schedule.S8, "authoritative")
    observation, authoritative = _run_and_derive(tmp_path, spec)
    trial_root = tmp_path / spec.trial_id
    dev_analysis = analyze_trial(
        observation,
        IndependentEffectOracleReader(trial_root / "oracle.sqlite"),
    )
    assert authoritative == dev_analysis
    verify_supplied_analysis(dev_analysis, authoritative)


def test_mechanically_evidenced_dirty_namespace_invalidation_is_accepted(tmp_path):
    spec = _spec(Arm.A1, ProviderStratum.P2, Schedule.S0, "dirty")
    trial_root = tmp_path / spec.trial_id
    trial_root.mkdir(parents=True)
    (trial_root / "preexisting.txt").write_text("dirty", encoding="utf-8")
    observation = DevTrialHarness(tmp_path).run(spec)
    execution = TrialExecutionEvidence(
        spec=spec,
        observation=observation,
        preexisting_entries=("preexisting.txt",),
        external_machine_failure=None,
        evidence_sha256={},
    )
    authoritative = derive_authoritative_trial(execution, trial_root=trial_root)
    assert authoritative.observation.harness_invalid
    assert authoritative.observation.harness_invalid_reason is not None
    assert HarnessInvalidReason.DIRTY_NAMESPACE.value in authoritative.observation.harness_invalid_reason
    assert not authoritative.primary_violation


def test_reason_string_without_mechanical_evidence_is_rejected(tmp_path):
    spec = _spec(Arm.B4, ProviderStratum.P2, Schedule.S0, "forged-invalid")
    observation = DevTrialHarness(tmp_path).run(spec)
    forged_observation = replace(
        observation,
        harness_invalid=True,
        harness_invalid_reason=HarnessInvalidReason.TRACE_CORRUPT.value,
    )
    with pytest.raises(ConfirmatoryEvidenceError, match="unsubstantiated HARNESS_INVALID"):
        derive_authoritative_trial(
            _execution(spec, forged_observation),
            trial_root=tmp_path / spec.trial_id,
        )


def test_ordinary_outcome_cannot_be_changed_to_harness_invalid(tmp_path):
    spec = _spec(Arm.A1, ProviderStratum.P2, Schedule.S0, "ordinary")
    observation = DevTrialHarness(tmp_path).run(spec)
    trial_root = tmp_path / spec.trial_id
    authoritative = derive_authoritative_trial(_execution(spec, observation), trial_root=trial_root)
    forged_observation = replace(
        authoritative.observation,
        harness_invalid=True,
        harness_invalid_reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value,
    )
    forged = replace(authoritative, observation=forged_observation)
    with pytest.raises(ConfirmatoryEvidenceError, match="observation disagrees"):
        verify_supplied_analysis(forged, authoritative)


class _FakeRunner:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[int] = []

    def run(self, spec: TrialSpec) -> TrialObservation:
        self.calls.append(spec.execution_order)
        trial_root = self.root / spec.trial_id
        trial_root.mkdir(parents=True, exist_ok=True)
        (trial_root / "evidence.txt").write_text(
            f"{spec.trial_id}|{spec.execution_order}\n",
            encoding="utf-8",
        )
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


def _block() -> tuple[TrialSpec, TrialSpec, TrialSpec]:
    block_seed = hashlib.sha256(b"DEV-ORDER-BLOCK").hexdigest()
    return (
        _spec(Arm.A0, ProviderStratum.P2, Schedule.S3, "order", execution_order=0, block_seed=block_seed),
        _spec(Arm.A1, ProviderStratum.P2, Schedule.S3, "order", execution_order=1, block_seed=block_seed),
        _spec(Arm.B4, ProviderStratum.P2, Schedule.S3, "order", execution_order=2, block_seed=block_seed),
    )


def _load_records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_rehashed_records(path: Path, records: list[dict[str, object]]) -> None:
    previous = "0" * 64
    rendered: list[str] = []
    for sequence, original in enumerate(records, start=1):
        record = dict(original)
        record["sequence"] = sequence
        record["previous_hash"] = previous
        record.pop("record_hash", None)
        canonical = json.dumps(record, separators=(",", ":"), sort_keys=True)
        record_hash = hashlib.sha256(canonical.encode()).hexdigest()
        record["record_hash"] = record_hash
        rendered.append(json.dumps(record, separators=(",", ":"), sort_keys=True))
        previous = record_hash
    path.write_text("\n".join(rendered) + "\n", encoding="utf-8")


def test_actual_zero_one_two_execution_order_passes(tmp_path):
    block = _block()
    runner = _FakeRunner(tmp_path / "trials")
    sequence_root = tmp_path / "sequences"
    digest = "a" * 64
    run_confirmatory_block(
        (block[2], block[0], block[1]),
        runner=runner,
        expected_manifest_sha256=digest,
        sequence_root=sequence_root,
    )
    assert runner.calls == [0, 1, 2]
    validated = validate_block_execution(
        block,
        evidence_root=runner.root,
        expected_manifest_sha256=digest,
        sequence_root=sequence_root,
    )
    assert [item.spec.execution_order for item in validated] == [0, 1, 2]


def test_two_zero_one_runtime_sequence_fails(tmp_path):
    block = _block()
    runner = _FakeRunner(tmp_path / "trials")
    sequence_root = tmp_path / "sequences"
    digest = "b" * 64
    run_confirmatory_block(
        block,
        runner=runner,
        expected_manifest_sha256=digest,
        sequence_root=sequence_root,
    )
    path = sequence_root / block_sequence_filename(block[0])
    records = _load_records(path)
    pairs = [(records[1], records[2]), (records[3], records[4]), (records[5], records[6])]
    wrong = [records[0], *pairs[2], *pairs[0], *pairs[1], records[7]]
    _write_rehashed_records(path, wrong)
    with pytest.raises(ConfirmatoryEvidenceError, match="runtime trial order"):
        validate_block_execution(
            block,
            evidence_root=runner.root,
            expected_manifest_sha256=digest,
            sequence_root=sequence_root,
        )


def test_duplicated_or_skipped_execution_position_fails(tmp_path):
    block = _block()
    runner = _FakeRunner(tmp_path / "trials")
    sequence_root = tmp_path / "sequences"
    digest = "c" * 64
    run_confirmatory_block(
        block,
        runner=runner,
        expected_manifest_sha256=digest,
        sequence_root=sequence_root,
    )
    path = sequence_root / block_sequence_filename(block[0])
    records = _load_records(path)
    records[3]["execution_order"] = 0
    records[4]["execution_order"] = 0
    _write_rehashed_records(path, records)
    with pytest.raises(ConfirmatoryEvidenceError, match="execution_order"):
        validate_block_execution(
            block,
            evidence_root=runner.root,
            expected_manifest_sha256=digest,
            sequence_root=sequence_root,
        )


def test_execution_sequence_is_bound_to_trial_ids(tmp_path):
    block = _block()
    runner = _FakeRunner(tmp_path / "trials")
    sequence_root = tmp_path / "sequences"
    digest = "d" * 64
    run_confirmatory_block(
        block,
        runner=runner,
        expected_manifest_sha256=digest,
        sequence_root=sequence_root,
    )
    path = sequence_root / block_sequence_filename(block[0])
    records = _load_records(path)
    records[1]["trial_id"] = "forged-trial-id"
    _write_rehashed_records(path, records)
    with pytest.raises(ConfirmatoryEvidenceError, match="runtime trial order"):
        validate_block_execution(
            block,
            evidence_root=runner.root,
            expected_manifest_sha256=digest,
            sequence_root=sequence_root,
        )


def test_execution_sequence_record_tampering_fails_hash_chain(tmp_path):
    block = _block()
    runner = _FakeRunner(tmp_path / "trials")
    sequence_root = tmp_path / "sequences"
    digest = "e" * 64
    run_confirmatory_block(
        block,
        runner=runner,
        expected_manifest_sha256=digest,
        sequence_root=sequence_root,
    )
    path = sequence_root / block_sequence_filename(block[0])
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(block[0].trial_id, "tampered", 1), encoding="utf-8")
    with pytest.raises(ConfirmatoryEvidenceError, match="record hash mismatch"):
        validate_block_execution(
            block,
            evidence_root=runner.root,
            expected_manifest_sha256=digest,
            sequence_root=sequence_root,
        )


def test_validate_block_records_rejects_duplicate_trial_records(tmp_path):
    block = _block()
    runner = _FakeRunner(tmp_path / "trials")
    sequence_root = tmp_path / "sequences"
    digest = "f" * 64
    run_confirmatory_block(
        block,
        runner=runner,
        expected_manifest_sha256=digest,
        sequence_root=sequence_root,
    )
    path = sequence_root / block_sequence_filename(block[0])
    records = _load_records(path)
    records[3] = dict(records[1])
    records[4] = dict(records[2])
    with pytest.raises(ConfirmatoryEvidenceError, match="runtime trial order"):
        validate_block_records(records, block, expected_manifest_sha256=digest)
