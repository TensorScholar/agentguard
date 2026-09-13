from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentguard.research.authorization_lineage.analysis import analyze_trial
from agentguard.research.authorization_lineage.fence import ConventionalReconciliationFence
from agentguard.research.authorization_lineage.harness import DevTrialHarness
from agentguard.research.authorization_lineage.ledger import (
    AuthorizationInstanceLedger,
    LineageLedgerError,
)
from agentguard.research.authorization_lineage.models import (
    Arm,
    ProviderStratum,
    Schedule,
    TrialSpec,
)
from agentguard.research.authorization_lineage.provider import (
    IndependentEffectOracleReader,
    SimulatedProvider,
)


def _spec(arm: Arm, provider: ProviderStratum, schedule: Schedule, suffix: str) -> TrialSpec:
    return TrialSpec(
        trial_id=f"dev-{suffix}-{arm.value}-{provider.value}-{schedule.value}",
        arm=arm,
        provider=provider,
        schedule=schedule,
        replicate=0,
        block_seed="DEV-NOT-CONFIRMATORY",
        alpha=f"alpha-dev-{suffix}",
        effect_key=f"effect-dev-{suffix}",
    )


def test_authorization_instance_replay_reuses_one_slot(tmp_path):
    ledger = AuthorizationInstanceLedger(tmp_path / "lineage.sqlite")
    first = ledger.register("alpha-1", "effect-1")
    second = ledger.register("alpha-1", "effect-1")
    assert first.slot_id == second.slot_id
    assert ledger.counts("alpha-1")["root_or_slot_allocations"] == 1


def test_authorization_instance_effect_key_mismatch_fails_closed(tmp_path):
    ledger = AuthorizationInstanceLedger(tmp_path / "lineage.sqlite")
    ledger.register("alpha-1", "effect-1")
    with pytest.raises(LineageLedgerError, match="authorization_instance_mismatch"):
        ledger.register("alpha-1", "effect-2")


def test_p1_provider_deduplicates_business_effect_in_oracle(tmp_path):
    provider = SimulatedProvider(tmp_path / "provider.sqlite", tmp_path / "oracle.sqlite")
    for attempt in ("attempt-1", "attempt-2"):
        provider.accept(
            trial_id="trial-1",
            provider=ProviderStratum.P1,
            attempt_id=attempt,
            effect_key="effect-1",
            idempotency_key="idem-1",
        )
        provider.commit(attempt)
    oracle = IndependentEffectOracleReader(tmp_path / "oracle.sqlite")
    assert oracle.effect_count("trial-1") == 1


def test_p3_fence_prevents_delayed_predecessor_effect(tmp_path):
    provider = SimulatedProvider(tmp_path / "provider.sqlite", tmp_path / "oracle.sqlite")
    provider.accept(
        trial_id="trial-1",
        provider=ProviderStratum.P3,
        attempt_id="attempt-1",
        effect_key="effect-1",
        idempotency_key=None,
        delayed=True,
    )
    provider.set_delayed("attempt-1")
    evidence = provider.certify_no_effect_and_fence("attempt-1")
    assert evidence.no_effect_certified
    assert evidence.predecessor_fenced
    assert provider.release_delayed("attempt-1") is False
    assert IndependentEffectOracleReader(tmp_path / "oracle.sqlite").effect_count("trial-1") == 0


def test_b4_conventional_fence_rejects_stale_worker(tmp_path):
    fence = ConventionalReconciliationFence(tmp_path / "fence.sqlite")
    t0 = datetime.now(UTC)
    old = fence.claim("alpha-1", "old", now=t0, lease_seconds=1)
    new = fence.claim("alpha-1", "new", now=t0 + timedelta(seconds=2), lease_seconds=5)
    assert old is not None and new is not None
    assert not fence.commit_is_current(old, now=t0 + timedelta(seconds=2))
    assert fence.commit_is_current(new, now=t0 + timedelta(seconds=2))


def test_dev_a0_s3_reproduces_cross_root_lineage_gap(tmp_path):
    spec = _spec(Arm.A0, ProviderStratum.P2, Schedule.S3, "a0-s3")
    harness = DevTrialHarness(tmp_path)
    observation = harness.run(spec)
    analyzed = analyze_trial(
        observation,
        IndependentEffectOracleReader(tmp_path / spec.trial_id / "oracle.sqlite"),
    )
    assert observation.root_or_slot_allocations == 2
    assert analyzed.lineage_budget_violation
    assert analyzed.oracle_effect_count == 2
    assert analyzed.external_effect_violation


def test_dev_a1_s3_blocks_second_root_from_same_alpha(tmp_path):
    spec = _spec(Arm.A1, ProviderStratum.P2, Schedule.S3, "a1-s3")
    harness = DevTrialHarness(tmp_path)
    observation = harness.run(spec)
    analyzed = analyze_trial(
        observation,
        IndependentEffectOracleReader(tmp_path / spec.trial_id / "oracle.sqlite"),
    )
    assert observation.root_or_slot_allocations == 1
    assert analyzed.oracle_effect_count == 1
    assert not analyzed.primary_violation


def test_dev_b4_s3_blocks_second_slot_from_same_alpha(tmp_path):
    spec = _spec(Arm.B4, ProviderStratum.P2, Schedule.S3, "b4-s3")
    harness = DevTrialHarness(tmp_path)
    observation = harness.run(spec)
    analyzed = analyze_trial(
        observation,
        IndependentEffectOracleReader(tmp_path / spec.trial_id / "oracle.sqlite"),
    )
    assert observation.root_or_slot_allocations == 1
    assert analyzed.oracle_effect_count == 1
    assert not analyzed.primary_violation


def test_dev_p4_ambiguous_replacement_is_denied_by_b4(tmp_path):
    spec = _spec(Arm.B4, ProviderStratum.P4, Schedule.S8, "b4-p4")
    harness = DevTrialHarness(tmp_path)
    observation = harness.run(spec)
    analyzed = analyze_trial(
        observation,
        IndependentEffectOracleReader(tmp_path / spec.trial_id / "oracle.sqlite"),
    )
    assert analyzed.oracle_effect_count == 1
    assert not analyzed.unsafe_successor_violation
    assert not analyzed.external_effect_violation


def test_schedule_matrix_rejects_non_preregistered_pair():
    with pytest.raises(ValueError, match="outside preregistered matrix"):
        _spec(Arm.A0, ProviderStratum.P1, Schedule.S1, "invalid")
