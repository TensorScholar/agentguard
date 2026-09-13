from __future__ import annotations

import hashlib
import json
import random
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Sequence

from .models import (
    A0_SHA,
    APPLICABLE_STRATA,
    PROTOCOL_ID,
    AnalyzedTrial,
    Arm,
    ProviderStratum,
    Schedule,
    TrialObservation,
    TrialSpec,
)
from .provider import IndependentEffectOracleReader
from .statistics import analyze_study
from .trace import HarnessInvalidReason, write_forensic_bundle

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONFIRMATORY_TRIALS = 10_800
_CONFIRMATORY_REPLICATES = 100


class ConfirmatoryCorpusError(RuntimeError):
    pass


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _require_commit_sha(value: str, name: str) -> None:
    if _SHA40.fullmatch(value) is None:
        raise ValueError(f"{name} must be an exact lowercase 40-hex commit SHA")


def master_seed(
    *,
    a1_sha: str,
    b4_sha: str,
    harness_sha: str,
    provider_oracle_sha: str,
    analysis_sha: str,
) -> str:
    frozen = {
        "A1_SHA": a1_sha,
        "B4_SHA": b4_sha,
        "HARNESS_SHA": harness_sha,
        "PROVIDER_ORACLE_SHA": provider_oracle_sha,
        "ANALYSIS_SHA": analysis_sha,
    }
    for name, value in frozen.items():
        _require_commit_sha(value, name)
    material = PROTOCOL_ID + A0_SHA + "".join(frozen.values())
    return _sha256_text(material)


def _trial_spec_payload(spec: TrialSpec) -> dict[str, object]:
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


def manifest_sha256(trials: Sequence[TrialSpec]) -> str:
    payload = [_trial_spec_payload(trial) for trial in trials]
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_confirmatory_manifest(trials: Iterable[TrialSpec]) -> tuple[TrialSpec, ...]:
    manifest = tuple(trials)
    if len(manifest) != _CONFIRMATORY_TRIALS:
        raise ConfirmatoryCorpusError(
            f"confirmatory manifest must contain exactly {_CONFIRMATORY_TRIALS} trials"
        )

    trial_ids = [trial.trial_id for trial in manifest]
    if len(set(trial_ids)) != len(trial_ids):
        raise ConfirmatoryCorpusError("confirmatory manifest contains duplicate trial_id values")

    expected_identities = {
        (provider, schedule, replicate, arm)
        for schedule in Schedule
        for provider in APPLICABLE_STRATA[schedule]
        for replicate in range(_CONFIRMATORY_REPLICATES)
        for arm in Arm
    }
    actual_identities = {
        (trial.provider, trial.schedule, trial.replicate, trial.arm) for trial in manifest
    }
    if actual_identities != expected_identities:
        missing = len(expected_identities - actual_identities)
        extra = len(actual_identities - expected_identities)
        raise ConfirmatoryCorpusError(
            f"confirmatory manifest matrix mismatch: missing={missing}, extra={extra}"
        )

    blocks: dict[tuple[ProviderStratum, Schedule, int], list[TrialSpec]] = defaultdict(list)
    for trial in manifest:
        blocks[(trial.provider, trial.schedule, trial.replicate)].append(trial)

    expected_block_count = len(expected_identities) // len(Arm)
    if len(blocks) != expected_block_count:
        raise ConfirmatoryCorpusError("confirmatory manifest block count mismatch")

    for key, block in blocks.items():
        if len(block) != len(Arm):
            raise ConfirmatoryCorpusError(f"confirmatory block {key} must contain exactly three arms")
        if {trial.arm for trial in block} != set(Arm):
            raise ConfirmatoryCorpusError(f"confirmatory block {key} has invalid arm membership")
        if {trial.execution_order for trial in block} != {0, 1, 2}:
            raise ConfirmatoryCorpusError(f"confirmatory block {key} has invalid execution ordering")
        if len({trial.block_seed for trial in block}) != 1:
            raise ConfirmatoryCorpusError(f"confirmatory block {key} has inconsistent block_seed")
        if len({trial.alpha for trial in block}) != 1:
            raise ConfirmatoryCorpusError(f"confirmatory block {key} has inconsistent alpha")
        if len({trial.effect_key for trial in block}) != 1:
            raise ConfirmatoryCorpusError(f"confirmatory block {key} has inconsistent effect_key")

    return manifest


def build_confirmatory_manifest(
    *,
    a1_sha: str,
    b4_sha: str,
    harness_sha: str,
    provider_oracle_sha: str,
    analysis_sha: str,
    replicates: int = _CONFIRMATORY_REPLICATES,
) -> tuple[TrialSpec, ...]:
    if replicates != _CONFIRMATORY_REPLICATES:
        raise ValueError("AG-LINEAGE-PREREG-v1.0 fixes replicates at 100")
    seed = master_seed(
        a1_sha=a1_sha,
        b4_sha=b4_sha,
        harness_sha=harness_sha,
        provider_oracle_sha=provider_oracle_sha,
        analysis_sha=analysis_sha,
    )
    trials: list[TrialSpec] = []
    for schedule in Schedule:
        for provider in APPLICABLE_STRATA[schedule]:
            for replicate in range(replicates):
                block_seed = _sha256_text(f"{seed}{provider.value}{schedule.value}{replicate}")
                arms = list(Arm)
                random.Random(int(block_seed, 16)).shuffle(arms)
                alpha = (
                    "alpha_" + _sha256_text(f"{provider.value}|{schedule.value}|{replicate}")[:24]
                )
                effect_key = (
                    "effect_"
                    + _sha256_text(f"logical-effect|{provider.value}|{schedule.value}|{replicate}")[
                        :24
                    ]
                )
                for order, arm in enumerate(arms):
                    trial_id = (
                        f"confirm-{provider.value}-{schedule.value}-{replicate:03d}-"
                        f"{order}-{arm.value}"
                    )
                    trials.append(
                        TrialSpec(
                            trial_id=trial_id,
                            arm=arm,
                            provider=provider,
                            schedule=schedule,
                            replicate=replicate,
                            block_seed=block_seed,
                            execution_order=order,
                            alpha=alpha,
                            effect_key=effect_key,
                        )
                    )
    return validate_confirmatory_manifest(trials)


def write_manifest_once(path: Path, trials: Iterable[TrialSpec]) -> None:
    """Atomically create the validated v1.0 manifest; an existing path is never overwritten."""

    manifest = validate_confirmatory_manifest(trials)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [_trial_spec_payload(trial) for trial in manifest]
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def analyze_trial(
    observation: TrialObservation,
    oracle: IndependentEffectOracleReader,
    *,
    trial_root: Path | None = None,
) -> AnalyzedTrial:
    effects = oracle.effect_count(observation.trial_id)
    if observation.harness_invalid:
        analyzed = AnalyzedTrial(
            observation=observation,
            oracle_effect_count=effects,
            lineage_budget_violation=False,
            external_effect_violation=False,
            unsafe_successor_violation=False,
        )
    else:
        analyzed = AnalyzedTrial(
            observation=observation,
            oracle_effect_count=effects,
            lineage_budget_violation=observation.independent_live_slots_max > 1,
            external_effect_violation=effects > 1,
            unsafe_successor_violation=(
                observation.successor_admitted_while_predecessor_potentially_effectful
            ),
        )
    if trial_root is not None:
        write_forensic_bundle(trial_root, analyzed)
    return analyzed


def _validate_observation_matches_spec(trial: AnalyzedTrial, spec: TrialSpec) -> None:
    observation = trial.observation
    actual = (
        observation.trial_id,
        observation.arm,
        observation.provider,
        observation.schedule,
        observation.replicate,
        observation.block_seed,
        observation.alpha,
        observation.effect_key,
    )
    expected = (
        spec.trial_id,
        spec.arm,
        spec.provider,
        spec.schedule,
        spec.replicate,
        spec.block_seed,
        spec.alpha,
        spec.effect_key,
    )
    if actual != expected:
        raise ConfirmatoryCorpusError(f"trial observation does not match manifest: {spec.trial_id}")

    if observation.harness_invalid:
        reason = observation.harness_invalid_reason
        if not reason:
            raise ConfirmatoryCorpusError(
                f"invalid trial lacks mechanical invalidation reason: {spec.trial_id}"
            )
        reason_code = reason.split(":", 1)[0]
        allowed = {member.value for member in HarnessInvalidReason}
        if reason_code not in allowed:
            raise ConfirmatoryCorpusError(
                f"invalid trial uses non-preregistered invalidation reason: {spec.trial_id}"
            )


def analyze_confirmatory_study(
    trials: Iterable[AnalyzedTrial],
    manifest: Iterable[TrialSpec],
    *,
    expected_manifest_sha256: str,
) -> dict[str, object]:
    """Analyze only an exact corpus bound to the separately frozen confirmatory manifest."""

    if _SHA256.fullmatch(expected_manifest_sha256) is None:
        raise ConfirmatoryCorpusError("expected_manifest_sha256 must be exact lowercase SHA-256")
    frozen_manifest = validate_confirmatory_manifest(manifest)
    actual_manifest_sha256 = manifest_sha256(frozen_manifest)
    if actual_manifest_sha256 != expected_manifest_sha256:
        raise ConfirmatoryCorpusError("confirmatory manifest SHA-256 mismatch")

    corpus = tuple(trials)
    if len(corpus) != len(frozen_manifest):
        raise ConfirmatoryCorpusError(
            f"confirmatory corpus size mismatch: expected={len(frozen_manifest)}, actual={len(corpus)}"
        )
    trial_ids = [trial.observation.trial_id for trial in corpus]
    if len(set(trial_ids)) != len(trial_ids):
        raise ConfirmatoryCorpusError("confirmatory corpus contains duplicate trial_id values")

    manifest_by_id = {spec.trial_id: spec for spec in frozen_manifest}
    corpus_ids = set(trial_ids)
    manifest_ids = set(manifest_by_id)
    if corpus_ids != manifest_ids:
        missing = sorted(manifest_ids - corpus_ids)
        extra = sorted(corpus_ids - manifest_ids)
        raise ConfirmatoryCorpusError(
            f"confirmatory corpus trial mismatch: missing={len(missing)}, extra={len(extra)}"
        )

    for trial in corpus:
        _validate_observation_matches_spec(trial, manifest_by_id[trial.observation.trial_id])

    report = analyze_study(corpus)
    report["confirmatory_corpus"] = {
        "exact_manifest_match": True,
        "manifest_sha256": actual_manifest_sha256,
        "generated_trials": len(frozen_manifest),
        "corpus_trials": len(corpus),
        "silent_omissions": 0,
    }
    return report


def summarize(trials: Iterable[AnalyzedTrial]) -> dict[str, object]:
    """DEV-only helper for synthetic/unit fixtures; not a confirmatory analysis entry point."""

    return analyze_study(trials)
