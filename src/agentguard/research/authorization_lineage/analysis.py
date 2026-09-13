from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .models import (
    A0_SHA,
    APPLICABLE_STRATA,
    PROTOCOL_ID,
    AnalyzedTrial,
    Arm,
    Schedule,
    TrialObservation,
    TrialSpec,
)
from .provider import IndependentEffectOracleReader


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def master_seed(
    *,
    a1_sha: str,
    b4_sha: str,
    harness_sha: str,
    provider_oracle_sha: str,
    analysis_sha: str,
) -> str:
    values = (a1_sha, b4_sha, harness_sha, provider_oracle_sha, analysis_sha)
    if any(len(value) != 40 for value in values):
        raise ValueError("all frozen implementation identifiers must be 40-hex commit SHAs")
    material = PROTOCOL_ID + A0_SHA + "".join(values)
    return _sha256_text(material)


def build_confirmatory_manifest(
    *,
    a1_sha: str,
    b4_sha: str,
    harness_sha: str,
    provider_oracle_sha: str,
    analysis_sha: str,
    replicates: int = 100,
) -> tuple[TrialSpec, ...]:
    if replicates != 100:
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
                alpha = "alpha_" + _sha256_text(
                    f"{provider.value}|{schedule.value}|{replicate}"
                )[:24]
                effect_key = "effect_" + _sha256_text(
                    f"logical-effect|{provider.value}|{schedule.value}|{replicate}"
                )[:24]
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
                            alpha=alpha,
                            effect_key=effect_key,
                        )
                    )
    if len(trials) != 10_800:
        raise AssertionError(f"preregistered manifest must contain 10,800 trials, got {len(trials)}")
    return tuple(trials)


def write_manifest_once(path: Path, trials: Iterable[TrialSpec]) -> None:
    if path.exists():
        raise FileExistsError("confirmatory manifest is write-once")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(trial) for trial in trials]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


def analyze_trial(
    observation: TrialObservation,
    oracle: IndependentEffectOracleReader,
) -> AnalyzedTrial:
    if observation.harness_invalid:
        return AnalyzedTrial(
            observation=observation,
            oracle_effect_count=oracle.effect_count(observation.trial_id),
            lineage_budget_violation=False,
            external_effect_violation=False,
            unsafe_successor_violation=False,
        )
    effects = oracle.effect_count(observation.trial_id)
    lineage_violation = (
        observation.root_or_slot_allocations > 1 or observation.independent_live_slots_max > 1
    )
    return AnalyzedTrial(
        observation=observation,
        oracle_effect_count=effects,
        lineage_budget_violation=lineage_violation,
        external_effect_violation=effects > 1,
        unsafe_successor_violation=(
            observation.successor_admitted_while_predecessor_potentially_effectful
        ),
    )


def summarize(trials: Iterable[AnalyzedTrial]) -> dict[str, object]:
    grouped: dict[tuple[str, str, str], list[AnalyzedTrial]] = defaultdict(list)
    invalid = 0
    for trial in trials:
        if trial.observation.harness_invalid:
            invalid += 1
            continue
        key = (
            trial.observation.arm.value,
            trial.observation.provider.value,
            trial.observation.schedule.value,
        )
        grouped[key].append(trial)
    cells: dict[str, object] = {}
    for key, items in sorted(grouped.items()):
        label = "/".join(key)
        cells[label] = {
            "n": len(items),
            "primary_violations": sum(item.primary_violation for item in items),
            "lineage_budget_violations": sum(item.lineage_budget_violation for item in items),
            "external_effect_violations": sum(item.external_effect_violation for item in items),
            "unsafe_successor_violations": sum(item.unsafe_successor_violation for item in items),
            "max_effect_count": max(item.oracle_effect_count for item in items),
            "legitimate_completion_rate": (
                sum(item.observation.legitimate_completion for item in items) / len(items)
            ),
            "unresolved_rate": sum(item.observation.unresolved for item in items) / len(items),
        }
    return {"invalid_trials": invalid, "cells": cells}
