from __future__ import annotations

import hashlib
import json
import random
import re
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

_SHA40 = re.compile(r"^[0-9a-f]{40}$")


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
    """Atomically create the v1.0 manifest; an existing path is never overwritten."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [asdict(trial) for trial in trials]
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


def analyze_trial(
    observation: TrialObservation,
    oracle: IndependentEffectOracleReader,
) -> AnalyzedTrial:
    effects = oracle.effect_count(observation.trial_id)
    if observation.harness_invalid:
        return AnalyzedTrial(
            observation=observation,
            oracle_effect_count=effects,
            lineage_budget_violation=False,
            external_effect_violation=False,
            unsafe_successor_violation=False,
        )
    # Raw root/grant count is a secondary endpoint. A second root can be a safe continuation of the
    # same slot under P1 or a P3 fenced transfer; P-M1 concerns independent effect opportunities.
    lineage_violation = observation.independent_live_slots_max > 1
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
    """Summarize retained observations without using SUT state as external-effect truth."""

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
        legitimate_completions = sum(
            item.oracle_effect_count == 1 and not item.observation.unresolved for item in items
        )
        cells[label] = {
            "n": len(items),
            "primary_violations": sum(item.primary_violation for item in items),
            "lineage_budget_violations": sum(item.lineage_budget_violation for item in items),
            "external_effect_violations": sum(item.external_effect_violation for item in items),
            "unsafe_successor_violations": sum(item.unsafe_successor_violation for item in items),
            "max_effect_count": max(item.oracle_effect_count for item in items),
            "max_independent_effect_opportunities": max(
                item.observation.independent_live_slots_max for item in items
            ),
            "max_root_or_slot_allocations": max(
                item.observation.root_or_slot_allocations for item in items
            ),
            "legitimate_completion_rate": legitimate_completions / len(items),
            "unresolved_rate": sum(item.observation.unresolved for item in items) / len(items),
        }
    return {"invalid_trials": invalid, "cells": cells}
