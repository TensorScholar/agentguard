from __future__ import annotations

import hashlib

import pytest

from decisionlock.research.authorization_lineage.confirmatory import (
    ConfirmatoryEvidenceError,
    observation_payload,
    validate_block_records,
)
from decisionlock.research.authorization_lineage.models import (
    Arm,
    ProviderStratum,
    Schedule,
    TrialObservation,
    TrialSpec,
)


def _block() -> tuple[TrialSpec, TrialSpec, TrialSpec]:
    seed = hashlib.sha256(b"DEV-BLOCK-IDENTITY").hexdigest()
    common = {
        "provider": ProviderStratum.P2,
        "schedule": Schedule.S3,
        "replicate": 0,
        "block_seed": seed,
        "alpha": "alpha-dev-block-identity",
        "effect_key": "effect-dev-block-identity",
    }
    return (
        TrialSpec(trial_id="dev-block-A0", arm=Arm.A0, execution_order=0, **common),
        TrialSpec(trial_id="dev-block-A1", arm=Arm.A1, execution_order=1, **common),
        TrialSpec(trial_id="dev-block-B4", arm=Arm.B4, execution_order=2, **common),
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


def _records(block: tuple[TrialSpec, TrialSpec, TrialSpec], manifest_sha: str):
    first = block[0]
    block_id = "|".join(
        (first.provider.value, first.schedule.value, str(first.replicate), first.block_seed)
    )
    records: list[dict[str, object]] = [
        {
            "event": "block.start",
            "block_id": block_id,
            "manifest_sha256": manifest_sha,
            "block_seed": first.block_seed,
        }
    ]
    for spec in block:
        common = {
            "block_id": block_id,
            "manifest_sha256": manifest_sha,
            "trial_id": spec.trial_id,
            "block_seed": spec.block_seed,
            "execution_order": spec.execution_order,
        }
        records.append({"event": "trial.start", **common, "preexisting_entries": []})
        records.append(
            {
                "event": "trial.finish",
                **common,
                "observation": observation_payload(_observation(spec)),
                "evidence_sha256": {},
                "external_machine_failure": None,
            }
        )
    records.append(
        {
            "event": "block.finish",
            "block_id": block_id,
            "manifest_sha256": manifest_sha,
            "block_seed": first.block_seed,
        }
    )
    return records


def test_execution_sequence_is_bound_to_block_identity():
    block = _block()
    manifest_sha = "a" * 64
    records = _records(block, manifest_sha)
    validate_block_records(records, block, expected_manifest_sha256=manifest_sha)
    records[3]["block_id"] = "forged-block"
    with pytest.raises(ConfirmatoryEvidenceError, match="block identity"):
        validate_block_records(records, block, expected_manifest_sha256=manifest_sha)
