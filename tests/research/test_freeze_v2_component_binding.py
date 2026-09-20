"""Freeze v2 component binding tests (9-component MASTER_SEED model).

Covers the evidence-integrity expansion only: no confirmatory manifest is
written to disk, no seed artifacts are generated, and no scientific logic
(arms/harness/provider/canonical/confirmatory/trace/statistics) is touched.
All fixtures below are synthetic in-memory identities.
"""

from __future__ import annotations

import hashlib

import pytest

from agentguard.research.authorization_lineage.analysis import (
    build_confirmatory_manifest,
    manifest_sha256,
    master_seed,
)


def _component_shas(**overrides: str) -> dict[str, str]:
    """Nine distinct but valid lowercase 40-hex component identities."""
    shas = {
        "a1_sha": "0" * 40,
        "b4_sha": "1" * 40,
        "harness_sha": "2" * 40,
        "provider_oracle_sha": "3" * 40,
        "analysis_sha": "4" * 40,
        "canonical_sha": "5" * 40,
        "confirmatory_sha": "6" * 40,
        "trace_sha": "7" * 40,
        "evidence_store_sha": "8" * 40,
    }
    shas.update(overrides)
    return shas


def test_same_inputs_produce_identical_seed() -> None:
    assert master_seed(**_component_shas()) == master_seed(**_component_shas())


def test_missing_component_hash_fails_closed() -> None:
    for missing in (
        "canonical_sha",
        "confirmatory_sha",
        "trace_sha",
        "evidence_store_sha",
        "a1_sha",
    ):
        partial = _component_shas()
        del partial[missing]
        with pytest.raises(TypeError):
            master_seed(**partial)


def test_malformed_component_hash_fails_closed() -> None:
    with pytest.raises(ValueError, match="must be an exact lowercase 40-hex commit SHA"):
        master_seed(**_component_shas(canonical_sha="5" * 39))
    with pytest.raises(ValueError, match="must be an exact lowercase 40-hex commit SHA"):
        master_seed(**_component_shas(trace_sha="G" * 40))
    with pytest.raises(ValueError, match="must be an exact lowercase 40-hex commit SHA"):
        master_seed(**_component_shas(evidence_store_sha="8" * 40 + "extra"))


@pytest.mark.parametrize(
    "component",
    ["canonical_sha", "confirmatory_sha", "trace_sha", "evidence_store_sha"],
)
def test_changed_evidence_component_changes_master_seed(component: str) -> None:
    baseline = master_seed(**_component_shas())
    rotated = master_seed(**_component_shas(**{component: "a" * 40}))
    assert rotated != baseline


def test_changed_science_component_still_changes_master_seed() -> None:
    baseline = master_seed(**_component_shas())
    assert master_seed(**_component_shas(analysis_sha="b" * 40)) != baseline


def test_manifest_generation_receives_deterministic_seed_material() -> None:
    shas = _component_shas()
    manifest = build_confirmatory_manifest(**shas)
    assert len(manifest) == 10_800

    expected_seed = master_seed(**shas)
    first = manifest[0]
    expected_block_seed = hashlib.sha256(
        f"{expected_seed}{first.provider.value}{first.schedule.value}{first.replicate}".encode()
    ).hexdigest()
    assert first.block_seed == expected_block_seed

    repeat = build_confirmatory_manifest(**shas)
    assert manifest_sha256(repeat) == manifest_sha256(manifest)
    assert repeat[0].block_seed == first.block_seed


def test_rotated_evidence_component_changes_manifest_seed_material() -> None:
    baseline_first_block = build_confirmatory_manifest(**_component_shas())[0]
    rotated_seed = master_seed(**_component_shas(canonical_sha="a" * 40))
    rotated_block_seed = hashlib.sha256(
        f"{rotated_seed}{baseline_first_block.provider.value}"
        f"{baseline_first_block.schedule.value}"
        f"{baseline_first_block.replicate}".encode()
    ).hexdigest()
    assert rotated_block_seed != baseline_first_block.block_seed
