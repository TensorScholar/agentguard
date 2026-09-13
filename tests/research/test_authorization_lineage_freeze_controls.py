from __future__ import annotations

import hashlib
import json
import random
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.research.authorization_lineage import preflight
from agentguard.research.authorization_lineage.analysis import (
    ConfirmatoryCorpusError,
    manifest_sha256,
    summarize,
    validate_confirmatory_corpus,
    validate_confirmatory_manifest,
)
from agentguard.research.authorization_lineage.models import (
    APPLICABLE_STRATA,
    AnalyzedTrial,
    Arm,
    Schedule,
    TrialObservation,
    TrialSpec,
)
from agentguard.research.authorization_lineage.preflight import (
    ConfirmatoryPreflightError,
    run_confirmatory_preflight,
)
from agentguard.research.authorization_lineage.trace import HarnessInvalidReason


def _synthetic_manifest() -> tuple[TrialSpec, ...]:
    trials: list[TrialSpec] = []
    for schedule in Schedule:
        for provider in APPLICABLE_STRATA[schedule]:
            for replicate in range(100):
                material = f"DEV-BLOCK|{provider.value}|{schedule.value}|{replicate:03d}"
                block = hashlib.sha256(material.encode()).hexdigest()
                alpha = f"DEV-ALPHA-{provider.value}-{schedule.value}-{replicate:03d}"
                effect_key = f"DEV-EFFECT-{provider.value}-{schedule.value}-{replicate:03d}"
                arms = list(Arm)
                random.Random(int(block, 16)).shuffle(arms)
                for execution_order, arm in enumerate(arms):
                    trials.append(
                        TrialSpec(
                            trial_id=(
                                f"dev-corpus-{provider.value}-{schedule.value}-{replicate:03d}-"
                                f"{execution_order}-{arm.value}"
                            ),
                            arm=arm,
                            provider=provider,
                            schedule=schedule,
                            replicate=replicate,
                            block_seed=block,
                            execution_order=execution_order,
                            alpha=alpha,
                            effect_key=effect_key,
                        )
                    )
    assert len(trials) == 10_800
    return tuple(trials)


def _analyzed(spec: TrialSpec) -> AnalyzedTrial:
    observation = TrialObservation(
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
    return AnalyzedTrial(
        observation=observation,
        oracle_effect_count=1,
        lineage_budget_violation=False,
        external_effect_violation=False,
        unsafe_successor_violation=False,
    )


def test_confirmatory_manifest_requires_unique_execution_order_per_block():
    manifest = list(_synthetic_manifest())
    manifest[1] = replace(manifest[1], execution_order=manifest[0].execution_order)
    with pytest.raises(ConfirmatoryCorpusError, match="execution ordering"):
        validate_confirmatory_manifest(manifest)


def test_confirmatory_manifest_order_must_match_block_seed():
    manifest = list(_synthetic_manifest())
    first = manifest[0]
    second = manifest[1]
    manifest[0] = replace(first, arm=second.arm)
    manifest[1] = replace(second, arm=first.arm)
    with pytest.raises(ConfirmatoryCorpusError, match="does not match block_seed"):
        validate_confirmatory_manifest(manifest)


def test_confirmatory_corpus_rejects_missing_duplicate_and_mismatched_trials():
    manifest = _synthetic_manifest()
    digest = manifest_sha256(manifest)
    corpus = tuple(_analyzed(spec) for spec in manifest)
    validated = validate_confirmatory_corpus(
        corpus,
        manifest,
        expected_manifest_sha256=digest,
    )
    assert len(validated) == 10_800

    with pytest.raises(ConfirmatoryCorpusError, match="corpus size mismatch"):
        validate_confirmatory_corpus(
            corpus[:-1],
            manifest,
            expected_manifest_sha256=digest,
        )

    duplicated = corpus[:-1] + (corpus[0],)
    with pytest.raises(ConfirmatoryCorpusError, match="duplicate trial_id"):
        validate_confirmatory_corpus(
            duplicated,
            manifest,
            expected_manifest_sha256=digest,
        )

    mismatched_observation = replace(corpus[0].observation, effect_key="DEV-MISMATCH")
    mismatched = (replace(corpus[0], observation=mismatched_observation),) + corpus[1:]
    with pytest.raises(ConfirmatoryCorpusError, match="does not match manifest"):
        validate_confirmatory_corpus(
            mismatched,
            manifest,
            expected_manifest_sha256=digest,
        )


def test_confirmatory_corpus_rejects_flag_only_invalidation():
    manifest = _synthetic_manifest()
    digest = manifest_sha256(manifest)
    corpus = tuple(_analyzed(spec) for spec in manifest)
    flag_only_observation = replace(
        corpus[0].observation,
        harness_invalid=True,
        harness_invalid_reason=None,
    )
    flag_only = (replace(corpus[0], observation=flag_only_observation),) + corpus[1:]
    with pytest.raises(ConfirmatoryCorpusError, match="lacks mechanical invalidation reason"):
        validate_confirmatory_corpus(
            flag_only,
            manifest,
            expected_manifest_sha256=digest,
        )

    mechanical_observation = replace(
        corpus[0].observation,
        harness_invalid=True,
        harness_invalid_reason=HarnessInvalidReason.TRACE_CORRUPT.value,
    )
    mechanical = (replace(corpus[0], observation=mechanical_observation),) + corpus[1:]
    assert (
        len(
            validate_confirmatory_corpus(
                mechanical,
                manifest,
                expected_manifest_sha256=digest,
            )
        )
        == 10_800
    )


def test_confirmatory_corpus_rejects_manifest_digest_drift():
    manifest = _synthetic_manifest()
    corpus = tuple(_analyzed(spec) for spec in manifest)
    with pytest.raises(ConfirmatoryCorpusError, match="manifest SHA-256 mismatch"):
        validate_confirmatory_corpus(
            corpus,
            manifest,
            expected_manifest_sha256="0" * 64,
        )


def test_holm_family_is_secondary_completion_and_primary_falsifiers_are_unadjusted():
    specs = [
        TrialSpec(
            trial_id=f"dev-holm-{arm.value}",
            arm=arm,
            provider=next(iter(APPLICABLE_STRATA[Schedule.S0])),
            schedule=Schedule.S0,
            replicate=0,
            block_seed="DEV-HOLM-BLOCK",
            execution_order=order,
            alpha="DEV-HOLM-ALPHA",
            effect_key="DEV-HOLM-EFFECT",
        )
        for order, arm in enumerate(Arm)
    ]
    report = summarize(_analyzed(spec) for spec in specs)
    paired = report["paired_A1_B4"]
    assert paired["holm_family"] == "legitimate-completion exact McNemar across provider strata"
    assert paired["primary_invariant_falsifiers_adjusted"] is False
    provider_report = paired["by_provider"][specs[0].provider.value]
    assert "completion_mcnemar_holm_p" in provider_report
    assert "primary_violation_mcnemar_holm_p" not in provider_report


def _write_preflight_identity(tmp_path: Path) -> Path:
    lock = tmp_path / "runtime-lock.txt"
    lock.write_text("demo-runtime==1.0\n", encoding="utf-8")
    fixture = tmp_path / "fixture.txt"
    fixture.write_text("fixture\n", encoding="utf-8")
    identity = {
        "protocol": "AG-LINEAGE-PREREG-v1.0",
        "runtime": {
            "python_implementation": "CPython",
            "python_version": "3.12.10",
            "system": "Darwin",
            "machine": "arm64",
            "macos_version": "26.5.2",
            "macos_build": "25F84",
            "pip_version": "26.2.1",
            "git_version": "2.44.0",
        },
        "lock": {
            "path": "runtime-lock.txt",
            "sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        },
        "git_objects": {
            "fixture": {
                "kind": "blob",
                "path": "fixture.txt",
                "sha": "fixture-blob",
            }
        },
    }
    identity_path = tmp_path / "identity.json"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")
    return identity_path


def _patch_preflight_environment(
    monkeypatch,
    *,
    repo_root: Path,
    head: str,
    demo_version: str = "1.0",
    status_output: str = "",
    agentguard_source: Path | None = None,
    sys_paths: tuple[Path, ...] | None = None,
) -> None:
    def fake_git(_root, *args):
        values = {
            ("rev-parse", "HEAD"): head,
            ("status", "--porcelain", "--untracked-files=all"): status_output,
            ("--version",): "git version 2.44.0",
            ("hash-object", "fixture.txt"): "fixture-blob",
        }
        return values[args]

    def fake_command(*args):
        values = {
            ("sw_vers", "-productVersion"): "26.5.2",
            ("sw_vers", "-buildVersion"): "25F84",
        }
        return values[args]

    def fake_version(name):
        if name == "pip":
            return "26.2.1"
        if name == "demo-runtime":
            return demo_version
        raise AssertionError(name)

    expected_source = agentguard_source or repo_root / "src" / "agentguard" / "__init__.py"
    expected_paths = sys_paths or (repo_root, repo_root / "src", Path(preflight.sys.prefix))
    monkeypatch.setattr(preflight, "_git", fake_git)
    monkeypatch.setattr(preflight, "_command", fake_command)
    monkeypatch.setattr(preflight, "_agentguard_source", lambda: expected_source.resolve())
    monkeypatch.setattr(
        preflight, "_runtime_sys_path", lambda: tuple(path.resolve() for path in expected_paths)
    )
    monkeypatch.setattr(preflight.platform, "python_implementation", lambda: "CPython")
    monkeypatch.setattr(preflight.platform, "python_version", lambda: "3.12.10")
    monkeypatch.setattr(preflight.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(preflight.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(preflight.importlib.metadata, "version", fake_version)
    monkeypatch.delenv("PYTHONPATH", raising=False)


def test_confirmatory_preflight_fails_closed_on_commit_drift(tmp_path, monkeypatch):
    expected = "a" * 40
    identity_path = _write_preflight_identity(tmp_path)
    _patch_preflight_environment(monkeypatch, repo_root=tmp_path, head=expected)
    report = run_confirmatory_preflight(
        repo_root=tmp_path,
        expected_git_commit=expected,
        identity_path=identity_path,
    )
    assert report["status"] == "PASS"

    _patch_preflight_environment(monkeypatch, repo_root=tmp_path, head="b" * 40)
    with pytest.raises(ConfirmatoryPreflightError, match="Git commit drift"):
        run_confirmatory_preflight(
            repo_root=tmp_path,
            expected_git_commit=expected,
            identity_path=identity_path,
        )


def test_confirmatory_preflight_fails_closed_on_dependency_drift(tmp_path, monkeypatch):
    expected = "a" * 40
    identity_path = _write_preflight_identity(tmp_path)
    _patch_preflight_environment(
        monkeypatch,
        repo_root=tmp_path,
        head=expected,
        demo_version="2.0",
    )
    with pytest.raises(ConfirmatoryPreflightError, match="runtime dependency drift"):
        run_confirmatory_preflight(
            repo_root=tmp_path,
            expected_git_commit=expected,
            identity_path=identity_path,
        )


@pytest.mark.parametrize("status", [" M tracked.py", "?? rogue.txt", "?? roguepkg/__init__.py"])
def test_confirmatory_preflight_rejects_tracked_and_untracked_drift(tmp_path, monkeypatch, status):
    expected = "a" * 40
    identity_path = _write_preflight_identity(tmp_path)
    _patch_preflight_environment(
        monkeypatch,
        repo_root=tmp_path,
        head=expected,
        status_output=status,
    )
    with pytest.raises(ConfirmatoryPreflightError, match="tracked or untracked drift"):
        run_confirmatory_preflight(
            repo_root=tmp_path,
            expected_git_commit=expected,
            identity_path=identity_path,
        )


def test_confirmatory_preflight_rejects_pythonpath_injection(tmp_path, monkeypatch):
    expected = "a" * 40
    identity_path = _write_preflight_identity(tmp_path)
    _patch_preflight_environment(monkeypatch, repo_root=tmp_path, head=expected)
    monkeypatch.setenv("PYTHONPATH", "/tmp/confirmatory-injection")
    with pytest.raises(ConfirmatoryPreflightError, match="PYTHONPATH"):
        run_confirmatory_preflight(
            repo_root=tmp_path,
            expected_git_commit=expected,
            identity_path=identity_path,
        )


def test_confirmatory_preflight_rejects_package_provenance_drift(tmp_path, monkeypatch):
    expected = "a" * 40
    identity_path = _write_preflight_identity(tmp_path)
    _patch_preflight_environment(
        monkeypatch,
        repo_root=tmp_path,
        head=expected,
        agentguard_source=tmp_path / "elsewhere" / "agentguard" / "__init__.py",
    )
    with pytest.raises(ConfirmatoryPreflightError, match="package provenance drift"):
        run_confirmatory_preflight(
            repo_root=tmp_path,
            expected_git_commit=expected,
            identity_path=identity_path,
        )


def test_confirmatory_preflight_rejects_unexpected_sys_path(tmp_path, monkeypatch):
    expected = "a" * 40
    identity_path = _write_preflight_identity(tmp_path)
    _patch_preflight_environment(
        monkeypatch,
        repo_root=tmp_path,
        head=expected,
        sys_paths=(tmp_path, tmp_path / "src", Path("/tmp/confirmatory-injection")),
    )
    with pytest.raises(ConfirmatoryPreflightError, match="import-path provenance"):
        run_confirmatory_preflight(
            repo_root=tmp_path,
            expected_git_commit=expected,
            identity_path=identity_path,
        )
