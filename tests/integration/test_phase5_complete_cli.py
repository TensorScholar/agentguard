from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from agentguard.cli.app import app
from agentguard.domain import (
    CapabilityScope,
    FieldIntegrityConstraint,
    FieldProvenanceStatement,
    FieldReleaseReceipt,
    FieldReleaseType,
    ProvenanceLabel,
)

runner = CliRunner()


def _write(path: Path, model) -> None:
    path.write_text(model.model_dump_json(indent=2), encoding="utf-8")


def test_phase5_init_creates_separate_integrity_keys(tmp_path):
    workspace = tmp_path / "workspace"
    result = runner.invoke(app, ["init", "--output", str(workspace)])
    assert result.exit_code == 0, result.stdout
    for name in (
        "provenance-private.pem",
        "provenance-public.pem",
        "field-release-private.pem",
        "field-release-public.pem",
    ):
        assert (workspace / name).is_file()


def test_phase5_field_integrity_cli_round_trip(tmp_path, intent, policy):
    workspace = tmp_path / "workspace"
    assert runner.invoke(app, ["init", "--output", str(workspace)]).exit_code == 0
    request = tmp_path / "request.json"
    _write(request, intent)

    provenance = tmp_path / "provenance.json"
    result = runner.invoke(
        app,
        [
            "provenance-issue",
            str(request),
            "--field-path",
            "/order_id",
            "--semantic-type",
            "order_id",
            "--label",
            ProvenanceLabel.EXTERNAL_EMAIL.value,
            "--key",
            str(workspace / "provenance-private.pem"),
            "--output",
            str(provenance),
        ],
    )
    assert result.exit_code == 0, result.stdout

    statement = FieldProvenanceStatement.model_validate_json(provenance.read_text(encoding="utf-8"))
    request_with_statement = intent.model_copy(update={"field_provenance": (statement,)})
    request.write_text(request_with_statement.model_dump_json(indent=2), encoding="utf-8")

    release = tmp_path / "release.json"
    result = runner.invoke(
        app,
        [
            "field-release-issue",
            str(request),
            "--statement",
            str(provenance),
            "--release-type",
            FieldReleaseType.HUMAN_ENDORSEMENT.value,
            "--reason",
            "account owner confirmed",
            "--key",
            str(workspace / "field-release-private.pem"),
            "--output",
            str(release),
        ],
    )
    assert result.exit_code == 0, result.stdout

    protected = intent.model_copy(
        update={
            "field_provenance": (statement,),
            "field_releases": (
                FieldReleaseReceipt.model_validate_json(release.read_text(encoding="utf-8")),
            ),
        }
    )
    _write(request, protected)

    bounded = next(rule for rule in policy.rules if rule.id == "bounded-refund")
    bounded = bounded.model_copy(
        update={
            "credential": None,
            "field_integrity": (
                FieldIntegrityConstraint(
                    field_path="/order_id",
                    semantic_type="order_id",
                    denied_labels=frozenset({ProvenanceLabel.EXTERNAL_EMAIL}),
                    permitted_release_types=frozenset({FieldReleaseType.HUMAN_ENDORSEMENT}),
                ),
            ),
        }
    )
    field_policy = policy.model_copy(update={"rules": (bounded,)})
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(field_policy.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    receipt = tmp_path / "receipt.json"
    authorize = runner.invoke(
        app,
        [
            "authorize",
            str(request),
            str(policy_path),
            "--key",
            str(workspace / "decision-private.pem"),
            "--ledger",
            str(tmp_path / "state.sqlite"),
            "--provenance-public-key",
            str(workspace / "provenance-public.pem"),
            "--field-release-public-key",
            str(workspace / "field-release-public.pem"),
            "--output",
            str(receipt),
        ],
    )
    assert authorize.exit_code == 0, authorize.stdout
    value = json.loads(receipt.read_text(encoding="utf-8"))
    assert value["field_integrity_digest"].startswith("sha256:")
    assert value["field_release_set_digest"].startswith("sha256:")


def test_phase5_policy_intelligence_cli(tmp_path, intent, policy):
    request = tmp_path / "request.json"
    _write(request, intent)
    scope = CapabilityScope(
        capabilities=intent.action.capabilities | {"production_mutation"},
        protocols=frozenset({intent.action.protocol}),
        servers=frozenset({intent.action.server}),
        tools=frozenset({intent.action.tool}),
        operations=frozenset({intent.action.operation}),
        resource_types=frozenset({intent.resource.type}) if intent.resource else None,
        resource_ids=frozenset({intent.resource.id})
        if intent.resource and intent.resource.id
        else None,
        maximum_calls=10,
        delegable=True,
        maximum_delegation_depth=2,
    )
    scope_path = tmp_path / "scope.json"
    _write(scope_path, scope)
    analysis_path = tmp_path / "authority-analysis.json"
    result = runner.invoke(
        app,
        [
            "authority-analyze",
            str(request),
            "--scope",
            str(scope_path),
            "--output",
            str(analysis_path),
        ],
    )
    assert result.exit_code == 0, result.stdout
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    assert analysis["least_privilege"] is False
    assert analysis["findings"]

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(policy.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    counterfactual_path = tmp_path / "counterfactual.json"
    result = runner.invoke(
        app,
        [
            "policy-counterfactual",
            str(request),
            str(policy_path),
            "--output",
            str(counterfactual_path),
        ],
    )
    assert result.exit_code == 0, result.stdout
    value = json.loads(counterfactual_path.read_text(encoding="utf-8"))
    assert value["selected_rule_id"] == "bounded-refund"
    assert value["counterfactuals"][0]["removed_rule_id"] == "bounded-refund"
