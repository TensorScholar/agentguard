from __future__ import annotations

import json
from pathlib import Path

from agentguard import __version__
from agentguard.adapters.evidence import EvidenceVerificationError
from agentguard.cli.app import app
from typer.testing import CliRunner

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_init_creates_keys_and_policy(tmp_path):
    out = tmp_path / "workspace"
    result = runner.invoke(app, ["init", "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    assert (out / "policy.yaml").is_file()
    assert (out / "decision-private.pem").is_file()
    assert (out / "decision-public.pem").is_file()


def test_demo_command(tmp_path):
    out = tmp_path / "demo"
    result = runner.invoke(app, ["demo", "--output", str(out)])
    assert result.exit_code == 0, result.stdout
    payload = json.loads((out / "results.json").read_text())
    assert payload["happy_path"] == "authorized"
    assert payload["argument_mutation"] == "execution.arguments_digest_mismatch"
    assert payload["excessive_scope"] == "credential.scope_exceeds_decision"
    assert payload["replay"] == "decision_receipt.replayed"


def test_verify_execution_is_non_consuming_preflight(tmp_path):
    root = Path(__file__).parents[2]
    workspace = tmp_path / "workspace"
    assert runner.invoke(app, ["init", "--output", str(workspace)]).exit_code == 0

    request = root / "src/agentguard/resources/demo-intent.json"
    policy = workspace / "policy.yaml"
    receipt = tmp_path / "receipt.json"
    ledger = tmp_path / "authorization.sqlite"
    authorize_result = runner.invoke(
        app,
        [
            "authorize",
            str(request),
            str(policy),
            "--key",
            str(workspace / "decision-private.pem"),
            "--ledger",
            str(ledger),
            "--output",
            str(receipt),
        ],
    )
    assert authorize_result.exit_code == 0, authorize_result.stdout

    grant = tmp_path / "grant.json"
    broker_result = runner.invoke(
        app,
        [
            "broker-demo",
            str(request),
            str(receipt),
            "--decision-key",
            str(workspace / "decision-private.pem"),
            "--broker-key",
            str(workspace / "broker-private.pem"),
            "--ledger",
            str(ledger),
            "--output",
            str(grant),
        ],
    )
    assert broker_result.exit_code == 0, broker_result.stdout

    unused_preflight_ledger = tmp_path / "preflight.sqlite"
    args = [
        "verify-execution",
        str(request),
        str(receipt),
        str(policy),
        "--grant",
        str(grant),
        "--public-key",
        str(workspace / "decision-public.pem"),
        "--broker-public-key",
        str(workspace / "broker-public.pem"),
        "--ledger",
        str(unused_preflight_ledger),
    ]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    assert first.exit_code == 0, first.stdout
    assert second.exit_code == 0, second.stdout
    assert "nonce not consumed" in first.stdout
    assert not unused_preflight_ledger.exists()


def test_explain_command(tmp_path):
    root = Path(__file__).parents[2]
    result = runner.invoke(
        app,
        [
            "explain",
            str(root / "examples/scoped-refund/request.json"),
            str(root / "examples/scoped-refund/policy.yaml"),
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "allow" in result.stdout.lower()
    assert "bounded-refund" in result.stdout


def test_cli_signed_evidence_checkpoint_and_posture(tmp_path):
    root = Path(__file__).parents[2]
    workspace = tmp_path / "workspace"
    assert runner.invoke(app, ["init", "--output", str(workspace)]).exit_code == 0

    receipt = tmp_path / "receipt.json"
    ledger = tmp_path / "audit.sqlite"
    authorize_result = runner.invoke(
        app,
        [
            "authorize",
            str(root / "src/agentguard/resources/demo-intent.json"),
            str(workspace / "policy.yaml"),
            "--key",
            str(workspace / "decision-private.pem"),
            "--ledger",
            str(ledger),
            "--output",
            str(receipt),
        ],
    )
    assert authorize_result.exit_code == 0, authorize_result.stdout

    evidence = tmp_path / "evidence"
    build_result = runner.invoke(
        app,
        [
            "evidence-build",
            str(root / "src/agentguard/resources/demo-intent.json"),
            str(receipt),
            "--output",
            str(evidence),
            "--key",
            str(workspace / "decision-private.pem"),
        ],
    )
    assert build_result.exit_code == 0, build_result.stdout
    verify_result = runner.invoke(
        app,
        [
            "evidence-verify",
            str(evidence),
            "--public-key",
            str(workspace / "decision-public.pem"),
            "--require-signature",
        ],
    )
    assert verify_result.exit_code == 0, verify_result.stdout
    assert '"ok": true' in verify_result.stdout.lower()

    checkpoint = tmp_path / "checkpoint.json"
    create_result = runner.invoke(
        app,
        [
            "audit-checkpoint-create",
            "--ledger",
            str(ledger),
            "--key",
            str(workspace / "decision-private.pem"),
            "--output",
            str(checkpoint),
        ],
    )
    assert create_result.exit_code == 0, create_result.stdout
    checkpoint_result = runner.invoke(
        app,
        [
            "audit-checkpoint-verify",
            str(checkpoint),
            "--ledger",
            str(ledger),
            "--public-key",
            str(workspace / "decision-public.pem"),
        ],
    )
    assert checkpoint_result.exit_code == 0, checkpoint_result.stdout

    protected_result = runner.invoke(
        app,
        [
            "mcp-posture",
            "--config",
            str(root / "examples/mcp_posture_protected.json"),
            "--format",
            "json",
            "--fail-on-bypass",
        ],
    )
    assert protected_result.exit_code == 0, protected_result.stdout

    bypass_result = runner.invoke(
        app,
        [
            "mcp-posture",
            "--config",
            str(root / "examples/mcp_posture_bypass.json"),
            "--fail-on-bypass",
        ],
    )
    assert bypass_result.exit_code == 1


def test_cli_simulate_audit_verify_and_refuse_overwrite(tmp_path):
    root = Path(__file__).parents[2]
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "existing").write_text("keep", encoding="utf-8")
    overwrite = runner.invoke(app, ["init", "--output", str(workspace)])
    assert overwrite.exit_code != 0

    traces = tmp_path / "traces.jsonl"
    valid = json.loads(
        (root / "src/agentguard/resources/demo-intent.json").read_text(encoding="utf-8")
    )
    traces.write_text(json.dumps(valid) + "\nnot-json\n", encoding="utf-8")
    simulation = runner.invoke(
        app,
        [
            "simulate",
            str(root / "src/agentguard/resources/default_policy_v2.yaml"),
            str(traces),
        ],
    )
    assert simulation.exit_code == 0, simulation.stdout
    assert '"invalid": 1' in simulation.stdout

    ledger = tmp_path / "empty.sqlite"
    audit = runner.invoke(app, ["audit-verify", "--ledger", str(ledger)])
    assert audit.exit_code == 0, audit.stdout


def test_evidence_verify_signature_semantics(tmp_path):
    root = Path(__file__).parents[2]
    workspace = tmp_path / "workspace"
    assert runner.invoke(app, ["init", "--output", str(workspace)]).exit_code == 0
    other = tmp_path / "other"
    assert runner.invoke(app, ["init", "--output", str(other)]).exit_code == 0

    request = root / "src/agentguard/resources/demo-intent.json"
    policy = workspace / "policy.yaml"
    receipt = tmp_path / "receipt.json"
    ledger = tmp_path / "audit.sqlite"
    authorize_result = runner.invoke(
        app,
        [
            "authorize",
            str(request),
            str(policy),
            "--key",
            str(workspace / "decision-private.pem"),
            "--ledger",
            str(ledger),
            "--output",
            str(receipt),
        ],
    )
    assert authorize_result.exit_code == 0, authorize_result.stdout

    unsigned = tmp_path / "unsigned"
    assert (
        runner.invoke(
            app, ["evidence-build", str(request), str(receipt), "--output", str(unsigned)]
        ).exit_code
        == 0
    )
    signed = tmp_path / "signed"
    assert (
        runner.invoke(
            app,
            [
                "evidence-build",
                str(request),
                str(receipt),
                "--output",
                str(signed),
                "--key",
                str(workspace / "decision-private.pem"),
            ],
        ).exit_code
        == 0
    )

    unsigned_no_key = runner.invoke(app, ["evidence-verify", str(unsigned)])
    assert unsigned_no_key.exit_code == 0, unsigned_no_key.stdout
    assert json.loads(unsigned_no_key.stdout)["signature_verified"] is False

    unsigned_with_key = runner.invoke(
        app,
        ["evidence-verify", str(unsigned), "--public-key", str(workspace / "decision-public.pem")],
    )
    assert unsigned_with_key.exit_code != 0
    assert isinstance(unsigned_with_key.exception, EvidenceVerificationError)
    assert "attestation_missing" in str(unsigned_with_key.exception)
    assert '"signature_verified": true' not in unsigned_with_key.stdout.lower()

    signed_correct_key = runner.invoke(
        app,
        ["evidence-verify", str(signed), "--public-key", str(workspace / "decision-public.pem")],
    )
    assert signed_correct_key.exit_code == 0, signed_correct_key.stdout
    assert json.loads(signed_correct_key.stdout)["signature_verified"] is True

    signed_wrong_key = runner.invoke(
        app, ["evidence-verify", str(signed), "--public-key", str(other / "decision-public.pem")]
    )
    assert signed_wrong_key.exit_code != 0
    assert isinstance(signed_wrong_key.exception, EvidenceVerificationError)
    assert '"signature_verified": true' not in signed_wrong_key.stdout.lower()

    signed_no_key = runner.invoke(app, ["evidence-verify", str(signed)])
    assert signed_no_key.exit_code == 0, signed_no_key.stdout
    assert json.loads(signed_no_key.stdout)["signature_verified"] is False

    require_missing = runner.invoke(app, ["evidence-verify", str(unsigned), "--require-signature"])
    assert require_missing.exit_code != 0
    assert isinstance(require_missing.exception, EvidenceVerificationError)
    assert "attestation_missing" in str(require_missing.exception)

    (signed / "decision-receipt.json").write_text('{"tampered": true}', encoding="utf-8")
    tampered = runner.invoke(
        app,
        ["evidence-verify", str(signed), "--public-key", str(workspace / "decision-public.pem")],
    )
    assert tampered.exit_code != 0
    assert isinstance(tampered.exception, EvidenceVerificationError)
    assert '"signature_verified": true' not in tampered.stdout.lower()
