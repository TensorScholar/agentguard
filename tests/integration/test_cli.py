from __future__ import annotations
import json
from pathlib import Path
from typer.testing import CliRunner
from agentguard.cli.app import app
from agentguard.demo import create_demo

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0rc1" in result.stdout


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
    assert payload["replay"] == "decision_receipt.replayed"


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
