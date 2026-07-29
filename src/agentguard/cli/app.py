from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from agentguard import __version__
from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.evidence import build_bundle, verify_bundle
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.application import AgentGuardService
from agentguard.domain import (
    ActionIntent,
    ApprovalReceipt,
    CredentialRequest,
    EnforcementMode,
)
from agentguard.engine.execution import authorize_execution
from agentguard.engine.policy import evaluate_policy

from .io import load_json_model, load_policy, write_json

app = typer.Typer(
    no_args_is_help=True,
    invoke_without_command=True,
    help="Decision-bound action integrity for AI agents",
    epilog=(
        "Preserved v0.1 commands: doctor, scan, gate, check-call, proxy, approve-call, "
        "approvals, mcp-proxy, report, verify-audit."
    ),
)
console = Console()


@app.callback()
def main(
    ctx: typer.Context, version: bool = typer.Option(False, "--version", is_eager=True)
) -> None:
    if version:
        typer.echo(f"agentguard {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command()
def init(output: Path = Path(".agentguard"), force: bool = False) -> None:
    if output.exists() and any(output.iterdir()) and not force:
        raise typer.BadParameter(f"refusing to overwrite non-empty {output}")
    output.mkdir(parents=True, exist_ok=True)
    policy = Path(__file__).parents[1] / "resources" / "default_policy_v2.yaml"
    (output / "policy.yaml").write_text(policy.read_text(encoding="utf-8"), encoding="utf-8")
    signer = Ed25519Signer.generate()
    signer.save_private(output / "decision-private.pem")
    signer.save_public(output / "decision-public.pem")
    console.print(f"Initialized AgentGuard workspace at {output}")


@app.command()
def authorize(
    request: Path,
    policy: Path,
    key: Path = Path(".agentguard/decision-private.pem"),
    ledger: Path = Path(".agentguard/audit.sqlite"),
    output: Path = Path("decision-receipt.json"),
    mode: EnforcementMode = EnforcementMode.ENFORCE,
) -> None:
    intent = load_json_model(request, ActionIntent)
    doc = load_policy(policy)
    signer = Ed25519Signer.load_private(key)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    state = SQLiteState(ledger)
    receipt = AgentGuardService(signer, verifier, state).authorize(intent, doc, mode=mode)
    write_json(output, receipt)
    console.print(f"{receipt.effect.value.upper()} — {receipt.decision_id}")
    if receipt.effect.value == "deny" and mode == EnforcementMode.ENFORCE:
        raise typer.Exit(1)


@app.command()
def explain(request: Path, policy: Path) -> None:
    intent = load_json_model(request, ActionIntent)
    result = evaluate_policy(load_policy(policy), intent)
    table = Table("Field", "Value")
    table.add_row("Decision", result.effect.value)
    table.add_row("Selected rule", result.selected_rule.id if result.selected_rule else "default")
    table.add_row("Matched rules", ", ".join(r.id for r in result.matched_rules) or "none")
    table.add_row("Reason codes", ", ".join(result.reason_codes))
    table.add_row("Policy digest", result.policy_digest)
    console.print(table)


@app.command()
def approve(
    request: Path,
    receipt: Path,
    approver: str = typer.Option(..., "--approver"),
    reason: str = typer.Option(..., "--reason"),
    authentication_level: str | None = typer.Option(None, "--authentication-level"),
    key: Path = Path(".agentguard/decision-private.pem"),
    ledger: Path = Path(".agentguard/audit.sqlite"),
    output: Path = Path("approval-receipt.json"),
) -> None:
    from agentguard.domain import DecisionReceipt

    intent = load_json_model(request, ActionIntent)
    decision = load_json_model(receipt, DecisionReceipt)
    signer = Ed25519Signer.load_private(key)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    state = SQLiteState(ledger)
    approval = AgentGuardService(signer, verifier, state).approve(
        intent,
        decision,
        approver_subject=approver,
        reason=reason,
        authentication_level=authentication_level,
    )
    write_json(output, approval)
    console.print(f"APPROVED — {approval.approval_id}")


@app.command("broker-demo")
def broker_demo(
    receipt: Path, approval: Path | None = None, output: Path = Path("credential-grant.json")
) -> None:
    from agentguard.domain import DecisionReceipt

    r = load_json_model(receipt, DecisionReceipt)
    a = load_json_model(approval, ApprovalReceipt) if approval else None
    if r.credential_ceiling is None:
        raise typer.BadParameter("receipt has no credential ceiling")
    req = CredentialRequest(
        request_id="credreq_" + r.request_id,
        trace_id=r.trace_id,
        decision_id=r.decision_id,
        audience=r.credential_ceiling.audience,
        scopes=r.credential_ceiling.scopes,
        requested_ttl_seconds=min(30, r.credential_ceiling.maximum_ttl_seconds),
        tenant_id=r.credential_ceiling.tenant_id,
        approval_id=a.approval_id if a else None,
    )
    grant = MockCredentialBroker().issue(r, req, a)
    write_json(output, grant)
    console.print(f"Issued opaque development grant {grant.issuance_id}")


@app.command("verify-execution")
def verify_execution(
    request: Path,
    receipt: Path,
    grant: Path | None = None,
    approval: Path | None = None,
    public_key: Path = Path(".agentguard/decision-public.pem"),
    ledger: Path = Path(".agentguard/audit.sqlite"),
) -> None:
    from agentguard.domain import CredentialGrant, DecisionReceipt

    intent = load_json_model(request, ActionIntent)
    r = load_json_model(receipt, DecisionReceipt)
    g = load_json_model(grant, CredentialGrant) if grant else None
    a = load_json_model(approval, ApprovalReceipt) if approval else None
    verifier = Ed25519Verifier.from_public_file(public_key)
    state = SQLiteState(ledger)
    authorize_execution(intent, r, g, verifier, state, approval=a)
    console.print("Execution authorized and receipt atomically consumed")


@app.command()
def simulate(policy: Path, traces: Path) -> None:
    doc = load_policy(policy)
    counts = {"allow": 0, "deny": 0, "require_approval": 0, "invalid": 0}
    for line in traces.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            intent = ActionIntent.model_validate_json(line)
            counts[evaluate_policy(doc, intent).effect.value] += 1
        except (TypeError, ValueError, ValidationError):
            counts["invalid"] += 1
    console.print_json(data=counts)


@app.command("audit-verify")
def audit_verify(ledger: Path = Path(".agentguard/audit.sqlite")) -> None:
    ok, count, head, reason = SQLiteState(ledger).verify()
    console.print_json(
        data={"ok": ok, "checked_events": count, "head_hash": head, "reason": reason}
    )
    if not ok:
        raise typer.Exit(1)


@app.command("evidence-build")
def evidence_build(
    request: Path, receipt: Path, grant: Path | None = None, output: Path = Path("evidence")
) -> None:
    artifacts = {
        "action-intent.json": json.loads(request.read_text()),
        "decision-receipt.json": json.loads(receipt.read_text()),
    }
    if grant:
        artifacts["credential-grant.json"] = json.loads(grant.read_text())
    build_bundle(output, artifacts)
    console.print(f"Built evidence bundle at {output}")


@app.command("evidence-verify")
def evidence_verify(output: Path) -> None:
    ok, count = verify_bundle(output)
    console.print_json(data={"ok": ok, "checked_artifacts": count})


@app.command()
def demo(output: Path = Path(".agentguard/demo"), force: bool = False) -> None:
    from agentguard.demo import create_demo

    create_demo(output, force=force)
    console.print(f"Created meeting-ready demo at {output}")
