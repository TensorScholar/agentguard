from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from agentguard import __version__
from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import (
    Ed25519BrokerGrantVerifier,
    Ed25519Signer,
    Ed25519Verifier,
)
from agentguard.adapters.evidence import build_bundle, verify_bundle
from agentguard.adapters.protocols.mcp import MCPProtectedStdioProxy
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.application import AgentGuardService
from agentguard.domain import (
    ActionIntent,
    ApprovalReceipt,
    CredentialRequest,
    EnforcementMode,
    Principal,
)
from agentguard.engine.checkpoints import (
    AuditCheckpointError,
    issue_audit_checkpoint,
    verify_audit_checkpoint_signature,
)
from agentguard.engine.execution import authorize_execution
from agentguard.engine.policy import evaluate_policy
from agentguard.posture import EnforcementStatus, scan_enforcement_posture
from agentguard.security.files import read_regular_file, secure_atomic_write

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
    secure_atomic_write(output / "policy.yaml", read_regular_file(policy), mode=0o600)
    signer = Ed25519Signer.generate()
    signer.save_private(output / "decision-private.pem")
    signer.save_public(output / "decision-public.pem")
    broker_signer = Ed25519Signer.generate("mock-broker-ed25519")
    broker_signer.save_private(output / "broker-private.pem")
    broker_signer.save_public(output / "broker-public.pem")
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
    request: Path,
    receipt: Path,
    approval: Path | None = None,
    decision_key: Path = Path(".agentguard/decision-private.pem"),
    broker_key: Path = Path(".agentguard/broker-private.pem"),
    ledger: Path = Path(".agentguard/audit.sqlite"),
    output: Path = Path("credential-grant.json"),
) -> None:
    from agentguard.domain import DecisionReceipt

    intent = load_json_model(request, ActionIntent)
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
    decision_signer = Ed25519Signer.load_private(decision_key)
    decision_verifier = Ed25519Verifier({decision_signer.key_id: decision_signer.public_key()})
    broker_signer = Ed25519Signer.load_private(
        broker_key,
        key_id="mock-broker-ed25519",
    )
    broker = MockCredentialBroker(signer=broker_signer)
    service = AgentGuardService(
        decision_signer,
        decision_verifier,
        SQLiteState(ledger),
        broker.verifier,
    )
    grant = service.request_credential(intent, r, req, broker, a)
    write_json(output, grant)
    console.print(f"Issued opaque development grant {grant.issuance_id}")


@app.command("verify-execution")
def verify_execution(
    request: Path,
    receipt: Path,
    policy: Path,
    grant: Path | None = None,
    approval: Path | None = None,
    public_key: Path = Path(".agentguard/decision-public.pem"),
    broker_public_key: Path = Path(".agentguard/broker-public.pem"),
    broker: str = "mock-broker",
    ledger: Path = Path(".agentguard/audit.sqlite"),
) -> None:
    from agentguard.domain import CredentialGrant, DecisionReceipt

    intent = load_json_model(request, ActionIntent)
    r = load_json_model(receipt, DecisionReceipt)
    current_policy = load_policy(policy)
    g = load_json_model(grant, CredentialGrant) if grant else None
    a = load_json_model(approval, ApprovalReceipt) if approval else None
    verifier = Ed25519Verifier.from_public_file(public_key)
    broker_verifier = (
        Ed25519BrokerGrantVerifier.from_public_file(
            broker_public_key,
            broker_id=broker,
        )
        if g is not None
        else None
    )
    # Preserve --ledger for CLI compatibility, but preflight verification is intentionally
    # persistence-free and does not create or mutate execution state.
    del ledger
    authorize_execution(
        intent,
        r,
        g,
        verifier,
        None,
        broker_grant_verifier=broker_verifier,
        approval=a,
        current_policy=current_policy,
    )
    console.print(
        "Execution authority verified; nonce not consumed. "
        "Use protected execution to claim authority."
    )


@app.command()
def simulate(policy: Path, traces: Path) -> None:
    doc = load_policy(policy)
    counts = {"allow": 0, "deny": 0, "require_approval": 0, "invalid": 0}
    for line in read_regular_file(traces).decode("utf-8").splitlines():
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
    request: Path,
    receipt: Path,
    grant: Path | None = None,
    output: Path = Path("evidence"),
    key: Path | None = typer.Option(None, "--key"),
) -> None:
    artifacts = {
        "action-intent.json": json.loads(read_regular_file(request)),
        "decision-receipt.json": json.loads(read_regular_file(receipt)),
    }
    if grant:
        artifacts["credential-grant.json"] = json.loads(read_regular_file(grant))
    signer = Ed25519Signer.load_private(key) if key is not None else None
    build_bundle(output, artifacts, signer=signer)
    console.print(f"Built evidence bundle at {output}")


@app.command("evidence-verify")
def evidence_verify(
    output: Path,
    public_key: Path | None = typer.Option(None, "--public-key"),
    require_signature: bool = typer.Option(False, "--require-signature"),
) -> None:
    verifier = Ed25519Verifier.from_public_file(public_key) if public_key is not None else None
    ok, count = verify_bundle(
        output,
        verifier=verifier,
        require_signature=require_signature,
    )
    console.print_json(
        data={
            "ok": ok,
            "checked_artifacts": count,
            "signature_verified": verifier is not None,
        }
    )


@app.command("audit-checkpoint-create")
def audit_checkpoint_create(
    ledger: Path = Path(".agentguard/audit.sqlite"),
    key: Path = Path(".agentguard/decision-private.pem"),
    ledger_id: str = typer.Option("agentguard-local", "--ledger-id"),
    output: Path = Path("audit-checkpoint.json"),
) -> None:
    state = SQLiteState(ledger)
    ok, count, head, reason = state.verify()
    if not ok:
        raise typer.BadParameter(f"cannot checkpoint invalid audit chain: {reason}")
    checkpoint = issue_audit_checkpoint(
        ledger_id=ledger_id,
        event_count=count,
        head_hash=head,
        signer=Ed25519Signer.load_private(key),
    )
    write_json(output, checkpoint)
    console.print(f"Created signed audit checkpoint {checkpoint.checkpoint_id}")


@app.command("audit-checkpoint-verify")
def audit_checkpoint_verify(
    checkpoint: Path,
    ledger: Path = Path(".agentguard/audit.sqlite"),
    public_key: Path = Path(".agentguard/decision-public.pem"),
) -> None:
    from agentguard.domain import AuditCheckpoint

    value = load_json_model(checkpoint, AuditCheckpoint)
    try:
        verify_audit_checkpoint_signature(value, Ed25519Verifier.from_public_file(public_key))
    except AuditCheckpointError as exc:
        console.print_json(data={"ok": False, "reason": str(exc)})
        raise typer.Exit(1) from exc
    state = SQLiteState(ledger)
    ok, current_count, _, reason = state.verify()
    anchored_head = state.audit_head_at(value.event_count) if ok else None
    matches = ok and anchored_head == value.head_hash
    console.print_json(
        data={
            "ok": matches,
            "ledger_id": value.ledger_id,
            "checkpoint_events": value.event_count,
            "current_events": current_count,
            "reason": reason if not ok else (None if matches else "checkpoint.head_mismatch"),
        }
    )
    if not matches:
        raise typer.Exit(1)


@app.command("mcp-posture")
def mcp_posture(
    config: list[Path] = typer.Option(..., "--config"),
    output_format: str = typer.Option("markdown", "--format"),
    fail_on_bypass: bool = typer.Option(False, "--fail-on-bypass"),
) -> None:
    if output_format not in {"json", "markdown"}:
        raise typer.BadParameter("--format must be json or markdown")
    report = scan_enforcement_posture(config)
    if output_format == "json":
        console.print_json(data=report.model_dump(mode="json"))
    else:
        table = Table("Server", "Status", "Configuration", "Reasons")
        for route in report.routes:
            table.add_row(
                route.server_name,
                route.status.value,
                route.config_path,
                ", ".join(route.reason_codes),
            )
        console.print(table)
        console.print(
            f"Protected: {report.protected_count} | Direct: {report.direct_count} | "
            f"Ambiguous: {report.ambiguous_count} | Invalid: {report.invalid_count}"
        )
    if fail_on_bypass and (
        report.has_bypass
        or any(route.status != EnforcementStatus.PROTECTED for route in report.routes)
    ):
        raise typer.Exit(1)


@app.command(
    "mcp-proxy-v2", context_settings={"allow_extra_args": True, "ignore_unknown_options": True}
)
def mcp_proxy_v2(
    ctx: typer.Context,
    policy: Path = typer.Option(..., "--policy"),
    key: Path = typer.Option(Path(".agentguard/decision-private.pem"), "--key"),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    server_id: str = typer.Option(..., "--server-id"),
    agent_id: str = typer.Option("mcp-client", "--agent-id"),
    workload_id: str = typer.Option("mcp-stdio", "--workload-id"),
    tenant_id: str = typer.Option("local", "--tenant-id"),
    request_id_capacity: int = typer.Option(4096, "--request-id-capacity", min=1),
    schema_ttl_seconds: float = typer.Option(300.0, "--schema-ttl-seconds", min=0.001),
    execution_timeout_seconds: float = typer.Option(30.0, "--execution-timeout-seconds", min=0.001),
    shutdown_timeout_seconds: float = typer.Option(2.0, "--shutdown-timeout-seconds", min=0.0),
) -> None:
    """Run the explicit ENFORCE-only protected MCP 2025-03-26 stdio profile."""
    server_command = list(ctx.args)
    if server_command and server_command[0] == "--":
        server_command = server_command[1:]
    if not server_command:
        raise typer.BadParameter("mcp-proxy-v2 requires a server command after --")
    document = load_policy(policy)
    signer = Ed25519Signer.load_private(key)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    repository = SQLiteState(state)
    service = AgentGuardService(signer, verifier, repository)
    principal = Principal(
        agent_id=agent_id,
        workload_id=workload_id,
        tenant_id=tenant_id,
        identity_verified=False,
    )
    proxy = MCPProtectedStdioProxy(
        service,
        document,
        principal,
        server_id,
        server_command,
        request_id_capacity=request_id_capacity,
        schema_ttl_seconds=schema_ttl_seconds,
        execution_timeout_seconds=execution_timeout_seconds,
        shutdown_timeout_seconds=shutdown_timeout_seconds,
    )
    raise typer.Exit(proxy.run())


@app.command()
def demo(output: Path = Path(".agentguard/demo"), force: bool = False) -> None:
    from agentguard.demo import create_demo

    create_demo(output, force=force)
    console.print(f"Created meeting-ready demo at {output}")
