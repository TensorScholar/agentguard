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
from agentguard.adapters.reconciliation import DeterministicReconciler
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.application import AgentGuardService
from agentguard.domain import (
    ActionIntent,
    ApprovalReceipt,
    CapabilityScope,
    CredentialRequest,
    EnforcementMode,
    EvidenceTrustLevel,
    ExecutionAttestation,
    FieldProvenanceStatement,
    FieldReleaseType,
    Principal,
    ProvenanceLabel,
    ReconciliationEvidence,
    ReconciliationStatus,
)
from agentguard.engine.attestation import (
    AttestationVerificationError,
    verify_execution_attestation,
)
from agentguard.engine.authority import AuthorityError
from agentguard.engine.causal import (
    CausalIntegrityError,
    build_causal_execution_graph,
)
from agentguard.engine.checkpoints import (
    AuditCheckpointError,
    issue_audit_checkpoint,
    verify_audit_checkpoint_signature,
)
from agentguard.engine.execution import preflight_execution
from agentguard.engine.field_integrity import (
    issue_field_provenance_statement,
    issue_field_release,
    resolve_field_value,
)
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.policy_intelligence import (
    analyze_authority,
    analyze_policy_counterfactuals,
)
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
    attestation_signer = Ed25519Signer.generate("attestation-ed25519")
    attestation_signer.save_private(output / "attestation-private.pem")
    attestation_signer.save_public(output / "attestation-public.pem")
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    authority_signer.save_private(output / "authority-private.pem")
    authority_signer.save_public(output / "authority-public.pem")
    provenance_signer = Ed25519Signer.generate("provenance-ed25519")
    provenance_signer.save_private(output / "provenance-private.pem")
    provenance_signer.save_public(output / "provenance-public.pem")
    release_signer = Ed25519Signer.generate("field-release-ed25519")
    release_signer.save_private(output / "field-release-private.pem")
    release_signer.save_public(output / "field-release-public.pem")
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
    authority_public_key: Path = typer.Option(
        Path(".agentguard/authority-public.pem"), "--authority-public-key"
    ),
    provenance_public_key: Path = typer.Option(
        Path(".agentguard/provenance-public.pem"), "--provenance-public-key"
    ),
    field_release_public_key: Path = typer.Option(
        Path(".agentguard/field-release-public.pem"), "--field-release-public-key"
    ),
) -> None:
    intent = load_json_model(request, ActionIntent)
    doc = load_policy(policy)
    signer = Ed25519Signer.load_private(key)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    state = SQLiteState(ledger)
    authority_verifier = (
        Ed25519Verifier.from_public_file(authority_public_key, key_id="authority-ed25519")
        if intent.authority is not None
        else None
    )
    evaluation = evaluate_policy(doc, intent)
    needs_field_integrity = bool(intent.field_provenance or intent.field_releases) or any(
        rule.field_integrity for rule in evaluation.matched_rules
    )
    provenance_verifier = (
        Ed25519Verifier.from_public_file(provenance_public_key, key_id="provenance-ed25519")
        if needs_field_integrity
        else None
    )
    release_verifier = (
        Ed25519Verifier.from_public_file(field_release_public_key, key_id="field-release-ed25519")
        if needs_field_integrity
        else None
    )
    receipt = AgentGuardService(
        signer,
        verifier,
        state,
        authority_verifier=authority_verifier,
        provenance_verifier=provenance_verifier,
        release_verifier=release_verifier,
    ).authorize(intent, doc, mode=mode)
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
    provenance_public_key: Path = typer.Option(
        Path(".agentguard/provenance-public.pem"), "--provenance-public-key"
    ),
    field_release_public_key: Path = typer.Option(
        Path(".agentguard/field-release-public.pem"), "--field-release-public-key"
    ),
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
    evaluation = evaluate_policy(current_policy, intent)
    needs_field_integrity = bool(intent.field_provenance or intent.field_releases) or any(
        rule.field_integrity for rule in evaluation.matched_rules
    )
    provenance_verifier = (
        Ed25519Verifier.from_public_file(provenance_public_key, key_id="provenance-ed25519")
        if needs_field_integrity
        else None
    )
    release_verifier = (
        Ed25519Verifier.from_public_file(field_release_public_key, key_id="field-release-ed25519")
        if needs_field_integrity
        else None
    )
    causal_required = bool(intent.causal_parent_execution_ids) or any(
        rule.causal is not None for rule in evaluation.matched_rules
    )
    execution_repository = None
    if causal_required:
        if not ledger.is_file():
            raise typer.BadParameter(
                "causal preflight requires an existing --ledger containing parent executions"
            )
        execution_repository = SQLiteState(ledger)
    # Legacy/non-causal preflight remains persistence-free; no state is opened or created.
    preflight_execution(
        intent,
        r,
        g,
        verifier,
        None,
        broker_grant_verifier=broker_verifier,
        approval=a,
        current_policy=current_policy,
        provenance_verifier=provenance_verifier,
        release_verifier=release_verifier,
        execution_repository=execution_repository,
    )
    console.print(
        "Execution authority verified; nonce not consumed. "
        "Use protected execution to claim authority."
    )


@app.command("provenance-issue")
def provenance_issue(
    request: Path,
    field_path: str = typer.Option(..., "--field-path"),
    semantic_type: str = typer.Option(..., "--semantic-type"),
    label: list[ProvenanceLabel] = typer.Option(..., "--label"),
    key: Path = typer.Option(Path(".agentguard/provenance-private.pem"), "--key"),
    ttl_seconds: int = typer.Option(300, "--ttl-seconds", min=1, max=3600),
    parent_statement_id: list[str] = typer.Option([], "--parent-statement-id"),
    transformation: str | None = typer.Option(None, "--transformation"),
    output: Path = typer.Option(Path("field-provenance.json"), "--output"),
) -> None:
    intent = load_json_model(request, ActionIntent)
    signer = Ed25519Signer.load_private(key, key_id="provenance-ed25519")
    value = resolve_field_value(intent.arguments, field_path)
    statement = issue_field_provenance_statement(
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        tenant_id=intent.principal.tenant_id,
        field_path=field_path,
        value=value,
        semantic_type=semantic_type,
        labels=frozenset(label),
        signer=signer,
        parent_statement_ids=tuple(parent_statement_id),
        transformation=transformation,
        ttl_seconds=ttl_seconds,
    )
    write_json(output, statement)
    console.print(f"Issued signed provenance statement {statement.statement_id}")


@app.command("field-release-issue")
def field_release_issue(
    request: Path,
    statement: Path = typer.Option(..., "--statement"),
    release_type: FieldReleaseType = typer.Option(..., "--release-type"),
    reason: str = typer.Option(..., "--reason"),
    key: Path = typer.Option(Path(".agentguard/field-release-private.pem"), "--key"),
    ttl_seconds: int = typer.Option(120, "--ttl-seconds", min=1, max=900),
    output: Path = typer.Option(Path("field-release.json"), "--output"),
) -> None:
    intent = load_json_model(request, ActionIntent)
    provenance = load_json_model(statement, FieldProvenanceStatement)
    signer = Ed25519Signer.load_private(key, key_id="field-release-ed25519")
    release = issue_field_release(
        intent,
        provenance,
        release_type=release_type,
        reason=reason,
        signer=signer,
        ttl_seconds=ttl_seconds,
    )
    write_json(output, release)
    console.print(f"Issued typed field release {release.release_id}")


@app.command("causal-graph")
def causal_graph(
    execution_id: str = typer.Option(..., "--execution-id"),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    if not state.is_file():
        raise typer.BadParameter("causal graph requires an existing --state ledger")
    try:
        graph = build_causal_execution_graph(execution_id, SQLiteState(state))
    except CausalIntegrityError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if output is not None:
        write_json(output, graph)
    else:
        console.print_json(data=graph.model_dump(mode="json"))


@app.command("authority-analyze")
def authority_analyze(
    request: Path,
    scope: Path = typer.Option(..., "--scope"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    intent = load_json_model(request, ActionIntent)
    capability_scope = load_json_model(scope, CapabilityScope)
    analysis = analyze_authority(intent, capability_scope)
    if output is not None:
        write_json(output, analysis)
    else:
        console.print_json(data=analysis.model_dump(mode="json"))


@app.command("policy-counterfactual")
def policy_counterfactual(
    request: Path,
    policy: Path,
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    intent = load_json_model(request, ActionIntent)
    analysis = analyze_policy_counterfactuals(load_policy(policy), intent)
    if output is not None:
        write_json(output, analysis)
    else:
        console.print_json(data=analysis.model_dump(mode="json"))


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
        require_signature=require_signature or verifier is not None,
    )
    console.print_json(
        data={
            "ok": ok,
            "checked_artifacts": count,
            "signature_verified": verifier is not None and ok,
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


@app.command("attest-execution")
def attest_execution(
    execution_id: str = typer.Option(..., "--execution-id"),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    key: Path = typer.Option(Path(".agentguard/attestation-private.pem"), "--key"),
    output: Path = typer.Option(Path("execution-attestation.json"), "--output"),
) -> None:
    signer = Ed25519Signer.load_private(key, key_id="attestation-ed25519")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    repository = SQLiteState(state)
    service = AgentGuardService(signer, verifier, repository)
    attestation = service.issue_execution_attestation(execution_id, signer)
    write_json(output, attestation)
    console.print(f"Issued execution attestation {attestation.payload.attestation_id}")


@app.command("verify-attestation")
def verify_attestation(
    attestation: Path,
    public_key: Path = typer.Option(Path(".agentguard/attestation-public.pem"), "--public-key"),
) -> None:
    value = load_json_model(attestation, ExecutionAttestation)
    verifier = Ed25519Verifier.from_public_file(public_key, key_id=value.signer_key_id)
    try:
        verify_execution_attestation(value, verifier)
    except AttestationVerificationError as exc:
        console.print_json(data={"ok": False, "reason": str(exc)})
        raise typer.Exit(1) from exc
    console.print_json(
        data={
            "ok": True,
            "attestation_id": value.payload.attestation_id,
            "execution_id": value.payload.execution_id,
            "execution_state": value.payload.execution_state.value,
            "resolution": (
                value.payload.resolution.status.value
                if value.payload.resolution is not None
                else None
            ),
            "payload_digest": value.payload_digest,
            "signer_key_id": value.signer_key_id,
        }
    )


@app.command("reconcile-execution")
def reconcile_execution(
    execution_id: str = typer.Option(..., "--execution-id"),
    evidence: Path = typer.Option(..., "--evidence"),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    key: Path = typer.Option(Path(".agentguard/decision-private.pem"), "--key"),
) -> None:
    value = load_json_model(evidence, ReconciliationEvidence)
    if value.trust_level == EvidenceTrustLevel.PROVIDER_VERIFIED or value.status in {
        ReconciliationStatus.CONFIRMED_SUCCEEDED,
        ReconciliationStatus.CONFIRMED_FAILED,
    }:
        raise typer.BadParameter(
            "file-supplied evidence cannot assert provider-verified outcomes; "
            "use a trusted provider-specific reconciler"
        )
    signer = Ed25519Signer.load_private(key)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    service = AgentGuardService(signer, verifier, SQLiteState(state))
    resolution = service.reconcile_execution(execution_id, DeterministicReconciler(value))
    console.print_json(data=resolution.model_dump(mode="json"))


@app.command("authority-issue-root")
def authority_issue_root(
    principal: Path = typer.Option(..., "--principal"),
    scope: Path = typer.Option(..., "--scope"),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    key: Path = typer.Option(Path(".agentguard/authority-private.pem"), "--key"),
    ttl_seconds: int = typer.Option(3600, "--ttl-seconds", min=1, max=86400),
    output: Path = typer.Option(Path("authority-grant.json"), "--output"),
) -> None:
    subject = load_json_model(principal, Principal)
    capability_scope = load_json_model(scope, CapabilityScope)
    signer = Ed25519Signer.load_private(key, key_id="authority-ed25519")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    service = AgentGuardService(signer, verifier, SQLiteState(state), authority_verifier=verifier)
    grant = service.issue_root_authority(subject, capability_scope, signer, ttl_seconds=ttl_seconds)
    write_json(output, grant)
    console.print(f"Issued root authority {grant.grant_id}")


@app.command("authority-delegate")
def authority_delegate(
    parent_grant_id: str = typer.Option(..., "--parent-grant-id"),
    delegator: Path = typer.Option(..., "--delegator"),
    principal: Path = typer.Option(..., "--principal"),
    scope: Path = typer.Option(..., "--scope"),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    key: Path = typer.Option(Path(".agentguard/authority-private.pem"), "--key"),
    ttl_seconds: int = typer.Option(1800, "--ttl-seconds", min=1, max=86400),
    output: Path = typer.Option(Path("delegated-authority-grant.json"), "--output"),
) -> None:
    delegator_principal = load_json_model(delegator, Principal)
    subject = load_json_model(principal, Principal)
    capability_scope = load_json_model(scope, CapabilityScope)
    signer = Ed25519Signer.load_private(key, key_id="authority-ed25519")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    service = AgentGuardService(signer, verifier, SQLiteState(state), authority_verifier=verifier)
    grant = service.delegate_authority(
        parent_grant_id,
        delegator_principal,
        subject,
        capability_scope,
        signer,
        ttl_seconds=ttl_seconds,
    )
    write_json(output, grant)
    console.print(f"Delegated authority {grant.grant_id}")


@app.command("authority-lease")
def authority_lease(
    grant_id: str = typer.Option(..., "--grant-id"),
    holder: Path = typer.Option(..., "--holder"),
    maximum_uses: int = typer.Option(..., "--maximum-uses", min=1),
    ttl_seconds: int = typer.Option(300, "--ttl-seconds", min=1),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    key: Path = typer.Option(Path(".agentguard/authority-private.pem"), "--key"),
    output: Path = typer.Option(Path("capability-lease.json"), "--output"),
) -> None:
    holder_principal = load_json_model(holder, Principal)
    signer = Ed25519Signer.load_private(key, key_id="authority-ed25519")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    service = AgentGuardService(signer, verifier, SQLiteState(state), authority_verifier=verifier)
    lease = service.issue_capability_lease(
        grant_id, holder_principal, maximum_uses=maximum_uses, ttl_seconds=ttl_seconds
    )
    write_json(output, lease)
    console.print(f"Issued capability lease {lease.lease_id}")


@app.command("authority-reference")
def authority_reference(
    grant_id: str = typer.Option(..., "--grant-id"),
    lease_id: str = typer.Option(..., "--lease-id"),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    key: Path = typer.Option(Path(".agentguard/authority-private.pem"), "--key"),
    output: Path = typer.Option(Path("authority-reference.json"), "--output"),
) -> None:
    signer = Ed25519Signer.load_private(key, key_id="authority-ed25519")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    service = AgentGuardService(signer, verifier, SQLiteState(state), authority_verifier=verifier)
    reference = service.authority_reference(grant_id, lease_id)
    write_json(output, reference)
    console.print(f"Created authority reference for {grant_id}")


@app.command("authority-revoke")
def authority_revoke(
    grant_id: str = typer.Option(..., "--grant-id"),
    reason: str = typer.Option(..., "--reason"),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    key: Path = typer.Option(Path(".agentguard/authority-private.pem"), "--key"),
) -> None:
    signer = Ed25519Signer.load_private(key, key_id="authority-ed25519")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    service = AgentGuardService(signer, verifier, SQLiteState(state), authority_verifier=verifier)
    try:
        service.revoke_authority(grant_id, reason=reason)
    except AuthorityError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Revoked authority {grant_id} and active descendants")


@app.command("authority-lease-revoke")
def authority_lease_revoke(
    lease_id: str = typer.Option(..., "--lease-id"),
    state: Path = typer.Option(Path(".agentguard/action-integrity.sqlite"), "--state"),
    key: Path = typer.Option(Path(".agentguard/authority-private.pem"), "--key"),
) -> None:
    signer = Ed25519Signer.load_private(key, key_id="authority-ed25519")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    service = AgentGuardService(signer, verifier, SQLiteState(state), authority_verifier=verifier)
    service.revoke_capability_lease(lease_id)
    console.print(f"Revoked capability lease {lease_id}")


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
