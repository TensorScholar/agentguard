from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ._meta import package_version
from .audit import AuditLedger, hash_tool_arguments
from .changed import ChangedConfigError, changed_config_paths
from .demo import write_demo
from .discovery import discover_config_paths, scan_configs
from .doctor import render_doctor_markdown, run_doctor
from .gate import scan_report_fails_gate
from .mcp_stdio import DEFAULT_INVENTORY_TTL_SECONDS, MCPStdioProxy
from .models import (
    ApprovalGrant,
    AuditChainVerification,
    AuditEvent,
    Decision,
    PolicyDecision,
    RiskLevel,
    ScanReport,
    ToolCall,
)
from .policy import load_policy
from .policy_packs import available_policy_packs, render_policy_pack
from .render import (
    render_audit_markdown,
    render_findings_summary_markdown,
    render_scan_markdown,
    scan_report_to_findings,
    to_json,
)
from .secrets import redact_value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard")
    parser.add_argument("--version", action="version", version=f"agentguard {package_version()}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a starter AgentGuard policy")
    init_parser.add_argument(
        "--pack",
        choices=available_policy_packs(),
        default="coding-agent-local",
        help="Policy pack to write",
    )
    init_parser.add_argument(
        "--output",
        default=".agentguard/policy.yaml",
        help="Policy file path to create",
    )
    init_parser.add_argument("--force", action="store_true", help="Overwrite an existing policy")

    demo_parser = subparsers.add_parser("demo", help="Create a self-contained local demo")
    demo_parser.add_argument(
        "--output",
        default=".agentguard/demo",
        help="Directory where demo files will be written",
    )
    demo_parser.add_argument("--force", action="store_true", help="Overwrite an existing demo")

    doctor_parser = subparsers.add_parser("doctor", help="Check local AgentGuard environment")
    doctor_parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    doctor_parser.add_argument("--workdir", help="Directory to check for local output writes")

    scan_parser = subparsers.add_parser("scan", help="Scan MCP/tool configs")
    scan_parser.add_argument(
        "--config", action="append", default=[], help="Path to MCP JSON config"
    )
    scan_parser.add_argument("--changed-from", help="Scan MCP configs changed since this git ref")
    scan_parser.add_argument("--head-ref", default="HEAD", help="Git head ref for --changed-from")
    scan_parser.add_argument(
        "--format", choices=["json", "markdown", "findings-json"], default="markdown"
    )
    scan_parser.add_argument("--output", help="Write report to this path instead of stdout")
    scan_parser.add_argument("--summary-output", help="Write concise markdown summary to this path")

    gate_parser = subparsers.add_parser(
        "gate", help="Fail CI when MCP/tool config risk is too high"
    )
    gate_parser.add_argument(
        "--config", action="append", default=[], help="Path to MCP JSON config"
    )
    gate_parser.add_argument(
        "--changed-from", help="Gate only MCP configs changed since this git ref"
    )
    gate_parser.add_argument("--head-ref", default="HEAD", help="Git head ref for --changed-from")
    gate_parser.add_argument(
        "--fail-on-risk",
        choices=[risk.value for risk in RiskLevel],
        default=RiskLevel.HIGH.value,
        help="Fail when highest discovered risk is at or above this level",
    )
    gate_parser.add_argument(
        "--format", choices=["json", "markdown", "findings-json"], default="markdown"
    )
    gate_parser.add_argument("--output", help="Write report to this path")
    gate_parser.add_argument("--summary-output", help="Write concise markdown summary to this path")

    check_parser = subparsers.add_parser("check-call", help="Evaluate one tool call")
    check_parser.add_argument("--policy", help="Path to policy.yaml")
    check_parser.add_argument("--tool", required=True, help="Tool name")
    check_parser.add_argument("--arg", action="append", default=[], help="Tool arg as key=value")
    check_parser.add_argument("--agent-id", default="local")
    check_parser.add_argument("--format", choices=["json", "markdown"], default="json")

    proxy_parser = subparsers.add_parser(
        "proxy", help="Enforce policy on JSONL tool calls from stdin"
    )
    proxy_parser.add_argument("--policy", help="Path to policy.yaml")
    proxy_parser.add_argument(
        "--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path"
    )

    approve_parser = subparsers.add_parser(
        "approve-call",
        help="Create an expiring local approval grant for one exact tool call",
    )
    approve_parser.add_argument(
        "--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path"
    )
    approve_parser.add_argument("--tool", required=True, help="Tool name")
    approve_parser.add_argument("--arg", action="append", default=[], help="Tool arg as key=value")
    approve_parser.add_argument("--agent-id", default="mcp-client")
    approve_parser.add_argument("--source", default="mcp_stdio")
    approve_parser.add_argument("--approved-by", required=True)
    approve_parser.add_argument("--reason", required=True)
    approve_parser.add_argument("--ttl-seconds", type=float, default=300.0)
    approve_parser.add_argument("--max-uses", type=int, default=1)
    approve_parser.add_argument("--format", choices=["json", "markdown"], default="markdown")

    approvals_parser = subparsers.add_parser("approvals", help="List local approval grants")
    approvals_parser.add_argument(
        "--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path"
    )
    approvals_parser.add_argument("--include-expired", action="store_true")
    approvals_parser.add_argument("--format", choices=["json", "markdown"], default="markdown")

    mcp_parser = subparsers.add_parser("mcp-proxy", help="Proxy an MCP stdio server with policy")
    mcp_parser.add_argument("--policy", help="Path to policy.yaml")
    mcp_parser.add_argument(
        "--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path"
    )
    mcp_parser.add_argument(
        "--agent-id", default="mcp-client", help="Agent/client label for audit logs"
    )
    mcp_parser.add_argument(
        "--max-message-bytes",
        type=int,
        default=1_000_000,
        help="Maximum JSON-RPC line size accepted from either side",
    )
    mcp_parser.add_argument(
        "--shutdown-timeout-seconds",
        type=float,
        default=2.0,
        help="Grace period before terminating a server that ignores stdin close",
    )
    mcp_parser.add_argument(
        "--inventory-ttl-seconds",
        type=float,
        default=DEFAULT_INVENTORY_TTL_SECONDS,
        help="Seconds to trust cached MCP tools/list inventory; 0 disables expiry",
    )
    mcp_parser.add_argument(
        "server_command", nargs=argparse.REMAINDER, help="-- MCP server command"
    )

    report_parser = subparsers.add_parser("report", help="Render an audit report")
    report_parser.add_argument(
        "--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path"
    )
    report_parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    report_parser.add_argument("--output", help="Write report to this path instead of stdout")

    verify_parser = subparsers.add_parser(
        "verify-audit", help="Verify audit ledger hash-chain integrity"
    )
    verify_parser.add_argument(
        "--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path"
    )
    verify_parser.add_argument("--format", choices=["json", "markdown"], default="markdown")

    args = parser.parse_args(argv)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "demo":
        return _cmd_demo(args)
    if args.command == "doctor":
        return _cmd_doctor(args)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "gate":
        return _cmd_gate(args)
    if args.command == "check-call":
        return _cmd_check_call(args)
    if args.command == "proxy":
        return _cmd_proxy(args)
    if args.command == "approve-call":
        return _cmd_approve_call(args)
    if args.command == "approvals":
        return _cmd_approvals(args)
    if args.command == "mcp-proxy":
        return _cmd_mcp_proxy(args)
    if args.command == "report":
        return _cmd_report(args)
    if args.command == "verify-audit":
        return _cmd_verify_audit(args)
    parser.error("unknown command")
    return 2


def _cmd_init(args: argparse.Namespace) -> int:
    output_path = Path(args.output)
    if output_path.exists() and not args.force:
        sys.stderr.write(f"Refusing to overwrite existing policy: {output_path}\n")
        sys.stderr.write("Use --force to replace it.\n")
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_policy_pack(args.pack), encoding="utf-8")
    sys.stdout.write(f"Wrote {args.pack} policy to {output_path}\n")
    sys.stdout.write(
        "Next: run agentguard mcp-proxy --policy "
        f"{output_path} -- --your-mcp-server-command\n"
    )
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    output_path = Path(args.output)
    try:
        written = write_demo(output_path, force=args.force)
    except FileExistsError as exc:
        sys.stderr.write(f"{exc}\n")
        sys.stderr.write("Use --force to replace it.\n")
        return 1

    sys.stdout.write(f"Wrote AgentGuard demo to {output_path}\n")
    for path in written:
        sys.stdout.write(f"- {path}\n")
    sys.stdout.write("Next: python -m agentguard.cli gate ")
    sys.stdout.write(f"--config {output_path / 'dangerous_mcp_config.json'} --fail-on-risk high\n")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    report = run_doctor(Path(args.workdir) if args.workdir else None)
    output = to_json(report) if args.format == "json" else render_doctor_markdown(report)
    _write_output(output, None)
    return 0 if report.ok else 1


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        paths = _config_paths_from_args(args)
    except ChangedConfigError as exc:
        sys.stderr.write(f"Failed to inspect changed configs: {exc}\n")
        return 2
    report = scan_configs(paths)
    output = _render_scan_report(report, args.format)
    _write_output(output, args.output)
    _write_summary_output(report, args.summary_output)
    return 0


def _cmd_gate(args: argparse.Namespace) -> int:
    try:
        paths = _config_paths_from_args(args)
    except ChangedConfigError as exc:
        sys.stderr.write(f"Failed to inspect changed configs: {exc}\n")
        return 2

    report = scan_configs(paths)
    output = _render_scan_report(report, args.format)
    _write_output(output, args.output)
    _write_summary_output(report, args.summary_output)

    threshold = RiskLevel(args.fail_on_risk)
    if scan_report_fails_gate(report, threshold):
        sys.stderr.write(
            f"AgentGuard gate failed: highest risk {report.highest_risk.value} "
            f"is at or above {threshold.value}\n"
        )
        return 1
    return 0


def _cmd_check_call(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    call = ToolCall(tool_name=args.tool, arguments=_parse_args(args.arg), agent_id=args.agent_id)
    decision = policy.evaluate(call)
    event = AuditEvent.from_decision(call, decision)
    if args.format == "markdown":
        sys.stdout.write(
            f"Decision: **{decision.decision.value}**\n\n"
            f"Rule: `{decision.rule_id}`\n\n"
            f"Reason: {decision.reason}\n"
        )
    else:
        sys.stdout.write(to_json(event) + "\n")
    return 0 if decision.allowed else 1


def _cmd_proxy(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    ledger = AuditLedger(Path(args.ledger))
    exit_code = 0
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            call = ToolCall(
                tool_name=str(payload["tool_name"]),
                arguments=dict(payload.get("arguments", {})),
                agent_id=str(payload.get("agent_id", "unknown")),
                source=str(payload.get("source", "jsonl")),
                call_id=str(payload.get("call_id", "")) or ToolCall(tool_name="tmp").call_id,
            )
            decision = policy.evaluate(call)
            decision = _apply_approval_grant(ledger, call, decision)
            event = AuditEvent.from_decision(call, decision)
            ledger.record(event)
            sys.stdout.write(to_json(event) + "\n")
            if not decision.allowed:
                exit_code = 1
        except Exception as exc:  # noqa: BLE001 - CLI must keep processing the stream.
            exit_code = 1
            sys.stdout.write(json.dumps({"decision": "deny", "reason": str(exc)}) + "\n")
    return exit_code


def _cmd_approve_call(args: argparse.Namespace) -> int:
    if args.ttl_seconds <= 0:
        sys.stderr.write("--ttl-seconds must be greater than zero\n")
        return 2
    if args.max_uses < 1:
        sys.stderr.write("--max-uses must be greater than zero\n")
        return 2

    arguments = _parse_raw_args(args.arg)
    now = datetime.now(timezone.utc)
    grant = ApprovalGrant(
        agent_id=args.agent_id,
        source=args.source,
        tool_name=args.tool,
        arguments_hash=hash_tool_arguments(arguments),
        approved_by=args.approved_by,
        reason=args.reason,
        expires_at=now + timedelta(seconds=args.ttl_seconds),
        max_uses=args.max_uses,
        created_at=now,
    )
    ledger = AuditLedger(Path(args.ledger))
    ledger.add_approval_grant(grant)

    if args.format == "json":
        sys.stdout.write(to_json(grant) + "\n")
    else:
        sys.stdout.write(_render_approval_grant_markdown(grant))
    return 0


def _cmd_approvals(args: argparse.Namespace) -> int:
    ledger = AuditLedger(Path(args.ledger))
    grants = ledger.list_approval_grants(include_expired=args.include_expired)
    output = to_json(grants) if args.format == "json" else _render_approval_grants_markdown(grants)
    _write_output(output, None)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    ledger = AuditLedger(Path(args.ledger))
    events = ledger.list_events()
    tools = ledger.list_tool_inventory()
    chain = ledger.verify_chain()
    output = (
        to_json({"events": events, "tools": tools, "chain": chain})
        if args.format == "json"
        else render_audit_markdown(events, tools, chain)
    )
    _write_output(output, args.output)
    return 0


def _cmd_verify_audit(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger)
    if not ledger_path.exists():
        sys.stderr.write(f"Audit ledger does not exist: {ledger_path}\n")
        return 1
    ledger = AuditLedger(ledger_path)
    verification = ledger.verify_chain()
    output = (
        to_json(verification)
        if args.format == "json"
        else _render_audit_chain_verification_markdown(verification)
    )
    _write_output(output, None)
    return 0 if verification.ok else 1


def _cmd_mcp_proxy(args: argparse.Namespace) -> int:
    server_command = list(args.server_command)
    if server_command and server_command[0] == "--":
        server_command = server_command[1:]
    if not server_command:
        raise SystemExit("mcp-proxy requires a server command after --")

    policy = load_policy(args.policy)
    ledger = AuditLedger(Path(args.ledger))
    proxy = MCPStdioProxy(
        server_command=server_command,
        policy=policy,
        ledger=ledger,
        agent_id=args.agent_id,
        max_message_bytes=args.max_message_bytes,
        shutdown_timeout_seconds=args.shutdown_timeout_seconds,
        inventory_ttl_seconds=args.inventory_ttl_seconds,
    )
    return proxy.run()


def _apply_approval_grant(
    ledger: AuditLedger, call: ToolCall, decision: PolicyDecision
) -> PolicyDecision:
    if decision.decision != Decision.REQUIRE_APPROVAL:
        return decision
    grant = ledger.consume_approval_grant(call)
    if grant is None:
        return decision
    return PolicyDecision(
        decision=Decision.ALLOW,
        reason=f"approved by {grant.approved_by}: {grant.reason}",
        rule_id=f"approval.grant.{grant.grant_id}",
        capabilities=decision.capabilities,
        redacted_arguments=redact_value(call.arguments),
    )


def _parse_args(items: list[str]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Argument must be key=value: {item}")
        key, value = item.split("=", 1)
        output[key] = redact_value(value)
    return output


def _parse_raw_args(items: list[str]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Argument must be key=value: {item}")
        key, value = item.split("=", 1)
        output[key] = value
    return output


def _config_paths_from_args(args: argparse.Namespace) -> list[Path]:
    explicit = [Path(path) for path in args.config]
    if args.changed_from:
        changed = changed_config_paths(args.changed_from, args.head_ref)
        return discover_config_paths(explicit) + changed if explicit else changed
    return discover_config_paths(explicit or None)


def _write_output(output: str, path: str | None) -> None:
    if path:
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output if output.endswith("\n") else output + "\n", encoding="utf-8")
        return
    sys.stdout.write(output)
    if not output.endswith("\n"):
        sys.stdout.write("\n")


def _render_scan_report(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return to_json(report)
    if output_format == "findings-json":
        return to_json(scan_report_to_findings(report))
    return render_scan_markdown(report)


def _write_summary_output(report: ScanReport, path: str | None) -> None:
    if path:
        _write_output(render_findings_summary_markdown(report), path)


def _render_approval_grant_markdown(grant: ApprovalGrant) -> str:
    return (
        f"Created approval grant `{grant.grant_id}`\n\n"
        f"- Tool: `{grant.tool_name}`\n"
        f"- Agent: `{grant.agent_id}`\n"
        f"- Source: `{grant.source}`\n"
        f"- Arguments SHA-256: `{grant.arguments_hash}`\n"
        f"- Approved by: {grant.approved_by}\n"
        f"- Expires: {grant.expires_at.isoformat()}\n"
        f"- Max uses: {grant.max_uses}\n"
    )


def _render_approval_grants_markdown(grants: list[ApprovalGrant]) -> str:
    lines = [
        "# AgentGuard Approval Grants",
        "",
        "| Grant | Tool | Agent | Source | Uses | Expires | Approved By | Reason |",
        "| --- | --- | --- | --- | ---: | --- | --- | --- |",
    ]
    if not grants:
        lines.append("| None | None | None | None | 0 | None | None | No active grants |")
    for grant in grants:
        lines.append(
            " | ".join(
                [
                    f"| `{grant.grant_id}`",
                    f"`{grant.tool_name}`",
                    f"`{grant.agent_id}`",
                    f"`{grant.source}`",
                    f"{grant.used_count}/{grant.max_uses}",
                    grant.expires_at.isoformat(),
                    _markdown_cell(grant.approved_by),
                    _markdown_cell(grant.reason) + " |",
                ]
            )
        )
    return "\n".join(lines) + "\n"


def _render_audit_chain_verification_markdown(verification: AuditChainVerification) -> str:
    status = "OK" if verification.ok else "FAILED"
    lines = [
        "# AgentGuard Audit Integrity",
        "",
        f"Status: **{status}**",
        f"Events checked: {verification.checked_events}",
        f"Head hash: `{verification.head_hash}`",
    ]
    if not verification.ok:
        lines.extend(
            [
                f"First invalid event: `{verification.first_invalid_event_id}`",
                f"Reason: {verification.reason}",
            ]
        )
    return "\n".join(lines) + "\n"


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|")


if __name__ == "__main__":
    raise SystemExit(main())
