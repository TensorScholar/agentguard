from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ._meta import package_version
from .audit import AuditLedger
from .changed import ChangedConfigError, changed_config_paths
from .demo import write_demo
from .discovery import discover_config_paths, scan_configs
from .doctor import render_doctor_markdown, run_doctor
from .gate import scan_report_fails_gate
from .mcp_stdio import MCPStdioProxy
from .models import AuditEvent, RiskLevel, ScanReport, ToolCall
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
        "server_command", nargs=argparse.REMAINDER, help="-- MCP server command"
    )

    report_parser = subparsers.add_parser("report", help="Render an audit report")
    report_parser.add_argument(
        "--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path"
    )
    report_parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    report_parser.add_argument("--output", help="Write report to this path instead of stdout")

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
    if args.command == "mcp-proxy":
        return _cmd_mcp_proxy(args)
    if args.command == "report":
        return _cmd_report(args)
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
            event = AuditEvent.from_decision(call, decision)
            ledger.record(event)
            sys.stdout.write(to_json(event) + "\n")
            if not decision.allowed:
                exit_code = 1
        except Exception as exc:  # noqa: BLE001 - CLI must keep processing the stream.
            exit_code = 1
            sys.stdout.write(json.dumps({"decision": "deny", "reason": str(exc)}) + "\n")
    return exit_code


def _cmd_report(args: argparse.Namespace) -> int:
    ledger = AuditLedger(Path(args.ledger))
    events = ledger.list_events()
    tools = ledger.list_tool_inventory()
    output = (
        to_json({"events": events, "tools": tools})
        if args.format == "json"
        else render_audit_markdown(events, tools)
    )
    _write_output(output, args.output)
    return 0


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
    )
    return proxy.run()


def _parse_args(items: list[str]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"Argument must be key=value: {item}")
        key, value = item.split("=", 1)
        output[key] = redact_value(value)
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


if __name__ == "__main__":
    raise SystemExit(main())
