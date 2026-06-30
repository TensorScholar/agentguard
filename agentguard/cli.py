from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .audit import AuditLedger
from .discovery import discover_config_paths, scan_configs
from .mcp_stdio import MCPStdioProxy
from .models import AuditEvent, ToolCall
from .policy import load_policy
from .render import render_audit_markdown, render_scan_markdown, to_json
from .secrets import redact_value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan MCP/tool configs")
    scan_parser.add_argument("--config", action="append", default=[], help="Path to MCP JSON config")
    scan_parser.add_argument("--format", choices=["json", "markdown"], default="markdown")

    check_parser = subparsers.add_parser("check-call", help="Evaluate one tool call")
    check_parser.add_argument("--policy", help="Path to policy.yaml")
    check_parser.add_argument("--tool", required=True, help="Tool name")
    check_parser.add_argument("--arg", action="append", default=[], help="Tool arg as key=value")
    check_parser.add_argument("--agent-id", default="local")
    check_parser.add_argument("--format", choices=["json", "markdown"], default="json")

    proxy_parser = subparsers.add_parser("proxy", help="Enforce policy on JSONL tool calls from stdin")
    proxy_parser.add_argument("--policy", help="Path to policy.yaml")
    proxy_parser.add_argument("--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path")

    mcp_parser = subparsers.add_parser("mcp-proxy", help="Proxy an MCP stdio server with policy")
    mcp_parser.add_argument("--policy", help="Path to policy.yaml")
    mcp_parser.add_argument("--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path")
    mcp_parser.add_argument("--agent-id", default="mcp-client", help="Agent/client label for audit logs")
    mcp_parser.add_argument(
        "--max-message-bytes",
        type=int,
        default=1_000_000,
        help="Maximum JSON-RPC line size accepted from either side",
    )
    mcp_parser.add_argument("server_command", nargs=argparse.REMAINDER, help="-- MCP server command")

    report_parser = subparsers.add_parser("report", help="Render an audit report")
    report_parser.add_argument("--ledger", default=".agentguard/audit.sqlite", help="SQLite audit path")
    report_parser.add_argument("--format", choices=["json", "markdown"], default="markdown")

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
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


def _cmd_scan(args: argparse.Namespace) -> int:
    explicit = [Path(path) for path in args.config]
    paths = discover_config_paths(explicit or None)
    report = scan_configs(paths)
    output = to_json(report) if args.format == "json" else render_scan_markdown(report)
    sys.stdout.write(output)
    if not output.endswith("\n"):
        sys.stdout.write("\n")
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
    output = to_json(events) if args.format == "json" else render_audit_markdown(events)
    sys.stdout.write(output)
    if not output.endswith("\n"):
        sys.stdout.write("\n")
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


if __name__ == "__main__":
    raise SystemExit(main())
