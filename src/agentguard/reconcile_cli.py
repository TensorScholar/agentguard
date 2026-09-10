from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.protocols.mcp.modern import MCPHTTPServerBinding
from agentguard.adapters.reconciliation import (
    MCPHTTPProviderStatusProfile,
    MCPHTTPProviderStatusReconciler,
    SQLiteProviderEffectRepository,
)
from agentguard.adapters.storage.sqlite import SQLiteFencedReconciliationState
from agentguard.application import AgentGuardService, ProviderBoundExecutionReconciler


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("provider_status.schema_invalid") from exc
    if not isinstance(value, dict) or not isinstance(value.get("inputSchema"), dict):
        raise ValueError("provider_status.schema_input_required")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguard-reconcile",
        description="Reconcile one UNKNOWN AgentGuard execution with provider-verified evidence",
    )
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--state", type=Path, default=Path(".agentguard/action-integrity.sqlite"))
    parser.add_argument(
        "--provider-reconciliation-state",
        type=Path,
        default=Path(".agentguard/provider-reconciliation.sqlite"),
    )
    parser.add_argument("--key", type=Path, default=Path(".agentguard/decision-private.pem"))
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--upstream-url", required=True)
    parser.add_argument("--status-tool", required=True)
    parser.add_argument("--status-schema", type=Path, required=True)
    parser.add_argument("--status-lookup-argument", default="requestId")
    parser.add_argument("--status-field", default="status")
    parser.add_argument("--provider-operation-id-field", default="providerOperationId")
    parser.add_argument("--success-value", action="append", default=[])
    parser.add_argument("--failure-value", action="append", default=[])
    parser.add_argument("--pending-value", action="append", default=[])
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--max-response-bytes", type=int, default=4_000_000)
    parser.add_argument("--owner-id")
    parser.add_argument("--lease-seconds", type=int, default=60)
    parser.add_argument(
        "--allow-terminal-recheck",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="allow explicit operator re-check of executions with confirmed terminal resolutions",
    )
    return parser


def entrypoint() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")
    if args.max_response_bytes < 1:
        parser.error("--max-response-bytes must be positive")
    if args.lease_seconds <= args.timeout_seconds + 5:
        parser.error("--lease-seconds must exceed --timeout-seconds by more than 5 seconds")
    try:
        schema = _load_schema(args.status_schema)
    except ValueError as exc:
        parser.error(str(exc))

    provider_effects = SQLiteProviderEffectRepository(args.provider_reconciliation_state)
    external_effect = provider_effects.get_external_effect_binding(args.execution_id)
    if external_effect is None:
        parser.error("no durable provider binding exists for --execution-id")

    binding = MCPHTTPServerBinding.for_url(args.server_id, args.upstream_url)
    if external_effect.provider.endpoint_digest != binding.endpoint_digest:
        parser.error("--upstream-url does not match the durable provider endpoint binding")

    try:
        from agentguard.adapters.protocols.mcp.http_server import HTTPXUpstreamSender
    except ImportError as exc:
        parser.error("HTTP support is not installed; install AgentGuard with the 'http' extra")
        raise AssertionError("unreachable") from exc

    signer = Ed25519Signer.load_private(args.key)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    state = SQLiteFencedReconciliationState(args.state)
    service = AgentGuardService(signer, verifier, state)

    profile_kwargs: dict[str, Any] = {
        "status_tool": args.status_tool,
        "status_tool_schema": schema,
        "lookup_argument": args.status_lookup_argument,
        "status_field": args.status_field,
        "provider_operation_id_field": (
            None
            if args.provider_operation_id_field.lower() == "none"
            else args.provider_operation_id_field
        ),
    }
    if args.success_value:
        profile_kwargs["succeeded_values"] = frozenset(
            value.strip().lower() for value in args.success_value
        )
    if args.failure_value:
        profile_kwargs["failed_values"] = frozenset(
            value.strip().lower() for value in args.failure_value
        )
    if args.pending_value:
        profile_kwargs["pending_values"] = frozenset(
            value.strip().lower() for value in args.pending_value
        )
    try:
        profile = MCPHTTPProviderStatusProfile(**profile_kwargs)
    except ValueError as exc:
        parser.error(str(exc))

    owner_id = args.owner_id or f"operator:{os.getpid()}"
    lease = state.claim_reconciliation_lease(
        args.execution_id,
        owner_id,
        now=datetime.now(UTC),
        lease_seconds=args.lease_seconds,
        allow_terminal_recheck=args.allow_terminal_recheck,
    )
    if lease is None:
        parser.error("execution is not UNKNOWN or reconciliation is already owned")

    sender = HTTPXUpstreamSender(
        binding.upstream_url,
        timeout_seconds=args.timeout_seconds,
        max_response_bytes=args.max_response_bytes,
    )
    try:
        provider_reconciler = MCPHTTPProviderStatusReconciler(
            binding=binding,
            provider_identity=external_effect.provider,
            sender=sender,
            profile=profile,
        )
        reconciler = ProviderBoundExecutionReconciler(provider_effects, provider_reconciler)
        with state.resolution_lease(lease):
            resolution = service.reconcile_execution(args.execution_id, reconciler)
    finally:
        state.release_reconciliation_lease(lease)
        sender.close()
    print(resolution.model_dump_json(indent=2))


if __name__ == "__main__":
    entrypoint()
