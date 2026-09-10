from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any

from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.protocols.mcp.modern import MCPHTTPServerBinding
from agentguard.adapters.reconciliation import (
    MCPHTTPBoundStatusReconciler,
    MCPHTTPProviderStatusProfile,
    SQLiteProviderEffectRepository,
)
from agentguard.adapters.storage.sqlite import SQLiteFencedReconciliationState
from agentguard.application import (
    AgentGuardService,
    ProviderBoundExecutionReconciler,
    ReconciliationTickResult,
    ReconciliationWorker,
    ReconciliationWorkerConfig,
)
from agentguard.reconcile_cli import _load_schema


class UTCClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def _default_owner_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguard-reconcile-worker",
        description="Lease-fenced multi-process provider reconciliation worker",
    )
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
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--max-items-per-tick", type=int, default=100)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--health-check",
        action="store_true",
        help="probe durable state readiness, emit JSON, and exit",
    )
    return parser


def _profile(args: argparse.Namespace, schema: dict[str, Any]) -> MCPHTTPProviderStatusProfile:
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
    return MCPHTTPProviderStatusProfile(**profile_kwargs)


def _health_payload(worker: ReconciliationWorker) -> dict[str, object]:
    health = worker.health()
    return {
        "owner_id": health.owner_id,
        "live": health.live,
        "ready": health.ready,
        "last_tick_started_at": (
            health.last_tick_started_at.isoformat()
            if health.last_tick_started_at is not None
            else None
        ),
        "last_tick_completed_at": (
            health.last_tick_completed_at.isoformat()
            if health.last_tick_completed_at is not None
            else None
        ),
        "last_error": health.last_error,
        "consecutive_failed_ticks": health.consecutive_failed_ticks,
    }


def _tick_payload(
    worker: ReconciliationWorker,
    result: ReconciliationTickResult,
) -> dict[str, object]:
    return {
        "event": "reconciliation_tick",
        "observed_at": datetime.now(UTC).isoformat(),
        "owner_id": worker.health().owner_id,
        "scanned": result.scanned,
        "eligible": result.eligible,
        "claimed": result.claimed,
        "reconciled": result.reconciled,
        "busy": result.busy,
        "lease_lost": result.lease_lost,
        "failed": result.failed,
    }


def entrypoint() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")
    if args.max_response_bytes < 1:
        parser.error("--max-response-bytes must be positive")
    if args.lease_seconds < 1:
        parser.error("--lease-seconds must be positive")
    if args.lease_seconds <= args.timeout_seconds + 5:
        parser.error("--lease-seconds must exceed --timeout-seconds by more than 5 seconds")
    if args.poll_seconds <= 0:
        parser.error("--poll-seconds must be greater than zero")
    if args.max_items_per_tick < 1:
        parser.error("--max-items-per-tick must be positive")
    try:
        schema = _load_schema(args.status_schema)
        profile = _profile(args, schema)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        from agentguard.adapters.protocols.mcp.http_server import HTTPXUpstreamSender
    except ImportError as exc:
        parser.error("HTTP support is not installed; install AgentGuard with the 'http' extra")
        raise AssertionError("unreachable") from exc

    signer = Ed25519Signer.load_private(args.key)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    state = SQLiteFencedReconciliationState(args.state)
    provider_effects = SQLiteProviderEffectRepository(args.provider_reconciliation_state)
    service = AgentGuardService(signer, verifier, state)

    binding = MCPHTTPServerBinding.for_url(args.server_id, args.upstream_url)
    sender = HTTPXUpstreamSender(
        binding.upstream_url,
        timeout_seconds=args.timeout_seconds,
        max_response_bytes=args.max_response_bytes,
    )
    provider_status = MCPHTTPBoundStatusReconciler(
        binding=binding,
        sender=sender,
        profile=profile,
    )
    reconciler = ProviderBoundExecutionReconciler(provider_effects, provider_status)
    owner_id = args.owner_id or _default_owner_id()
    worker = ReconciliationWorker(
        service=service,
        state=state,
        provider_effects=provider_effects,
        reconciler=reconciler,
        clock=UTCClock(),
        config=ReconciliationWorkerConfig(
            owner_id=owner_id,
            lease_seconds=args.lease_seconds,
            max_items_per_tick=args.max_items_per_tick,
        ),
    )

    if args.health_check:
        ready = worker.probe_readiness()
        print(json.dumps(_health_payload(worker), sort_keys=True))
        sender.close()
        raise SystemExit(0 if ready else 1)

    stop = Event()

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    try:
        while not stop.is_set():
            result = worker.run_once()
            print(json.dumps(_tick_payload(worker, result), sort_keys=True), flush=True)
            if args.once:
                break
            stop.wait(args.poll_seconds)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "event": "reconciliation_worker_fatal",
                    "observed_at": datetime.now(UTC).isoformat(),
                    "owner_id": owner_id,
                    "error": f"{type(exc).__name__}:{exc}",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        raise
    finally:
        worker.mark_stopped()
        sender.close()


if __name__ == "__main__":
    entrypoint()
