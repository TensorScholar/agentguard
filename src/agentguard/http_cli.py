from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path

from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.protocols.mcp.http_gateway import MCPProtectedHTTPGateway
from agentguard.adapters.protocols.mcp.modern import MCPHTTPServerBinding
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.application import AgentGuardService
from agentguard.cli.io import load_policy
from agentguard.domain import Principal


def _loopback_listener(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguard-mcp-http",
        description="AgentGuard protected MCP 2026-07-28 Streamable HTTP gateway",
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--key", type=Path, default=Path(".agentguard/decision-private.pem"))
    parser.add_argument("--state", type=Path, default=Path(".agentguard/action-integrity.sqlite"))
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--upstream-url", required=True)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--agent-id", default="mcp-http-client")
    parser.add_argument("--workload-id", default="mcp-http")
    parser.add_argument("--tenant-id", default="local")
    parser.add_argument("--allowed-host", action="append", default=[])
    parser.add_argument("--allowed-origin", action="append", default=[])
    parser.add_argument("--require-origin", action="store_true")
    parser.add_argument("--access-token-env", default="AGENTGUARD_HTTP_ACCESS_TOKEN")
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--max-message-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-response-bytes", type=int, default=4_000_000)
    return parser


def entrypoint() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not _loopback_listener(args.listen_host):
        parser.error(
            "Phase 6A/6B server binds to loopback only; "
            "service/multi-process deployment is Phase 6E"
        )
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be greater than zero")
    if args.max_message_bytes < 1 or args.max_response_bytes < 1:
        parser.error("message/response byte limits must be positive")

    try:
        import uvicorn

        from agentguard.adapters.protocols.mcp.http_server import (
            HTTPXStreamForwarder,
            HTTPXUpstreamSender,
            create_protected_mcp_http_app,
        )
    except ImportError as exc:
        parser.error("HTTP support is not installed; install AgentGuard with the 'http' extra")
        raise AssertionError("unreachable") from exc

    token = os.environ.get(args.access_token_env)
    binding = MCPHTTPServerBinding.for_url(args.server_id, args.upstream_url)
    signer = Ed25519Signer.load_private(args.key)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    state = SQLiteState(args.state)
    service = AgentGuardService(signer, verifier, state)
    service.recover_incomplete_executions()
    principal = Principal(
        agent_id=args.agent_id,
        workload_id=args.workload_id,
        tenant_id=args.tenant_id,
        identity_verified=token is not None,
    )
    sender = HTTPXUpstreamSender(
        binding.upstream_url,
        timeout_seconds=args.timeout_seconds,
        max_response_bytes=args.max_response_bytes,
    )
    gateway = MCPProtectedHTTPGateway(
        service,
        load_policy(args.policy),
        principal,
        binding,
        sender,
        max_message_bytes=args.max_message_bytes,
    )
    default_hosts = {args.listen_host, "localhost", "127.0.0.1", "::1"}
    allowed_hosts = frozenset(args.allowed_host or default_hosts)
    app = create_protected_mcp_http_app(
        gateway,
        allowed_hosts=allowed_hosts,
        allowed_origins=frozenset(args.allowed_origin),
        require_origin=args.require_origin,
        access_token=token,
        stream_forwarder=HTTPXStreamForwarder(
            binding.upstream_url, timeout_seconds=args.timeout_seconds
        ),
    )
    uvicorn.run(app, host=args.listen_host, port=args.port, log_level="info")


if __name__ == "__main__":
    entrypoint()
