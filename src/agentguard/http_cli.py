from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path

from agentguard.adapters.broker import (
    BrokeredCredentialAuthority,
    EnvironmentCredentialSource,
    SQLiteCredentialProfileRepository,
)
from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.protocols.mcp.http_gateway import MCPProtectedHTTPGateway
from agentguard.adapters.protocols.mcp.modern import MCPHTTPServerBinding
from agentguard.adapters.reconciliation import SQLiteProviderEffectRepository
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.application import AgentGuardService
from agentguard.cli.io import load_policy
from agentguard.domain import CredentialAuthorityProfile, Principal, ProviderIdentity


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
    parser.add_argument(
        "--provider-reconciliation-state",
        type=Path,
        default=Path(".agentguard/provider-reconciliation.sqlite"),
    )
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

    credential = parser.add_argument_group("production credential authority")
    credential.add_argument("--credential-env")
    credential.add_argument("--credential-audience")
    credential.add_argument("--credential-scope", action="append", default=[])
    credential.add_argument("--credential-profile-id", default="mcp-http-provider")
    credential.add_argument("--credential-provider-id")
    credential.add_argument("--credential-broker-name", default="agentguard-http-credential-broker")
    credential.add_argument(
        "--credential-key", type=Path, default=Path(".agentguard/credential-broker-private.pem")
    )
    credential.add_argument("--credential-key-id", default="credential-broker-ed25519")
    credential.add_argument(
        "--credential-state", type=Path, default=Path(".agentguard/credential-authority.sqlite")
    )
    credential.add_argument("--credential-header-name", default="Authorization")
    credential.add_argument("--credential-header-scheme", default="Bearer")
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
    if args.credential_env is None and (args.credential_audience or args.credential_scope):
        parser.error("--credential-env is required when configuring credential authority")
    if args.credential_env is not None:
        if not args.credential_audience:
            parser.error("--credential-audience is required with --credential-env")
        if not args.credential_scope:
            parser.error("at least one --credential-scope is required with --credential-env")
        if not args.credential_key.is_file():
            parser.error("--credential-key must reference an existing broker private key")

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
    provider_effects = SQLiteProviderEffectRepository(args.provider_reconciliation_state)
    principal = Principal(
        agent_id=args.agent_id,
        workload_id=args.workload_id,
        tenant_id=args.tenant_id,
        identity_verified=token is not None,
    )

    credential_authority = None
    provider_identity = ProviderIdentity(
        provider_id=args.credential_provider_id or binding.server_id,
        tenant_id=principal.tenant_id,
        endpoint_digest=binding.endpoint_digest,
    )
    broker_grant_verifier = None
    if args.credential_env is not None:
        source = EnvironmentCredentialSource(args.credential_env)
        profiles = SQLiteCredentialProfileRepository(args.credential_state)
        header_scheme = (
            None
            if args.credential_header_scheme.lower() == "none"
            else args.credential_header_scheme
        )
        profile = CredentialAuthorityProfile(
            profile_id=args.credential_profile_id,
            provider=provider_identity,
            audience=args.credential_audience,
            scopes=frozenset(args.credential_scope),
            tenant_id=principal.tenant_id,
            source_binding_digest=source.binding_digest,
            header_name=args.credential_header_name,
            header_scheme=header_scheme,
        )
        profiles.store_credential_profile(profile)
        broker_signer = Ed25519Signer.load_private(
            args.credential_key, key_id=args.credential_key_id
        )
        credential_authority = BrokeredCredentialAuthority(
            name=args.credential_broker_name,
            signer=broker_signer,
            profiles=profiles,
            sources={profile.profile_id: source},
        )
        broker_grant_verifier = credential_authority.verifier

    service = AgentGuardService(
        signer,
        verifier,
        state,
        broker_grant_verifier=broker_grant_verifier,
    )
    service.recover_incomplete_executions()
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
        credential_broker=credential_authority,
        credential_material_resolver=credential_authority,
        provider_identity=provider_identity,
        provider_effect_repository=provider_effects,
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
