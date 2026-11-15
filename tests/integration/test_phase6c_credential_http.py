from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Mapping

from decisionlock.adapters.broker import (
    BrokeredCredentialAuthority,
    SQLiteCredentialProfileRepository,
)
from decisionlock.adapters.crypto import Ed25519Signer
from decisionlock.adapters.protocols.mcp.http_gateway import MCPProtectedHTTPGateway
from decisionlock.adapters.protocols.mcp.http_gateway_types import HTTPExchangeResponse
from decisionlock.adapters.protocols.mcp.modern import (
    CLIENT_CAPABILITIES_META_KEY,
    MODERN_PROTOCOL_PROFILE,
    PROTOCOL_VERSION_META_KEY,
    MCPHTTPServerBinding,
    encode_mcp_header_value,
)
from decisionlock.application import DecisionLockService
from decisionlock.domain import (
    CredentialAuthorityProfile,
    CredentialCeiling,
    Effect,
    ExecutionState,
    Principal,
    ProvenanceLabel,
    ProviderIdentity,
)
from decisionlock.domain.policy import (
    ActionMatcher,
    PolicyDefaults,
    PolicyDocument,
    PolicyMetadata,
    PolicyRule,
    ProvenanceMatcher,
)
from decisionlock.engine.canonical import digest


class MutableSource:
    def __init__(self, value: str) -> None:
        self.value = value
        self.read_count = 0

    @property
    def binding_digest(self) -> str:
        return digest({"kind": "integration-test", "id": "provider-secret"})

    def read(self) -> str:
        self.read_count += 1
        return self.value


class CredentialCheckingSender:
    def __init__(self, expected_secret: str) -> None:
        self.expected_secret = expected_secret
        self.calls: list[tuple[dict[str, Any], dict[str, str]]] = []

    def send(self, body: bytes, headers: Mapping[str, str]) -> HTTPExchangeResponse:
        message = json.loads(body)
        normalized = {key.lower(): value for key, value in headers.items()}
        self.calls.append((message, normalized))
        if message["method"] == "tools/list":
            assert "authorization" not in normalized
            response = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "tools": [
                        {
                            "name": "read_file",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                            },
                        }
                    ]
                },
            }
        else:
            assert message["method"] == "tools/call"
            assert normalized["authorization"] == f"Bearer {self.expected_secret}"
            response = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"content": [{"type": "text", "text": "credential-ok"}]},
            }
        return HTTPExchangeResponse(
            200,
            {"content-type": "application/json"},
            json.dumps(response).encode(),
        )


def _policy() -> PolicyDocument:
    return PolicyDocument(
        metadata=PolicyMetadata(id="phase6c", revision=1),
        defaults=PolicyDefaults(maximum_credential_ttl_seconds=30),
        rules=(
            PolicyRule(
                id="credential-read",
                priority=100,
                effect=Effect.ALLOW,
                action=ActionMatcher(tools=frozenset({"read_file"})),
                provenance=ProvenanceMatcher(contains_any=frozenset({ProvenanceLabel.UNVERIFIED})),
                credential=CredentialCeiling(
                    audience="mcp-filesystem",
                    scopes=frozenset({"mcp:read"}),
                    maximum_ttl_seconds=30,
                    tenant_id="tenant",
                ),
            ),
        ),
    )


def _message() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 41,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "README.md"},
            "_meta": {
                PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_PROFILE,
                CLIENT_CAPABILITIES_META_KEY: {},
            },
        },
    }


def _headers(message: dict[str, Any]) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "mcp-protocol-version": MODERN_PROTOCOL_PROFILE,
        "mcp-method": "tools/call",
        "mcp-name": encode_mcp_header_value(str(message["params"]["name"])),
        # Untrusted client authorization must never be forwarded to the provider.
        "authorization": "Bearer attacker-controlled",
    }


def test_credential_bound_http_call_injects_only_dispatch_secret(
    tmp_path, signer, verifier, state
) -> None:
    binding = MCPHTTPServerBinding.for_url("filesystem", "http://127.0.0.1:9010/mcp")
    principal = Principal(
        agent_id="agent",
        workload_id="mcp-http",
        tenant_id="tenant",
        identity_verified=True,
    )
    provider = ProviderIdentity(
        provider_id=binding.server_id,
        tenant_id=principal.tenant_id,
        endpoint_digest=binding.endpoint_digest,
    )
    source = MutableSource("provider-secret-v1")
    profile = CredentialAuthorityProfile(
        profile_id="filesystem-production",
        provider=provider,
        audience="mcp-filesystem",
        scopes=frozenset({"mcp:read"}),
        tenant_id="tenant",
        source_binding_digest=source.binding_digest,
    )
    profiles = SQLiteCredentialProfileRepository(tmp_path / "credential-authority.sqlite")
    profiles.store_credential_profile(profile)
    broker_signer = Ed25519Signer.generate("credential-authority-key")
    authority = BrokeredCredentialAuthority(
        name="production-broker",
        signer=broker_signer,
        profiles=profiles,
        sources={profile.profile_id: source},
    )
    sender = CredentialCheckingSender("provider-secret-v1")
    service = DecisionLockService(
        signer,
        verifier,
        state,
        broker_grant_verifier=authority.verifier,
    )
    gateway = MCPProtectedHTTPGateway(
        service,
        _policy(),
        principal,
        binding,
        sender,
        credential_broker=authority,
        credential_material_resolver=authority,
        provider_identity=provider,
    )

    message = _message()
    result = gateway.handle(json.dumps(message).encode(), _headers(message))
    payload = json.loads(result.body)

    assert result.status_code == 200
    assert payload["id"] == 41
    assert payload["result"]["content"][0]["text"] == "credential-ok"
    assert [call[0]["method"] for call in sender.calls] == ["tools/list", "tools/call"]
    assert source.read_count == 1
    records = state.list_executions()
    assert len(records) == 1
    assert records[0].state == ExecutionState.SUCCEEDED

    secret = b"provider-secret-v1"
    assert secret not in state.path.read_bytes()
    assert secret not in profiles.path.read_bytes()
    assert all("provider-secret-v1" not in event.model_dump_json() for event in state.list_events())


def test_revoked_profile_blocks_call_before_external_dispatch(
    tmp_path, signer, verifier, state
) -> None:
    binding = MCPHTTPServerBinding.for_url("filesystem", "http://127.0.0.1:9010/mcp")
    principal = Principal(
        agent_id="agent",
        workload_id="mcp-http",
        tenant_id="tenant",
        identity_verified=True,
    )
    provider = ProviderIdentity(
        provider_id=binding.server_id,
        tenant_id=principal.tenant_id,
        endpoint_digest=binding.endpoint_digest,
    )
    source = MutableSource("provider-secret-v1")
    profile = CredentialAuthorityProfile(
        profile_id="filesystem-production",
        provider=provider,
        audience="mcp-filesystem",
        scopes=frozenset({"mcp:read"}),
        tenant_id="tenant",
        source_binding_digest=source.binding_digest,
    )
    profiles = SQLiteCredentialProfileRepository(tmp_path / "credential-authority.sqlite")
    profiles.store_credential_profile(profile)
    profiles.revoke_credential_profile(profile.profile_id, datetime.now(UTC), "operator revocation")
    authority = BrokeredCredentialAuthority(
        name="production-broker",
        signer=Ed25519Signer.generate("credential-authority-key"),
        profiles=profiles,
        sources={profile.profile_id: source},
    )
    sender = CredentialCheckingSender("provider-secret-v1")
    service = DecisionLockService(
        signer,
        verifier,
        state,
        broker_grant_verifier=authority.verifier,
    )
    gateway = MCPProtectedHTTPGateway(
        service,
        _policy(),
        principal,
        binding,
        sender,
        credential_broker=authority,
        credential_material_resolver=authority,
        provider_identity=provider,
    )

    message = _message()
    result = gateway.handle(json.dumps(message).encode(), _headers(message))
    payload = json.loads(result.body)

    assert "credential issuance failed" in payload["error"]["message"]
    assert [call[0]["method"] for call in sender.calls] == ["tools/list"]
    assert source.read_count == 0
    assert state.list_executions() == ()
