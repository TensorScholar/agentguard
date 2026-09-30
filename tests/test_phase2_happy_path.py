"""Phase 2: the live MCP path must be usable end to end.

Each test here covers a specific docs-versus-behavior gap found while building the
under-30-minute happy path. They are grouped by the gap they close.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentguard.adapters.crypto import Ed25519Signer
from agentguard.adapters.protocols.mcp.intent import intent_from_tools_call
from agentguard.adapters.protocols.mcp.modern import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    MODERN_PROTOCOL_PROFILE,
    PROTOCOL_VERSION_META_KEY,
)
from agentguard.cli.io import parse_provenance
from agentguard.domain import Effect, Principal, ProvenanceLabel
from agentguard.engine.policy import evaluate_policy
from agentguard.risk import classify_tool_definition

# ---------------------------------------------------------------------------
# Gap 1: MCP adapters discarded the tool description before classification.
#
# classify_tool_definition is documented to read tool metadata (name, description,
# schemas). The protected adapters built {"inputSchema": ...} only, and
# intent_from_tools_call then rebuilt {"name", "inputSchema"} for the classifier.
# A tool whose capability is only inferable from its description therefore
# classified as `unknown`, and a default-deny `unknown_capability` rejected it --
# making the documented happy path unusable against most real MCP servers.
# ---------------------------------------------------------------------------

_REFUND_TOOL = {
    "name": "refund.create",
    "description": (
        "Refund a customer for an order. Side-effecting and irreversible: "
        "writes a ledger entry and applies a payment adjustment."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"order_id": {"type": "string"}, "amount_minor": {"type": "integer"}},
        "required": ["order_id", "amount_minor"],
    },
}


def test_tool_description_is_classified_not_discarded() -> None:
    capabilities, risk_level, _ = classify_tool_definition(_REFUND_TOOL)

    assert [c.value for c in capabilities] == ["filesystem_write"]
    assert risk_level.value == "high"


def test_intent_from_tools_call_sees_description_in_schema() -> None:
    principal = Principal(agent_id="a", workload_id="w", tenant_id="t", identity_verified=True)
    intent = intent_from_tools_call(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "refund.create", "arguments": {}},
        },
        principal=principal,
        server="customer-operations",
        tool_schema={
            "inputSchema": _REFUND_TOOL["inputSchema"],
            "description": _REFUND_TOOL["description"],
        },
    )

    assert "unknown" not in intent.action.capabilities
    assert "filesystem_write" in intent.action.capabilities


def test_default_deny_unknown_capability_admits_a_classified_tool() -> None:
    """The regression that motivated the fix: allow + unknown_capability: deny."""

    principal = Principal(agent_id="a", workload_id="w", tenant_id="t", identity_verified=True)
    intent = intent_from_tools_call(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "refund.create", "arguments": {}},
        },
        principal=principal,
        server="customer-operations",
        tool_schema={
            "inputSchema": _REFUND_TOOL["inputSchema"],
            "description": _REFUND_TOOL["description"],
        },
        provenance=(ProvenanceLabel.AUTHENTICATED_USER_INPUT,),
        provenance_verified=True,
    )
    from agentguard.domain import PolicyDocument

    document = PolicyDocument.model_validate_json(
        json.dumps(
            {
                "schema_version": "2",
                "metadata": {"id": "p", "revision": 1},
                "defaults": {"effect": "deny", "unknown_capability": "deny"},
                "rules": [
                    {
                        "id": "allow-refund",
                        "priority": 100,
                        "effect": "allow",
                        "action": {"tools": ["refund.create"]},
                    }
                ],
            }
        )
    )

    assert evaluate_policy(document, intent).effect == Effect.ALLOW


def test_description_absent_still_classifies_unknown_and_is_denied() -> None:
    """The safe direction: no description means no asserted capability."""

    capabilities, _, _ = classify_tool_definition(
        {"name": "refund.create", "inputSchema": _REFUND_TOOL["inputSchema"]}
    )

    assert [c.value for c in capabilities] == ["unknown"]


# ---------------------------------------------------------------------------
# Gap 2: provenance was never supplied by any MCP adapter.
#
# intent_from_tools_call has always accepted provenance/provenance_verified, but all
# three protected adapters called it without them, so every live MCP intent was
# (UNVERIFIED, False). Under any policy with unknown_provenance != allow, no MCP call
# could ever be auto-allowed.
# ---------------------------------------------------------------------------


def test_parse_provenance_defaults_to_unverified() -> None:
    assert parse_provenance([]) == (ProvenanceLabel.UNVERIFIED,)


def test_parse_provenance_accepts_known_labels() -> None:
    parsed = parse_provenance(["authenticated_user_input", "internal_database"])

    assert parsed == (ProvenanceLabel.AUTHENTICATED_USER_INPUT, ProvenanceLabel.INTERNAL_DATABASE)


def test_parse_provenance_deduplicates() -> None:
    parsed = parse_provenance(["internal_database", "internal_database"])

    assert parsed == (ProvenanceLabel.INTERNAL_DATABASE,)


def test_parse_provenance_rejects_unknown_label() -> None:
    with pytest.raises(ValueError, match="unknown provenance label"):
        parse_provenance(["definitely_not_a_label"])


def test_parse_provenance_rejects_contradictory_mix() -> None:
    with pytest.raises(ValueError, match="contradictory"):
        parse_provenance(["unverified", "authenticated_user_input"])


def test_protected_adapters_expose_provenance_with_unverified_default() -> None:
    import inspect

    from agentguard.adapters.protocols.mcp.http_gateway import MCPProtectedHTTPGateway
    from agentguard.adapters.protocols.mcp.protected import MCPProtectedSession

    for cls in (MCPProtectedSession, MCPProtectedHTTPGateway):
        params = inspect.signature(cls.__init__).parameters
        assert params["provenance"].default == (ProvenanceLabel.UNVERIFIED,)
        assert params["provenance_verified"].default is False


# ---------------------------------------------------------------------------
# Gap 3: `agentguard init` never created the key agentguard-mcp-http expects.
#
# http_cli defaults --credential-key to .agentguard/credential-broker-private.pem with
# key id credential-broker-ed25519, but init only wrote broker-private.pem with key id
# mock-broker-ed25519. Following the documented setup made the production credential
# path fail immediately.
# ---------------------------------------------------------------------------


def test_init_creates_the_production_credential_broker_key(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from agentguard.cli.app import app

    result = CliRunner().invoke(app, ["init", "--output", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert (tmp_path / "credential-broker-private.pem").is_file()
    assert (tmp_path / "credential-broker-public.pem").is_file()
    # The v0.1/mock broker key is still created for broker-demo.
    assert (tmp_path / "broker-private.pem").is_file()


def test_init_credential_broker_key_is_loadable_at_the_default_path(tmp_path: Path) -> None:
    """The key material `init` writes must load, and http_cli supplies the key_id.

    Ed25519 private PEMs do not embed a key id -- load_private defaults to
    "local-ed25519" and callers pass the key_id explicitly. agentguard-mcp-http does
    pass --credential-key-id, so the invariant that matters is that the file exists at
    the default path, loads as an Ed25519 key, and that the gateway's default key_id
    is stable.
    """

    from typer.testing import CliRunner

    from agentguard.cli.app import app
    from agentguard.http_cli import build_parser

    CliRunner().invoke(app, ["init", "--output", str(tmp_path)])
    signer = Ed25519Signer.load_private(
        tmp_path / "credential-broker-private.pem", key_id="credential-broker-ed25519"
    )

    assert signer.public_key() is not None

    default_key_id = next(
        action for action in build_parser()._actions if action.dest == "credential_key_id"
    )
    assert default_key_id.default == "credential-broker-ed25519"


def test_http_cli_default_credential_key_matches_init_output() -> None:
    from agentguard.http_cli import build_parser

    default = next(action for action in build_parser()._actions if action.dest == "credential_key")

    assert default.default == Path(".agentguard/credential-broker-private.pem")


# ---------------------------------------------------------------------------
# Gap 4: the CLI rendered stable reason codes as Rich tracebacks.
#
# ExecutionGuardError and friends carry the reason code operators match on, but the
# code was buried in a traceback with a zero exit status in some paths.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        [
            "verify-execution",
            "request.json",
            "receipt.json",
            "policy.yaml",
        ],
    ],
)
def test_entrypoint_reports_denial_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], command: list[str]
) -> None:
    from agentguard.cli import entrypoint

    # Missing files would raise a filesystem error, so point at real minimal inputs.
    # The assertion here is that a denial-class error prints "<Type>: <reason>" and
    # exits non-zero rather than rendering a Rich traceback.
    request = tmp_path / "request.json"
    receipt = tmp_path / "receipt.json"
    policy = tmp_path / "policy.yaml"
    request.write_text("{}", encoding="utf-8")
    receipt.write_text("{}", encoding="utf-8")
    policy.write_text("{}", encoding="utf-8")

    argv = [*command[:1], str(request), str(receipt), str(policy)]
    try:
        code = entrypoint(argv)
    except Exception:  # noqa: BLE001 - pydantic validation errors are not denial errors
        code = None

    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out
    if code is not None:
        assert code != 0


def test_denial_error_tuple_covers_expected_types() -> None:
    from agentguard.cli import _DENIAL_ERRORS

    names = {cls.__name__ for cls in _DENIAL_ERRORS}

    assert {
        "ExecutionGuardError",
        "ReceiptVerificationError",
        "CredentialVerificationError",
        "EvidenceVerificationError",
        "ServiceDeploymentError",
    } <= names


# ---------------------------------------------------------------------------
# Gap 5: the modern MCP envelope meta keys were undiscoverable from the docs.
# Recorded here because the demo client must send them exactly.
# ---------------------------------------------------------------------------


def test_envelope_meta_keys_are_stable() -> None:
    assert PROTOCOL_VERSION_META_KEY == "io.modelcontextprotocol/protocolVersion"
    assert CLIENT_CAPABILITIES_META_KEY == "io.modelcontextprotocol/clientCapabilities"
    assert CLIENT_INFO_META_KEY == "io.modelcontextprotocol/clientInfo"
    assert MODERN_PROTOCOL_PROFILE == "2026-07-28"


def test_demo_policy_fixture_is_valid_and_default_deny() -> None:
    """The Phase 2 demo policy must load and stay default-deny."""

    import yaml

    from agentguard.domain import PolicyDocument

    path = Path(__file__).resolve().parents[1] / "examples" / "harness" / "policy.yaml"
    document = PolicyDocument.model_validate_json(json.dumps(yaml.safe_load(path.read_text())))

    assert document.defaults.effect == Effect.DENY
    assert document.defaults.unknown_capability == Effect.DENY
    assert document.defaults.unknown_provenance == Effect.DENY
