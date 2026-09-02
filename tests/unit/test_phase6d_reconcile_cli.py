from __future__ import annotations

import json
import sys
from datetime import UTC, datetime

import pytest

import agentguard.reconcile_cli as reconcile_cli
from agentguard.adapters.protocols.mcp import http_server
from agentguard.adapters.protocols.mcp.modern import MCPHTTPServerBinding
from agentguard.domain import (
    ExecutionAttemptIdentity,
    ExternalEffectBinding,
    ExternalOperationIdentity,
    IdempotencyBinding,
    ProviderIdentity,
)


def _effect() -> ExternalEffectBinding:
    binding = MCPHTTPServerBinding.for_url("filesystem", "http://127.0.0.1:9010/mcp")
    return ExternalEffectBinding(
        decision_id="decision_cli",
        intent_digest="sha256:" + "1" * 64,
        action_digest="sha256:" + "2" * 64,
        resource_digest="sha256:" + "3" * 64,
        arguments_digest="sha256:" + "4" * 64,
        provider=ProviderIdentity(
            provider_id="filesystem",
            endpoint_digest=binding.endpoint_digest,
        ),
        operation=ExternalOperationIdentity(
            operation_id="operation_cli",
            operation_kind="mcp.tools/call",
            operation_name="read_file",
        ),
        attempt=ExecutionAttemptIdentity(
            execution_id="exec_cli",
            attempt_id="attempt_cli",
            attempt_number=1,
            started_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
        ),
        idempotency=IdempotencyBinding(),
    )


class FakeEffects:
    def __init__(self, effect: ExternalEffectBinding) -> None:
        self.effect = effect

    def get_external_effect_binding(self, execution_id: str) -> ExternalEffectBinding | None:
        return self.effect if execution_id == self.effect.attempt.execution_id else None

    def record_provider_reconciliation_evidence(self, evidence, recorded_at) -> None:
        del evidence, recorded_at

    def list_provider_reconciliation_evidence(self, binding_digest):
        del binding_digest
        return ()


class FakeSigner:
    key_id = "decision-key"

    @staticmethod
    def public_key() -> object:
        return object()


class FakeResolution:
    def model_dump_json(self, *, indent: int) -> str:
        assert indent == 2
        return json.dumps({"status": "confirmed_succeeded"}, indent=indent)


class FakeService:
    def __init__(self) -> None:
        self.execution_id: str | None = None
        self.reconciler = None

    def reconcile_execution(self, execution_id: str, reconciler) -> FakeResolution:
        self.execution_id = execution_id
        self.reconciler = reconciler
        return FakeResolution()


class FakeSender:
    last: FakeSender | None = None

    def __init__(
        self, upstream_url: str, *, timeout_seconds: float, max_response_bytes: int
    ) -> None:
        self.upstream_url = upstream_url
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.closed = False
        type(self).last = self

    def close(self) -> None:
        self.closed = True

    def send(self, body: bytes, headers):
        raise AssertionError("fake service must not dispatch provider IO")


def test_load_schema_rejects_invalid_or_incomplete_json(tmp_path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="provider_status.schema_invalid"):
        reconcile_cli._load_schema(invalid)

    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text(json.dumps({"type": "object"}), encoding="utf-8")
    with pytest.raises(ValueError, match="provider_status.schema_input_required"):
        reconcile_cli._load_schema(incomplete)


def test_reconcile_cli_wires_operator_profile_and_closes_sender(
    tmp_path, monkeypatch, capsys
) -> None:
    schema_path = tmp_path / "status-schema.json"
    schema_path.write_text(
        json.dumps(
            {
                "inputSchema": {
                    "type": "object",
                    "properties": {"requestId": {"type": "string"}},
                }
            }
        ),
        encoding="utf-8",
    )
    effect = _effect()
    effects = FakeEffects(effect)
    service = FakeService()

    monkeypatch.setattr(
        reconcile_cli,
        "SQLiteProviderEffectRepository",
        lambda path: effects,
    )
    monkeypatch.setattr(
        reconcile_cli.Ed25519Signer,
        "load_private",
        staticmethod(lambda path: FakeSigner()),
    )
    monkeypatch.setattr(reconcile_cli, "Ed25519Verifier", lambda keys: object())
    monkeypatch.setattr(reconcile_cli, "SQLiteState", lambda path: object())
    monkeypatch.setattr(reconcile_cli, "AgentGuardService", lambda *args: service)
    monkeypatch.setattr(http_server, "HTTPXUpstreamSender", FakeSender)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentguard-reconcile",
            "--execution-id",
            "exec_cli",
            "--state",
            str(tmp_path / "action.sqlite"),
            "--provider-reconciliation-state",
            str(tmp_path / "provider.sqlite"),
            "--key",
            str(tmp_path / "decision.pem"),
            "--server-id",
            "filesystem",
            "--upstream-url",
            "http://127.0.0.1:9010/mcp",
            "--status-tool",
            "operation_status",
            "--status-schema",
            str(schema_path),
            "--provider-operation-id-field",
            "none",
            "--success-value",
            "DONE",
            "--failure-value",
            "BROKEN",
            "--pending-value",
            "WAITING",
            "--timeout-seconds",
            "4.5",
            "--max-response-bytes",
            "12345",
        ],
    )

    reconcile_cli.entrypoint()

    assert service.execution_id == "exec_cli"
    assert service.reconciler is not None
    profile = service.reconciler.reconciler.profile
    assert profile.succeeded_values == frozenset({"done"})
    assert profile.failed_values == frozenset({"broken"})
    assert profile.pending_values == frozenset({"waiting"})
    assert profile.provider_operation_id_field is None
    assert FakeSender.last is not None
    assert FakeSender.last.timeout_seconds == 4.5
    assert FakeSender.last.max_response_bytes == 12345
    assert FakeSender.last.closed is True
    assert json.loads(capsys.readouterr().out)["status"] == "confirmed_succeeded"
