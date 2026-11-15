from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from decisionlock.adapters.protocols.mcp import (
    PROTECTED_OUTCOME_UNKNOWN,
    PROTECTED_PROFILE_UNSUPPORTED,
    PROTECTED_REQUEST_REJECTED,
    SUPPORTED_PROTOCOL_PROFILE,
    MCPProtectedExecutor,
    MCPProtectedSession,
    MCPProtectedStdioProxy,
    MCPProtectedTransport,
    MCPServerBinding,
    SessionToolSchemaCache,
)
from decisionlock.application import DecisionLockService
from decisionlock.domain import (
    CredentialCeiling,
    Effect,
    ExecutionState,
    ExecutionStatus,
    Principal,
    ProvenanceLabel,
)
from decisionlock.domain.policy import (
    ActionMatcher,
    PolicyDefaults,
    PolicyDocument,
    PolicyMetadata,
    PolicyRule,
    ProvenanceMatcher,
)
from decisionlock.ports import AmbiguousExecutionError, DefiniteExecutionFailure


def allow_policy(*, credential: bool = False) -> PolicyDocument:
    ceiling = (
        CredentialCeiling(
            audience="filesystem",
            scopes=frozenset({"read"}),
            maximum_ttl_seconds=30,
        )
        if credential
        else None
    )
    return PolicyDocument(
        metadata=PolicyMetadata(id="mcp-protected", revision=1),
        defaults=PolicyDefaults(),
        rules=(
            PolicyRule(
                id="allow-read",
                priority=100,
                effect=Effect.ALLOW,
                action=ActionMatcher(tools=frozenset({"read_file"})),
                provenance=ProvenanceMatcher(contains_any=frozenset({ProvenanceLabel.UNVERIFIED})),
                credential=ceiling,
            ),
        ),
    )


def principal() -> Principal:
    return Principal(
        agent_id="agent",
        workload_id="workload",
        tenant_id="tenant",
        identity_verified=False,
    )


class FakeTransport:
    def __init__(self, response: dict[str, Any] | None = None, exc: Exception | None = None):
        self.response = response
        self.exc = exc
        self.payloads: list[bytes] = []
        self.execution_ids: list[str] = []
        self.controls: list[bytes] = []

    def request(self, execution_id, payload, *, timeout_seconds, cancelled):
        del timeout_seconds
        self.execution_ids.append(execution_id)
        self.payloads.append(payload)
        if cancelled():
            raise DefiniteExecutionFailure("mcp.cancelled_before_dispatch")
        if self.exc is not None:
            raise self.exc
        assert self.response is not None
        response = dict(self.response)
        response["id"] = execution_id
        return response

    def send_control(self, payload: bytes) -> bool:
        self.controls.append(payload)
        return True

    def cancel_execution(self, execution_id: str) -> None:
        self.execution_ids.append("cancel:" + execution_id)


class RelayTransport(FakeTransport):
    def __init__(self):
        super().__init__()
        self.failures: list[str] = []

    def deliver_response(self, message):
        del message
        return False

    def owns_execution_id(self, execution_id):
        del execution_id
        return False

    def fail_all_pending(self, code):
        self.failures.append(code)


def prepared_proxy(service, *, policy=None, capacity=64) -> MCPProtectedStdioProxy:
    proxy = MCPProtectedStdioProxy(
        service,
        policy or allow_policy(),
        principal(),
        "filesystem",
        ["python", "server.py"],
        request_id_capacity=capacity,
        execution_timeout_seconds=0.2,
    )
    proxy.session.note_initialize_request(1, SUPPORTED_PROTOCOL_PROFILE)
    proxy.session.observe_initialize_response(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"protocolVersion": SUPPORTED_PROTOCOL_PROFILE},
        }
    )
    assert proxy.session.schemas.observe_tools_list_page(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "inputSchema": {"type": "object"},
                    }
                ]
            },
        },
        requested_cursor=None,
    )
    return proxy


def call_message(request_id: int = 3, *, extra_params=None) -> dict[str, Any]:
    params: dict[str, Any] = {
        "name": "read_file",
        "arguments": {"path": "README.md"},
    }
    if extra_params:
        params.update(extra_params)
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params}


def execute_direct(proxy, transport, message=None) -> dict[str, Any]:
    output = io.BytesIO()
    proxy._execute_tools_call(
        message or call_message(),
        output,
        threading.Lock(),
        transport,
    )
    return json.loads(output.getvalue())


def test_request_id_reuse_is_always_rejected_and_never_evicted() -> None:
    binding = MCPServerBinding.for_launch("server", ["python", "server.py"])
    session = MCPProtectedSession(binding, request_id_capacity=2)
    assert session.register_request_id(1, "a") is None
    assert session.register_request_id(1, "a") == "mcp.request_id_reused"
    assert session.register_request_id(2, "b") is None
    assert session.register_request_id(3, "c") == "mcp.request_id_registry_exhausted"
    assert session.register_request_id(1, "different") == "mcp.request_id_reused"


def test_unsupported_negotiated_profile_blocks_tools_call_before_reservation(
    signer, verifier, state
) -> None:
    service = DecisionLockService(signer, verifier, state)
    proxy = MCPProtectedStdioProxy(
        service, allow_policy(), principal(), "filesystem", ["python", "server.py"]
    )
    proxy.session.note_initialize_request(1, "2025-03-26")
    proxy.session.observe_initialize_response(
        {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2026-07-28"}}
    )
    response = execute_direct(proxy, FakeTransport(), call_message())
    assert response["error"]["code"] == PROTECTED_PROFILE_UNSUPPORTED
    assert state.list_executions() == ()


def test_schema_pagination_must_complete_before_resolution() -> None:
    binding = MCPServerBinding.for_launch("server", ["python", "server.py"])
    cache = SessionToolSchemaCache(binding)
    assert cache.observe_tools_list_page(
        {
            "result": {
                "tools": [{"name": "a", "inputSchema": {"type": "object"}}],
                "nextCursor": "page-2",
            }
        },
        requested_cursor=None,
    )
    assert cache.resolve("a") is None
    assert cache.observe_tools_list_page(
        {"result": {"tools": [{"name": "b", "inputSchema": {"type": "object"}}]}},
        requested_cursor="page-2",
    )
    assert cache.resolve("a") is not None
    assert cache.resolve("b") is not None


def test_schema_wrong_pagination_cursor_invalidates_inventory() -> None:
    binding = MCPServerBinding.for_launch("server", ["python", "server.py"])
    cache = SessionToolSchemaCache(binding)
    assert cache.observe_tools_list_page(
        {
            "result": {
                "tools": [{"name": "a", "inputSchema": {"type": "object"}}],
                "nextCursor": "expected",
            }
        },
        requested_cursor=None,
    )
    assert not cache.observe_tools_list_page({"result": {"tools": []}}, requested_cursor="wrong")
    assert cache.resolve("a") is None


def test_tool_list_change_notification_invalidates_cache(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    assert proxy.session.schemas.resolve("read_file") is not None
    output = io.BytesIO()
    transport = RelayTransport()
    done = threading.Event()
    proxy._relay_server(
        io.BytesIO(b'{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{}}\n'),
        output,
        threading.Lock(),
        transport,  # type: ignore[arg-type]
        done,
    )
    assert done.is_set()
    assert proxy.session.schemas.resolve("read_file") is None


def test_dispatch_is_new_request_derived_from_verified_execution_and_omits_progress_token(
    signer, verifier, state
) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport({"jsonrpc": "2.0", "result": {"content": [{"text": "ok"}]}})
    message = call_message(extra_params={"_meta": {"progressToken": "client-token"}})
    response = execute_direct(proxy, transport, message)
    assert response["id"] == 3
    sent = json.loads(transport.payloads[0])
    assert sent["id"].startswith("exec_")
    assert sent["id"] != message["id"]
    assert sent["method"] == "tools/call"
    assert sent["params"] == {
        "name": "read_file",
        "arguments": {"path": "README.md"},
    }
    assert "_meta" not in sent["params"]
    record = state.list_executions()[0]
    assert record.state == ExecutionState.SUCCEEDED
    assert record.request_id.startswith("mcpreq_")
    assert record.request_id != str(message["id"])


def test_provider_response_is_preserved_except_client_correlation_id(
    signer, verifier, state
) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    provider_result = {
        "jsonrpc": "2.0",
        "result": {
            "content": [{"type": "text", "text": "password=legitimate-tool-output"}],
            "custom": {"unchanged": True},
        },
    }
    response = execute_direct(proxy, FakeTransport(provider_result))
    assert response["id"] == 3
    assert response["result"] == provider_result["result"]


@pytest.mark.parametrize(
    ("provider_response", "expected_state"),
    [
        ({"jsonrpc": "2.0", "result": {"content": []}}, ExecutionState.SUCCEEDED),
        ({"jsonrpc": "2.0", "result": {"isError": True, "content": []}}, ExecutionState.FAILED),
        (
            {"jsonrpc": "2.0", "error": {"code": -32099, "message": "provider failed"}},
            ExecutionState.FAILED,
        ),
    ],
)
def test_provider_results_map_to_durable_terminal_states(
    provider_response, expected_state, signer, verifier, state
) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    execute_direct(proxy, FakeTransport(provider_response))
    assert state.list_executions()[0].state == expected_state


def test_failed_provider_response_is_not_rewritten_as_retry_safe(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    response = execute_direct(
        proxy,
        FakeTransport({"jsonrpc": "2.0", "error": {"code": -1, "message": "definite report"}}),
    )
    assert response["error"] == {"code": -1, "message": "definite report"}
    assert "retry_safe" not in response["error"]
    assert state.list_executions()[0].state == ExecutionState.FAILED


@pytest.mark.parametrize(
    "exc",
    [
        AmbiguousExecutionError("mcp.response_timeout"),
        AmbiguousExecutionError("mcp.server_eof"),
        AmbiguousExecutionError("mcp.downstream_write_ambiguous"),
        AmbiguousExecutionError("mcp.cancelled_after_dispatch"),
    ],
)
def test_ambiguous_transport_failures_map_to_unknown(exc, signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    response = execute_direct(proxy, FakeTransport(exc=exc))
    record = state.list_executions()[0]
    assert record.state == ExecutionState.UNKNOWN
    assert response["error"]["data"]["retry_safe"] is False


def test_definite_prewrite_failure_maps_to_failed_but_not_safe_retry(
    signer, verifier, state
) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    response = execute_direct(
        proxy, FakeTransport(exc=DefiniteExecutionFailure("mcp.process_unavailable"))
    )
    record = state.list_executions()[0]
    assert record.state == ExecutionState.FAILED
    assert response["error"]["data"]["retry_safe"] is False


def test_server_instance_substitution_blocks_dispatch(signer, verifier, state) -> None:
    service = DecisionLockService(signer, verifier, state)
    proxy = prepared_proxy(service)
    transport = FakeTransport({"jsonrpc": "2.0", "result": {}})
    resolved = proxy.session.schemas.resolve("read_file")
    assert resolved is not None
    from decisionlock.adapters.protocols.mcp.intent import intent_from_tools_call
    from decisionlock.domain import Resource

    resource = Resource(
        type="mcp_stdio_server",
        id=proxy.binding.server_id,
        attributes={
            "transport": "stdio",
            "server_instance_id": "mcpsrv_substituted",
            "launch_fingerprint": proxy.binding.launch_fingerprint,
            "protocol_profile": SUPPORTED_PROTOCOL_PROFILE,
        },
    )
    message = call_message()
    intent = intent_from_tools_call(
        message,
        principal=principal(),
        server=proxy.binding.server_id,
        tool_schema=resolved.schema,
        resource=resource,
    )
    receipt = service.authorize(intent, allow_policy())
    executor = MCPProtectedExecutor(
        session=proxy.session,
        transport=transport,  # type: ignore[arg-type]
        client_request_key=proxy.session.request_key(3),
        timeout_seconds=1,
    )
    outcome = service.execute_protected(
        intent, receipt, None, executor, current_policy=allow_policy()
    )
    assert outcome.status == ExecutionStatus.FAILURE
    assert transport.payloads == []


def test_launch_fingerprint_substitution_blocks_dispatch(signer, verifier, state) -> None:
    service = DecisionLockService(signer, verifier, state)
    proxy = prepared_proxy(service)
    transport = FakeTransport({"jsonrpc": "2.0", "result": {}})
    resolved = proxy.session.schemas.resolve("read_file")
    assert resolved is not None
    from decisionlock.adapters.protocols.mcp.intent import intent_from_tools_call
    from decisionlock.domain import Resource

    resource = Resource(
        type="mcp_stdio_server",
        id=proxy.binding.server_id,
        attributes={
            "transport": "stdio",
            "server_instance_id": proxy.binding.server_instance_id,
            "launch_fingerprint": "0" * 64,
            "protocol_profile": SUPPORTED_PROTOCOL_PROFILE,
        },
    )
    intent = intent_from_tools_call(
        call_message(),
        principal=principal(),
        server=proxy.binding.server_id,
        tool_schema=resolved.schema,
        resource=resource,
    )
    receipt = service.authorize(intent, allow_policy())
    outcome = service.execute_protected(
        intent,
        receipt,
        None,
        MCPProtectedExecutor(
            session=proxy.session,
            transport=transport,  # type: ignore[arg-type]
            client_request_key=proxy.session.request_key(3),
            timeout_seconds=1,
        ),
        current_policy=allow_policy(),
    )
    assert outcome.status == ExecutionStatus.FAILURE
    assert transport.payloads == []


def test_final_schema_change_is_detected_before_downstream_write(signer, verifier, state) -> None:
    service = DecisionLockService(signer, verifier, state)
    proxy = prepared_proxy(service)
    transport = FakeTransport({"jsonrpc": "2.0", "result": {}})
    resolved = proxy.session.schemas.resolve("read_file")
    assert resolved is not None
    from decisionlock.adapters.protocols.mcp.intent import intent_from_tools_call
    from decisionlock.domain import Resource

    resource = Resource(
        type="mcp_stdio_server",
        id=proxy.binding.server_id,
        attributes={
            "transport": "stdio",
            "server_instance_id": proxy.binding.server_instance_id,
            "launch_fingerprint": proxy.binding.launch_fingerprint,
            "protocol_profile": SUPPORTED_PROTOCOL_PROFILE,
        },
    )
    intent = intent_from_tools_call(
        call_message(),
        principal=principal(),
        server=proxy.binding.server_id,
        tool_schema=resolved.schema,
        resource=resource,
    )
    receipt = service.authorize(intent, allow_policy())
    proxy.session.schemas.invalidate()
    outcome = service.execute_protected(
        intent,
        receipt,
        None,
        MCPProtectedExecutor(
            session=proxy.session,
            transport=transport,  # type: ignore[arg-type]
            client_request_key=proxy.session.request_key(3),
            timeout_seconds=1,
        ),
        current_policy=allow_policy(),
    )
    assert outcome.status == ExecutionStatus.FAILURE
    assert transport.payloads == []


def test_credential_bound_call_fails_closed_before_reservation(signer, verifier, state) -> None:
    proxy = prepared_proxy(
        DecisionLockService(signer, verifier, state), policy=allow_policy(credential=True)
    )
    response = execute_direct(
        proxy, FakeTransport({"jsonrpc": "2.0", "result": {"secret": "never"}})
    )
    assert "credential-bound" in response["error"]["message"]
    assert state.list_executions() == ()
    raw = json.dumps(response)
    assert "credential_handle" not in raw


def test_unsupported_execution_metadata_fails_closed(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport({"jsonrpc": "2.0", "result": {}})
    response = execute_direct(proxy, transport, call_message(extra_params={"task": {"id": "x"}}))
    assert response["error"]["code"] == -32602
    assert transport.payloads == []
    assert state.list_executions() == ()


def test_custom_method_is_not_passthrough(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport()
    assert (
        proxy._supported_passthrough(
            {"jsonrpc": "2.0", "id": 9, "method": "vendor/custom", "params": {}},
            transport,  # type: ignore[arg-type]
        )
        is None
    )
    assert transport.controls == []


def test_batch_containing_tools_call_is_rejected_not_forwarded(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport()
    output = io.BytesIO()
    workers: list[threading.Thread] = []
    done = threading.Event()
    proxy._relay_client(
        io.BytesIO(
            (
                json.dumps([call_message(), {"jsonrpc": "2.0", "id": 4, "method": "ping"}]) + "\n"
            ).encode()
        ),
        output,
        threading.Lock(),
        transport,  # type: ignore[arg-type]
        workers,
        done,
    )
    response = json.loads(output.getvalue())
    assert response["error"]["code"] == PROTECTED_REQUEST_REJECTED
    assert transport.controls == []


def test_reused_client_id_rejected_by_client_relay_even_after_first_request(
    signer, verifier, state
) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport()
    output = io.BytesIO()
    workers: list[threading.Thread] = []
    done = threading.Event()
    payload = (
        json.dumps({"jsonrpc": "2.0", "id": 10, "method": "ping", "params": {}})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 10, "method": "ping", "params": {}})
        + "\n"
    ).encode()
    proxy._relay_client(
        io.BytesIO(payload),
        output,
        threading.Lock(),
        transport,  # type: ignore[arg-type]
        workers,
        done,
    )
    assert len(transport.controls) == 1
    assert b"mcp.request_id_reused" in output.getvalue()


def test_request_registry_exhaustion_fails_closed_in_relay(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state), capacity=1)
    transport = FakeTransport()
    output = io.BytesIO()
    done = threading.Event()
    proxy._relay_client(
        io.BytesIO(
            b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}\n'
            b'{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}\n'
        ),
        output,
        threading.Lock(),
        transport,  # type: ignore[arg-type]
        [],
        done,
    )
    assert len(transport.controls) == 1
    assert b"mcp.request_id_registry_exhausted" in output.getvalue()


def test_cancel_notification_translates_client_id_to_execution_id(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport()
    key = proxy.session.request_key(3)
    proxy.session.bind_execution(key, "exec_bound")
    payload = proxy._supported_passthrough(
        {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 3, "reason": "stop"},
        },
        transport,  # type: ignore[arg-type]
    )
    assert payload is not None
    message = json.loads(payload)
    assert message["params"]["requestId"] == "exec_bound"
    assert "cancel:exec_bound" in transport.execution_ids


class FakeStdin(io.BytesIO):
    def flush(self) -> None:
        return None


class FakeProcess:
    def __init__(self) -> None:
        self.stdin = FakeStdin()
        self.returncode = None
        self.dead = False

    def poll(self):
        return 1 if self.dead else None


def test_transport_correlates_out_of_order_responses_without_cross_delivery() -> None:
    process = FakeProcess()
    transport = MCPProtectedTransport(process, write_lock=threading.Lock())  # type: ignore[arg-type]
    results: dict[str, dict[str, Any]] = {}

    def invoke(execution_id: str) -> None:
        results[execution_id] = transport.request(
            execution_id,
            (execution_id + "\n").encode(),
            timeout_seconds=1,
            cancelled=lambda: False,
        )

    first = threading.Thread(target=invoke, args=("exec_1",))
    second = threading.Thread(target=invoke, args=("exec_2",))
    first.start()
    second.start()
    deadline = time.monotonic() + 1
    while len(process.stdin.getvalue().splitlines()) < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert transport.deliver_response({"jsonrpc": "2.0", "id": "exec_2", "result": {"n": 2}})
    assert transport.deliver_response({"jsonrpc": "2.0", "id": "exec_1", "result": {"n": 1}})
    first.join(1)
    second.join(1)
    assert results["exec_1"]["result"]["n"] == 1
    assert results["exec_2"]["result"]["n"] == 2
    assert transport.owns_execution_id("exec_1")
    assert transport.owns_execution_id("exec_2")


def test_transport_classifies_prewrite_and_postwrite_cancellation() -> None:
    process = FakeProcess()
    transport = MCPProtectedTransport(process, write_lock=threading.Lock())  # type: ignore[arg-type]
    with pytest.raises(DefiniteExecutionFailure, match="cancelled_before"):
        transport.request(
            "exec_before",
            b"request\n",
            timeout_seconds=1,
            cancelled=lambda: True,
        )

    cancellation = threading.Event()
    error: list[Exception] = []

    def invoke() -> None:
        try:
            transport.request(
                "exec_after",
                b"request\n",
                timeout_seconds=1,
                cancelled=cancellation.is_set,
            )
        except Exception as exc:  # noqa: BLE001 - deliberate assertion capture
            error.append(exc)

    thread = threading.Thread(target=invoke)
    thread.start()
    deadline = time.monotonic() + 1
    while b"request\n" not in process.stdin.getvalue() and time.monotonic() < deadline:
        time.sleep(0.005)
    cancellation.set()
    thread.join(1)
    assert isinstance(error[0], AmbiguousExecutionError)
    assert str(error[0]) == "mcp.cancelled_after_dispatch"


def test_launch_fingerprint_does_not_expose_secret_flag_value(tmp_path: Path) -> None:
    binding = MCPServerBinding.for_launch(
        "server",
        ["python", "server.py", "--api-key", "super-secret-value"],
        cwd=tmp_path,
    )
    rendered = json.dumps(binding.__dict__)
    assert "super-secret-value" not in rendered
    assert binding.launch_fingerprint.startswith("sha256:")
    assert len(binding.launch_fingerprint.removeprefix("sha256:")) == 64


def test_concurrent_duplicate_tools_call_id_dispatches_once(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport({"jsonrpc": "2.0", "result": {"content": []}})
    output = io.BytesIO()
    workers: list[threading.Thread] = []
    done = threading.Event()
    line = json.dumps(call_message(77)) + "\n"
    proxy._relay_client(
        io.BytesIO((line + line).encode()),
        output,
        threading.Lock(),
        transport,  # type: ignore[arg-type]
        workers,
        done,
    )
    for worker in workers:
        worker.join(1)
    assert len(transport.payloads) == 1
    assert b"mcp.request_id_reused" in output.getvalue()
    assert len(state.list_executions()) == 1


def test_top_level_extension_field_fails_closed(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport({"jsonrpc": "2.0", "result": {}})
    message = call_message()
    message["task"] = {"id": "newer-semantics"}
    response = execute_direct(proxy, transport, message)
    assert response["error"]["code"] == PROTECTED_REQUEST_REJECTED
    assert transport.payloads == []
    assert state.list_executions() == ()


def test_decisionlock_launch_secret_never_enters_execution_state_or_audit(
    tmp_path, signer, verifier
) -> None:
    from decisionlock.adapters.storage.sqlite import SQLiteState

    state = SQLiteState(tmp_path / "state.sqlite")
    service = DecisionLockService(signer, verifier, state)
    proxy = MCPProtectedStdioProxy(
        service,
        allow_policy(),
        principal(),
        "filesystem",
        ["python", "server.py", "--api-key", "decisionlock-owned-secret"],
    )
    proxy.session.note_initialize_request(1, SUPPORTED_PROTOCOL_PROFILE)
    proxy.session.observe_initialize_response(
        {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": SUPPORTED_PROTOCOL_PROFILE}}
    )
    assert proxy.session.schemas.observe_tools_list_page(
        {"result": {"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]}},
        requested_cursor=None,
    )
    response = execute_direct(
        proxy, FakeTransport({"jsonrpc": "2.0", "result": {"content": [{"text": "ok"}]}})
    )
    assert "decisionlock-owned-secret" not in json.dumps(response)
    assert b"decisionlock-owned-secret" not in state.path.read_bytes()


def test_server_binding_rejects_missing_identity_or_command() -> None:
    with pytest.raises(ValueError, match="server_id"):
        MCPServerBinding.for_launch("", ["python"])
    with pytest.raises(ValueError, match="server command"):
        MCPServerBinding.for_launch("server", [])


def test_schema_cache_rejects_invalid_stale_and_conflicting_pages() -> None:
    binding = MCPServerBinding.for_launch("server", ["python"])
    cache = SessionToolSchemaCache(binding, ttl_seconds=1)
    assert not cache.observe_tools_list_page({"result": {"tools": "bad"}}, requested_cursor=None)
    assert cache.observe_tools_list_page(
        {
            "result": {
                "tools": [{"name": "a", "inputSchema": {"type": "object"}}],
                "nextCursor": "next",
            }
        },
        requested_cursor=None,
    )
    assert not cache.observe_tools_list_page(
        {"result": {"tools": [{"name": "a", "inputSchema": {"type": "string"}}]}},
        requested_cursor="next",
    )
    assert cache.resolve("a") is None
    assert cache.observe_tools_list_page(
        {"result": {"tools": [{"name": "a", "inputSchema": {"type": "object"}}]}},
        requested_cursor=None,
        observed_at=time_to_datetime(0),
    )
    assert cache.resolve("a", now=time_to_datetime(2)) is None


def time_to_datetime(seconds: int):
    from datetime import UTC, datetime, timedelta

    return datetime(2025, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)


def test_session_rejects_invalid_ids_and_ignores_unmatched_responses() -> None:
    session = MCPProtectedSession(MCPServerBinding.for_launch("server", ["python"]))
    with pytest.raises(ValueError, match="string or integer"):
        session.register_request_id(True, "digest")
    assert session.observe_tools_list_response({"id": 999, "result": {"tools": []}}) is None
    session.observe_initialize_response(
        {"id": 999, "result": {"protocolVersion": SUPPORTED_PROTOCOL_PROFILE}}
    )
    assert session.negotiated_profile is None
    assert not session.protected_profile_supported


def test_supported_control_surface_is_reconstructed_and_custom_fields_are_rejected(
    signer, verifier, state
) -> None:
    proxy = MCPProtectedStdioProxy(
        DecisionLockService(signer, verifier, state),
        allow_policy(),
        principal(),
        "filesystem",
        ["python"],
    )
    transport = FakeTransport()
    initialize = proxy._supported_passthrough(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": SUPPORTED_PROTOCOL_PROFILE,
                "capabilities": {},
                "clientInfo": {"name": "client", "version": "1"},
            },
        },
        transport,  # type: ignore[arg-type]
    )
    assert json.loads(initialize)["params"]["protocolVersion"] == SUPPORTED_PROTOCOL_PROFILE
    assert (
        proxy._supported_passthrough(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            transport,  # type: ignore[arg-type]
        )
        is not None
    )
    assert (
        proxy._supported_passthrough(
            {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}},
            transport,  # type: ignore[arg-type]
        )
        is not None
    )
    tools_list = proxy._supported_passthrough(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"cursor": "c"}},
        transport,  # type: ignore[arg-type]
    )
    assert json.loads(tools_list)["params"] == {"cursor": "c"}
    assert (
        proxy._supported_passthrough(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "initialize",
                "params": {
                    "protocolVersion": SUPPORTED_PROTOCOL_PROFILE,
                    "capabilities": {},
                    "clientInfo": {},
                    "task": {},
                },
            },
            transport,  # type: ignore[arg-type]
        )
        is None
    )


def test_transport_prewrite_dead_process_and_timeout_after_write() -> None:
    process = FakeProcess()
    process.dead = True
    transport = MCPProtectedTransport(process, write_lock=threading.Lock())  # type: ignore[arg-type]
    with pytest.raises(DefiniteExecutionFailure, match="process_unavailable"):
        transport.request("exec_dead", b"x\n", timeout_seconds=1, cancelled=lambda: False)

    live = FakeProcess()
    transport = MCPProtectedTransport(live, write_lock=threading.Lock())  # type: ignore[arg-type]
    with pytest.raises(AmbiguousExecutionError, match="response_timeout"):
        transport.request("exec_timeout", b"x\n", timeout_seconds=0.01, cancelled=lambda: False)
    assert not transport.deliver_response({"jsonrpc": "2.0", "id": "unknown", "result": {}})
    live.dead = True
    assert not transport.send_control(b"ping\n")


def test_proxy_rejects_invalid_settings_and_is_single_launch(signer, verifier, state) -> None:
    service = DecisionLockService(signer, verifier, state)
    with pytest.raises(ValueError, match="server command"):
        MCPProtectedStdioProxy(service, allow_policy(), principal(), "server", [])
    with pytest.raises(ValueError, match="execution timeout"):
        MCPProtectedStdioProxy(
            service,
            allow_policy(),
            principal(),
            "server",
            ["python"],
            execution_timeout_seconds=0,
        )
    proxy = MCPProtectedStdioProxy(service, allow_policy(), principal(), "server", ["python"])
    proxy._has_run = True
    with pytest.raises(RuntimeError, match="single-launch"):
        proxy.run()


def test_stdio_provider_result_with_finite_floats(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport(
        {"jsonrpc": "2.0", "result": {"score": 0.5, "price": 12.34, "ratio": 1e-6}}
    )
    response = execute_direct(proxy, transport, call_message(request_id=101))
    assert "result" in response
    assert response["result"] == {"score": 0.5, "price": 12.34, "ratio": 1e-6}
    executions = state.list_executions()
    assert len(executions) == 1
    record = executions[0]
    assert record.state == ExecutionState.SUCCEEDED
    assert record.result_digest is not None
    assert record.result_digest.startswith("sha256:")
    assert record.error_code is None


def test_stdio_digest_failure_maintains_caller_ledger_consistency(signer, verifier, state) -> None:
    proxy = prepared_proxy(DecisionLockService(signer, verifier, state))
    transport = FakeTransport({"jsonrpc": "2.0", "result": {"non_finite": float("nan")}})
    response = execute_direct(proxy, transport, call_message(request_id=102))
    assert "error" in response
    assert response["error"]["code"] == PROTECTED_OUTCOME_UNKNOWN
    executions = state.list_executions()
    assert len(executions) == 1
    record = executions[0]
    assert record.state == ExecutionState.UNKNOWN
    assert record.error_code == "execution.executor_exception"
