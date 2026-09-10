from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import Ed25519Signer
from agentguard.adapters.executor import DeterministicFakeExecutor
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.application import AgentGuardService, ExecutionPersistenceError
from agentguard.domain import (
    AuditEventType,
    CredentialGrant,
    CredentialRequest,
    ExecutionState,
    ExecutionStatus,
)
from agentguard.engine.canonical import digest
from agentguard.engine.execution import (
    ExecutionGuardError,
    authorize_execution,
    validate_execution_authority,
)
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import issue_decision_receipt


def _credential_flow(intent, policy, signer, verifier, state):
    broker = MockCredentialBroker()
    service = AgentGuardService(signer, verifier, state, broker.verifier)
    receipt = service.authorize(intent, policy)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="protected-execution-credential",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    grant = service.request_credential(intent, receipt, request, broker)
    return service, broker, receipt, grant


def test_exact_action_binding_and_raw_input_separation(intent, policy, signer, verifier, state):
    service, _, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    executor = DeterministicFakeExecutor()

    mutated = intent.model_copy(
        update={
            "action": intent.action.model_copy(update={"tool": "refund.delete"}),
            "arguments": {**intent.arguments, "order_id": "attacker-controlled"},
        }
    )
    with pytest.raises(ExecutionGuardError, match="action_digest_mismatch"):
        service.execute_protected(
            mutated,
            receipt,
            grant,
            executor,
            current_policy=policy,
        )
    assert executor.calls == []

    outcome = service.execute_protected(
        intent,
        receipt,
        grant,
        executor,
        current_policy=policy,
    )
    assert outcome.status == ExecutionStatus.SUCCESS
    assert len(executor.calls) == 1
    trusted = executor.calls[0]
    assert trusted.intent.action == intent.action
    assert trusted.intent.resource == intent.resource
    assert trusted.intent.arguments == intent.arguments
    assert trusted.intent.action.tool != mutated.action.tool
    assert trusted.intent.arguments != mutated.arguments


def test_post_validation_in_place_mutation_cannot_reach_executor(
    intent, policy, signer, verifier, state, monkeypatch
):
    caller_intent = intent.model_copy(deep=True)
    service, _, receipt, grant = _credential_flow(caller_intent, policy, signer, verifier, state)
    executor = DeterministicFakeExecutor()
    original_arguments = dict(caller_intent.arguments)
    original_reserve = state.reserve_execution

    def reserve_then_mutate(verified, reserved_at):
        result = original_reserve(verified, reserved_at)
        caller_intent.arguments["order_id"] = "mutated-after-validation"
        return result

    monkeypatch.setattr(state, "reserve_execution", reserve_then_mutate)
    outcome = service.execute_protected(
        caller_intent,
        receipt,
        grant,
        executor,
        current_policy=policy,
    )

    assert outcome.status == ExecutionStatus.SUCCESS
    assert caller_intent.arguments != original_arguments
    assert executor.calls[0].intent.arguments == original_arguments


def test_preflight_validation_is_non_consuming(intent, policy, signer, verifier, state):
    service, broker, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)

    authorize_execution(
        intent,
        receipt,
        grant,
        verifier,
        state,
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
    )
    authorize_execution(
        intent,
        receipt,
        grant,
        verifier,
        state,
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
    )
    assert state.list_executions() == ()

    executor = DeterministicFakeExecutor()
    outcome = service.execute_protected(
        intent,
        receipt,
        grant,
        executor,
        current_policy=policy,
    )
    assert outcome.status == ExecutionStatus.SUCCESS
    assert len(executor.calls) == 1


def test_replay_has_one_reservation_winner(intent, policy, signer, verifier, state):
    service, _, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    executor = DeterministicFakeExecutor()

    first = service.execute_protected(
        intent,
        receipt,
        grant,
        executor,
        current_policy=policy,
    )
    with pytest.raises(ExecutionGuardError, match="decision_receipt.replayed"):
        service.execute_protected(
            intent,
            receipt,
            grant,
            executor,
            current_policy=policy,
        )

    assert first.status == ExecutionStatus.SUCCESS
    assert len(executor.calls) == 1
    records = state.list_executions()
    assert len(records) == 1
    assert records[0].state == ExecutionState.SUCCEEDED


def test_concurrent_replay_has_one_reservation_winner(intent, policy, signer, verifier, state):
    service, _, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    executor = DeterministicFakeExecutor()

    def run() -> str:
        try:
            result = service.execute_protected(
                intent,
                receipt,
                grant,
                executor,
                current_policy=policy,
            )
            return result.status.value
        except ExecutionGuardError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))

    assert sorted(results) == ["decision_receipt.replayed", "success"]
    assert len(executor.calls) == 1
    assert len(state.list_executions()) == 1


def test_reserved_failure_never_calls_executor(
    intent, policy, signer, verifier, state, monkeypatch
):
    service, _, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    executor = DeterministicFakeExecutor()
    original_append = state.append

    def fail_after_reservation(event):
        if event.event_type == AuditEventType.RECEIPT_CONSUMED:
            raise RuntimeError("synthetic audit failure")
        return original_append(event)

    monkeypatch.setattr(state, "append", fail_after_reservation)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        service.execute_protected(
            intent,
            receipt,
            grant,
            executor,
            current_policy=policy,
        )

    assert executor.calls == []
    records = state.list_executions()
    assert len(records) == 1
    assert records[0].state == ExecutionState.RESERVED
    assert service.recover_incomplete_executions() == ()
    assert state.get_execution(records[0].execution_id).state == ExecutionState.RESERVED

    monkeypatch.setattr(state, "append", original_append)
    outcome = service.resume_reserved_execution(
        records[0].execution_id,
        intent,
        receipt,
        grant,
        executor,
        current_policy=policy,
    )
    assert outcome.status == ExecutionStatus.SUCCESS
    assert len(executor.calls) == 1
    assert state.get_execution(records[0].execution_id).state == ExecutionState.SUCCEEDED


@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_state"),
    [
        ("success", ExecutionStatus.SUCCESS, ExecutionState.SUCCEEDED),
        ("failure", ExecutionStatus.FAILURE, ExecutionState.FAILED),
        ("unknown", ExecutionStatus.UNKNOWN, ExecutionState.UNKNOWN),
        ("raise_failure", ExecutionStatus.FAILURE, ExecutionState.FAILED),
        ("raise_unknown", ExecutionStatus.UNKNOWN, ExecutionState.UNKNOWN),
        ("raise", ExecutionStatus.UNKNOWN, ExecutionState.UNKNOWN),
    ],
)
def test_executor_outcomes_are_durably_classified(
    intent,
    policy,
    signer,
    verifier,
    state,
    mode,
    expected_status,
    expected_state,
):
    service, _, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    executor = DeterministicFakeExecutor(mode=mode)

    outcome = service.execute_protected(
        intent,
        receipt,
        grant,
        executor,
        current_policy=policy,
    )

    assert outcome.status == expected_status
    record = state.get_execution(outcome.execution_id)
    assert record is not None
    assert record.state == expected_state
    assert record.decision_id == outcome.decision_id == receipt.decision_id
    assert record.trace_id == outcome.trace_id == receipt.trace_id


def test_recovery_marks_stranded_dispatching_unknown_without_redispatch(
    intent, policy, signer, verifier, tmp_path
):
    path = tmp_path / "recovery.sqlite"
    state = SQLiteState(path)
    _, broker, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    verified = validate_execution_authority(
        intent,
        receipt,
        grant,
        verifier,
        execution_id="exec_recovery",
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
    )
    assert state.reserve_execution(verified, verified.verified_at) is None
    state.mark_execution_dispatching(verified)

    reopened = SQLiteState(path)
    recovery_service = AgentGuardService(signer, verifier, reopened, broker.verifier)
    executor = DeterministicFakeExecutor()
    recovered = recovery_service.recover_incomplete_executions()

    assert executor.calls == []
    assert len(recovered) == 1
    record = reopened.get_execution(verified.execution_id)
    assert record is not None
    assert record.state == ExecutionState.UNKNOWN
    assert record.error_code == "execution.recovered_ambiguous_dispatch"
    assert recovery_service.recover_incomplete_executions() == ()


def test_execution_audit_events_correlate_decision_and_execution(
    intent, policy, signer, verifier, state
):
    service, _, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    outcome = service.execute_protected(
        intent,
        receipt,
        grant,
        DeterministicFakeExecutor(),
        current_policy=policy,
    )

    events = [event for event in state.list_events() if event.execution_id == outcome.execution_id]
    assert [event.event_type for event in events] == [
        AuditEventType.RECEIPT_CONSUMED,
        AuditEventType.EXECUTION_STARTED,
        AuditEventType.EXECUTION_SUCCEEDED,
    ]
    assert all(event.decision_id == receipt.decision_id for event in events)
    assert all(event.data["intent_digest"] == receipt.intent_digest for event in events)


def test_credential_material_is_confined_from_protected_execution_api(
    intent, policy, signer, verifier, state
):
    service, _, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    assert grant.credential_handle is not None
    executor = DeterministicFakeExecutor()

    outcome = service.execute_protected(
        intent,
        receipt,
        grant,
        executor,
        current_policy=policy,
    )

    assert outcome.model_dump().get("credential_handle") is None
    trusted = executor.calls[0]
    authority = trusted.credential_authority
    assert authority is not None
    assert not hasattr(authority, "credential_handle")
    assert grant.credential_handle not in trusted.model_dump_json()
    assert grant.credential_handle.encode() not in state.path.read_bytes()
    audit_json = "\n".join(event.model_dump_json() for event in state.list_events())
    assert grant.credential_handle not in audit_json


def test_terminal_persistence_failure_leaves_dispatching_for_unknown_recovery(
    intent, policy, signer, verifier, state, monkeypatch
):
    service, _, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    executor = DeterministicFakeExecutor()
    original_finish = state.finish_execution

    def fail_finish(*args, **kwargs):
        raise RuntimeError("synthetic terminal persistence failure")

    monkeypatch.setattr(state, "finish_execution", fail_finish)
    with pytest.raises(ExecutionPersistenceError, match="terminal_persistence_failed"):
        service.execute_protected(
            intent,
            receipt,
            grant,
            executor,
            current_policy=policy,
        )
    assert len(executor.calls) == 1
    record = state.list_executions()[0]
    assert record.state == ExecutionState.DISPATCHING

    monkeypatch.setattr(state, "finish_execution", original_finish)
    recovered = service.recover_incomplete_executions()
    assert len(recovered) == 1
    assert state.get_execution(record.execution_id).state == ExecutionState.UNKNOWN


def _reserve_with_expired_authorization(intent, policy, signer, verifier, state, execution_id):
    """Validate while the receipt is live, then reserve; wall-clock time is past expiry.

    Public paths cannot separate validation time from dispatch time, so the backdated
    fixture is the only way to place a RESERVED record past its authorization expiry.
    """
    broker_signer = Ed25519Signer.generate("mock-broker-ed25519")
    broker = MockCredentialBroker(signer=broker_signer)
    issued_at = datetime.now(UTC) - timedelta(seconds=300)
    live_at = issued_at + timedelta(seconds=30)
    evaluation = evaluate_policy(policy, intent, now=live_at)
    receipt = issue_decision_receipt(intent, evaluation, signer, now=issued_at, ttl_seconds=60)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    handle = f"opaque://expired-authorization/{execution_id}"
    grant = broker.attest_for_testing(
        CredentialGrant(
            grant_id="grant_expired_" + execution_id,
            issuance_id="iss_expired_" + execution_id,
            decision_id=receipt.decision_id,
            trace_id=receipt.trace_id,
            mode="opaque_handle",
            credential_handle=handle,
            credential_handle_digest=digest(handle),
            audience=ceiling.audience,
            scopes=ceiling.scopes,
            tenant_id=ceiling.tenant_id,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=60),
            broker=broker.name,
            broker_key_id=broker_signer.key_id,
            attestation="",
        )
    )
    verified = validate_execution_authority(
        intent,
        receipt,
        grant,
        verifier,
        execution_id=execution_id,
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
        execution_repository=state,
        now=live_at,
    )
    assert state.reserve_execution(verified, live_at) is None
    service = AgentGuardService(signer, verifier, state, broker.verifier)
    return service, receipt, grant, verified


def test_dispatch_after_authorization_expiry_rejected(intent, policy, signer, verifier, state):
    service, _, _, verified = _reserve_with_expired_authorization(
        intent, policy, signer, verifier, state, "exec_expired_dispatch"
    )
    executor = DeterministicFakeExecutor()
    # _dispatch_reserved is the single choke point for execute/commit/resume dispatch.
    with pytest.raises(ExecutionGuardError, match="authorization_expired"):
        service._dispatch_reserved(verified, executor)
    assert executor.calls == []
    record = state.get_execution("exec_expired_dispatch")
    assert record is not None
    assert record.state == ExecutionState.RESERVED


def test_stale_reserved_resume_after_expiry_rejected(intent, policy, signer, verifier, state):
    service, receipt, grant, _ = _reserve_with_expired_authorization(
        intent, policy, signer, verifier, state, "exec_expired_resume"
    )
    executor = DeterministicFakeExecutor()
    with pytest.raises(ExecutionGuardError, match="expired"):
        service.resume_reserved_execution(
            "exec_expired_resume",
            intent,
            receipt,
            grant,
            executor,
            current_policy=policy,
        )
    assert executor.calls == []
    record = state.get_execution("exec_expired_resume")
    assert record is not None
    assert record.state == ExecutionState.RESERVED


def test_dispatch_rejects_reserved_authority_binding_mismatch(
    intent, policy, signer, verifier, state
):
    service, _, _, verified = _reserve_with_expired_authorization(
        intent, policy, signer, verifier, state, "exec_binding_mismatch"
    )
    rebound = verified.model_copy(
        update={"authorization_expires_at": verified.authorization_expires_at + timedelta(hours=1)}
    )
    executor = DeterministicFakeExecutor()
    with pytest.raises(ExecutionGuardError, match="reserved_binding_mismatch"):
        service._dispatch_reserved(rebound, executor)
    assert executor.calls == []
    record = state.get_execution(verified.execution_id)
    assert record is not None
    assert record.state == ExecutionState.RESERVED


def test_dispatch_transition_failure_never_calls_executor(
    intent, policy, signer, verifier, state, monkeypatch
):
    service, _, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    verified = validate_execution_authority(
        intent,
        receipt,
        grant,
        verifier,
        execution_id="exec_transition_failure",
        broker_grant_verifier=service.broker_grant_verifier,
        current_policy=policy,
        execution_repository=state,
    )
    assert state.reserve_execution(verified, verified.verified_at) is None
    executor = DeterministicFakeExecutor()

    def fail_transition(_verified):
        raise RuntimeError("execution.synthetic_transition_failure")

    monkeypatch.setattr(state, "mark_execution_dispatching", fail_transition)
    with pytest.raises(ExecutionGuardError, match="synthetic_transition_failure"):
        service._dispatch_reserved(verified, executor)
    assert executor.calls == []
    record = state.get_execution(verified.execution_id)
    assert record is not None
    assert record.state == ExecutionState.RESERVED


def test_dispatch_lock_wait_rechecks_authorization_after_lock(
    intent, policy, signer, verifier, state, monkeypatch
):
    service, _, _, verified = _reserve_with_expired_authorization(
        intent, policy, signer, verifier, state, "exec_lock_wait_expiry"
    )
    before_expiry = verified.authorization_expires_at - timedelta(microseconds=1)
    at_expiry = verified.authorization_expires_at
    clock = {"now": before_expiry}

    class ControlledDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            value = clock["now"]
            if tz is None:
                return value.replace(tzinfo=None)
            return value.astimezone(tz)

    monkeypatch.setattr("agentguard.application.service.datetime", ControlledDateTime)
    monkeypatch.setattr("agentguard.adapters.storage.sqlite.state.datetime", ControlledDateTime)

    attempted_dispatch = Event()
    original_mark = state.mark_execution_dispatching

    def mark_after_signal(*args, **kwargs):
        attempted_dispatch.set()
        return original_mark(*args, **kwargs)

    monkeypatch.setattr(state, "mark_execution_dispatching", mark_after_signal)
    blocker = sqlite3.connect(state.path, timeout=10, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    executor = DeterministicFakeExecutor()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(service._dispatch_reserved, verified, executor)
            assert attempted_dispatch.wait(timeout=2)
            clock["now"] = at_expiry
            blocker.execute("COMMIT")
            with pytest.raises(ExecutionGuardError, match="authorization_expired"):
                future.result(timeout=2)
    finally:
        try:
            blocker.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass
        blocker.close()

    assert executor.calls == []
    record = state.get_execution(verified.execution_id)
    assert record is not None
    assert record.state == ExecutionState.RESERVED


def test_mcp_proxy_startup_does_not_recover_dispatching_execution(
    intent, policy, signer, verifier, tmp_path, monkeypatch
):
    import sys

    from agentguard.adapters.protocols.mcp.protected import MCPProtectedStdioProxy
    from agentguard.domain import Principal

    path = tmp_path / "mcp_recovery.sqlite"
    state = SQLiteState(path)
    service, broker, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    verified = validate_execution_authority(
        intent,
        receipt,
        grant,
        verifier,
        execution_id="exec_live_mcp",
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
        execution_repository=state,
    )
    assert state.reserve_execution(verified, verified.verified_at) is None
    state.mark_execution_dispatching(verified)

    reopened_state = SQLiteState(path)
    new_service = AgentGuardService(signer, verifier, reopened_state, broker.verifier)
    principal = Principal(agent_id="test-agent", workload_id="workload-1", tenant_id="tenant-1")
    proxy = MCPProtectedStdioProxy(
        new_service,
        policy,
        principal,
        "test-server",
        [sys.executable, "-c", "pass"],
    )

    def stop_popen(*args, **kwargs):
        raise RuntimeError("startup_complete")

    monkeypatch.setattr("subprocess.Popen", stop_popen)
    with pytest.raises(RuntimeError, match="startup_complete"):
        proxy.run()

    record = reopened_state.get_execution("exec_live_mcp")
    assert record is not None
    assert record.state == ExecutionState.DISPATCHING
    events = reopened_state.list_events()
    assert not any(e.event_type == AuditEventType.EXECUTION_UNKNOWN for e in events)


def test_http_startup_does_not_recover_dispatching_execution(
    intent, policy, signer, verifier, tmp_path, monkeypatch
):
    import sys

    import yaml

    from agentguard import http_cli

    state_path = tmp_path / "http_state.sqlite"
    provider_path = tmp_path / "http_provider.sqlite"
    key_path = tmp_path / "private.pem"
    policy_path = tmp_path / "policy.yaml"

    signer.save_private(key_path)
    policy_path.write_text(yaml.safe_dump(policy.model_dump(mode="json")), encoding="utf-8")

    state = SQLiteState(state_path)
    service, broker, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    verified = validate_execution_authority(
        intent,
        receipt,
        grant,
        verifier,
        execution_id="exec_live_http",
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
        execution_repository=state,
    )
    assert state.reserve_execution(verified, verified.verified_at) is None
    state.mark_execution_dispatching(verified)

    initial_record = state.get_execution("exec_live_http")
    assert initial_record is not None
    assert initial_record.state == ExecutionState.DISPATCHING

    monkeypatch.setenv("TEST_TOKEN", "mock-token")
    monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentguard-mcp-http",
            "--server-id",
            "test-server",
            "--upstream-url",
            "https://upstream.example/mcp",
            "--policy",
            str(policy_path),
            "--key",
            str(key_path),
            "--state",
            str(state_path),
            "--provider-reconciliation-state",
            str(provider_path),
            "--listen-host",
            "127.0.0.1",
            "--port",
            "8080",
            "--access-token-env",
            "TEST_TOKEN",
        ],
    )
    http_cli.entrypoint()

    reopened_state = SQLiteState(state_path)
    record = reopened_state.get_execution("exec_live_http")
    assert record is not None
    assert record.state == ExecutionState.DISPATCHING
    events = reopened_state.list_events()
    assert not any(e.event_type == AuditEventType.EXECUTION_UNKNOWN for e in events)


def test_reconcile_worker_startup_does_not_recover_dispatching_execution(
    intent, policy, signer, verifier, tmp_path, monkeypatch
):
    import json
    import sys

    from agentguard import reconcile_worker_cli

    state_path = tmp_path / "worker_state.sqlite"
    provider_path = tmp_path / "worker_provider.sqlite"
    key_path = tmp_path / "private.pem"
    schema_path = tmp_path / "status_schema.json"

    signer.save_private(key_path)
    schema_path.write_text(
        json.dumps(
            {
                "inputSchema": {
                    "type": "object",
                    "properties": {"requestId": {"type": "string"}, "status": {"type": "string"}},
                }
            }
        ),
        encoding="utf-8",
    )

    state = SQLiteState(state_path)
    service, broker, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    verified = validate_execution_authority(
        intent,
        receipt,
        grant,
        verifier,
        execution_id="exec_live_worker",
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
        execution_repository=state,
    )
    assert state.reserve_execution(verified, verified.verified_at) is None
    state.mark_execution_dispatching(verified)

    initial_record = state.get_execution("exec_live_worker")
    assert initial_record is not None
    assert initial_record.state == ExecutionState.DISPATCHING

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agentguard-reconcile-worker",
            "--server-id",
            "test-server",
            "--upstream-url",
            "https://upstream.example/mcp",
            "--status-tool",
            "operation_status",
            "--status-schema",
            str(schema_path),
            "--status-lookup-argument",
            "requestId",
            "--status-field",
            "status",
            "--key",
            str(key_path),
            "--state",
            str(state_path),
            "--provider-reconciliation-state",
            str(provider_path),
            "--timeout-seconds",
            "5",
            "--lease-seconds",
            "15",
            "--health-check",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        reconcile_worker_cli.entrypoint()
    assert exc.value.code == 0

    reopened_state = SQLiteState(state_path)
    record = reopened_state.get_execution("exec_live_worker")
    assert record is not None
    assert record.state == ExecutionState.DISPATCHING
    events = reopened_state.list_events()
    assert not any(e.event_type == AuditEventType.EXECUTION_UNKNOWN for e in events)


def test_explicit_recovery_converts_stranded_dispatching_to_unknown(
    intent, policy, signer, verifier, tmp_path
):
    path = tmp_path / "explicit_recovery.sqlite"
    state = SQLiteState(path)
    service, broker, receipt, grant = _credential_flow(intent, policy, signer, verifier, state)
    verified = validate_execution_authority(
        intent,
        receipt,
        grant,
        verifier,
        execution_id="exec_explicit_recovery",
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
        execution_repository=state,
    )
    assert state.reserve_execution(verified, verified.verified_at) is None
    state.mark_execution_dispatching(verified)

    assert state.get_execution("exec_explicit_recovery").state == ExecutionState.DISPATCHING

    reopened = SQLiteState(path)
    recovery_service = AgentGuardService(signer, verifier, reopened, broker.verifier)
    recovered = recovery_service.recover_incomplete_executions()
    assert len(recovered) == 1
    assert recovered[0].execution_id == "exec_explicit_recovery"
    assert recovered[0].state == ExecutionState.UNKNOWN
    assert recovered[0].error_code == "execution.recovered_ambiguous_dispatch"

    updated = reopened.get_execution("exec_explicit_recovery")
    assert updated is not None
    assert updated.state == ExecutionState.UNKNOWN

    events = [e for e in reopened.list_events() if e.execution_id == "exec_explicit_recovery"]
    unknown_events = [e for e in events if e.event_type == AuditEventType.EXECUTION_UNKNOWN]
    assert len(unknown_events) == 1
    assert unknown_events[0].data.get("recovered") is True
