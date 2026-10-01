from __future__ import annotations

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.executor import DeterministicFakeExecutor
from agentguard.application import AgentGuardService
from agentguard.domain import CredentialRequest, ExecutionStatus
from agentguard.engine.execution import ExecutionGuardError, preflight_execution


def test_authorize_broker_execute(intent, policy, signer, verifier, state):
    broker = MockCredentialBroker()
    service = AgentGuardService(signer, verifier, state, broker.verifier)
    receipt = service.authorize(intent, policy)
    c = receipt.credential_ceiling
    request = CredentialRequest(
        request_id="cr",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=c.audience,
        scopes=c.scopes,
        requested_ttl_seconds=30,
        tenant_id=c.tenant_id,
    )
    grant = service.request_credential(intent, receipt, request, broker)
    outcome = service.execute_protected(
        intent,
        receipt,
        grant,
        DeterministicFakeExecutor(),
        current_policy=policy,
    )
    assert outcome.status == ExecutionStatus.SUCCESS
    assert state.verify()[0]


def test_replay_is_blocked(intent, policy, signer, verifier, state):
    service = AgentGuardService(signer, verifier, state)
    receipt = service.authorize(intent, policy)
    c = receipt.credential_ceiling
    request = CredentialRequest(
        request_id="cr",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=c.audience,
        scopes=c.scopes,
        requested_ttl_seconds=30,
        tenant_id=c.tenant_id,
    )
    broker = MockCredentialBroker()
    service = AgentGuardService(signer, verifier, state, broker.verifier)
    grant = broker.issue(receipt, request)
    executor = DeterministicFakeExecutor()
    service.execute_protected(
        intent,
        receipt,
        grant,
        executor,
        current_policy=policy,
    )
    with pytest.raises(ExecutionGuardError, match="replayed"):
        service.execute_protected(
            intent,
            receipt,
            grant,
            executor,
            current_policy=policy,
        )
    assert len(executor.calls) == 1


def test_argument_mutation_is_blocked(intent, policy, signer, verifier, state):
    service = AgentGuardService(signer, verifier, state)
    receipt = service.authorize(intent, policy)
    c = receipt.credential_ceiling
    request = CredentialRequest(
        request_id="cr",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=c.audience,
        scopes=c.scopes,
        requested_ttl_seconds=30,
        tenant_id=c.tenant_id,
    )
    broker = MockCredentialBroker()
    grant = broker.issue(receipt, request)
    mutated = intent.model_copy(update={"arguments": {**intent.arguments, "order_id": "other"}})
    with pytest.raises(ExecutionGuardError, match="arguments_digest_mismatch"):
        preflight_execution(
            mutated,
            receipt,
            grant,
            verifier,
            state,
            broker_grant_verifier=broker.verifier,
            current_policy=policy,
        )
