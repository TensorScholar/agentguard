from __future__ import annotations
from agentguard.adapters.broker import MockCredentialBroker
from agentguard.application import AgentGuardService
from agentguard.domain import CredentialRequest
from agentguard.engine.execution import authorize_execution,ExecutionGuardError
import pytest

def test_authorize_broker_execute(intent,policy,signer,verifier,state):
    service=AgentGuardService(signer,verifier,state)
    receipt=service.authorize(intent,policy)
    c=receipt.credential_ceiling
    request=CredentialRequest(request_id="cr",trace_id=receipt.trace_id,decision_id=receipt.decision_id,audience=c.audience,scopes=c.scopes,requested_ttl_seconds=30,tenant_id=c.tenant_id)
    grant=service.request_credential(intent,receipt,request,MockCredentialBroker())
    service.guard_execution(intent,receipt,grant)
    assert state.verify()[0]

def test_replay_is_blocked(intent,policy,signer,verifier,state):
    service=AgentGuardService(signer,verifier,state); receipt=service.authorize(intent,policy); c=receipt.credential_ceiling
    request=CredentialRequest(request_id="cr",trace_id=receipt.trace_id,decision_id=receipt.decision_id,audience=c.audience,scopes=c.scopes,requested_ttl_seconds=30,tenant_id=c.tenant_id)
    grant=MockCredentialBroker().issue(receipt,request)
    authorize_execution(intent,receipt,grant,verifier,state)
    with pytest.raises(ExecutionGuardError,match="replayed"): authorize_execution(intent,receipt,grant,verifier,state)

def test_argument_mutation_is_blocked(intent,policy,signer,verifier,state):
    service=AgentGuardService(signer,verifier,state); receipt=service.authorize(intent,policy); c=receipt.credential_ceiling
    request=CredentialRequest(request_id="cr",trace_id=receipt.trace_id,decision_id=receipt.decision_id,audience=c.audience,scopes=c.scopes,requested_ttl_seconds=30,tenant_id=c.tenant_id)
    grant=MockCredentialBroker().issue(receipt,request)
    mutated=intent.model_copy(update={"arguments":{**intent.arguments,"order_id":"other"}})
    with pytest.raises(ExecutionGuardError,match="arguments_digest_mismatch"): authorize_execution(mutated,receipt,grant,verifier,state)
