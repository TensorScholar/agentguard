from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.executor import DeterministicFakeExecutor
from agentguard.application import AgentGuardService
from agentguard.domain import (
    CapabilityLeaseStatus,
    CapabilityScope,
    CredentialRequest,
    Principal,
)
from agentguard.engine.authority import AuthorityError
from agentguard.engine.execution import ExecutionGuardError, validate_execution_authority


def _scope(*, calls: int = 2, delegable: bool = True, depth: int = 2) -> CapabilityScope:
    return CapabilityScope(
        capabilities=frozenset({"financial_mutation"}),
        protocols=frozenset({"mcp"}),
        servers=frozenset({"customer-operations"}),
        tools=frozenset({"refund.create"}),
        operations=frozenset({"call"}),
        resource_types=frozenset({"order"}),
        resource_ids=frozenset({"order-1042"}),
        maximum_calls=calls,
        delegable=delegable,
        maximum_delegation_depth=depth,
    )


def _authority_service(signer, verifier, state, authority_signer):
    authority_verifier = Ed25519Verifier({authority_signer.key_id: authority_signer.public_key()})
    broker = MockCredentialBroker()
    return (
        AgentGuardService(
            signer,
            verifier,
            state,
            broker.verifier,
            authority_verifier=authority_verifier,
        ),
        broker,
        authority_verifier,
    )


def _credential_for(service, broker, intent, policy):
    receipt = service.authorize(intent, policy)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="authority-credential-" + intent.request_id,
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    grant = service.request_credential(intent, receipt, request, broker)
    return receipt, grant


def test_delegated_authority_executes_and_consumes_lease_once(
    intent, policy, signer, verifier, state
):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    service, broker, _ = _authority_service(signer, verifier, state, authority_signer)
    root = service.issue_root_authority(intent.principal, _scope(), authority_signer)
    child_principal = intent.principal.model_copy(update={"agent_id": "support-subagent"})
    child = service.delegate_authority(
        root.grant_id,
        intent.principal,
        child_principal,
        _scope(calls=1, delegable=False, depth=0),
        authority_signer,
    )
    lease = service.issue_capability_lease(child.grant_id, child_principal, maximum_uses=1)
    reference = service.authority_reference(child.grant_id, lease.lease_id)
    delegated_intent = intent.model_copy(
        update={
            "request_id": "delegated-request",
            "principal": child_principal,
            "authority": reference,
        }
    )
    receipt, credential = _credential_for(service, broker, delegated_intent, policy)
    executor = DeterministicFakeExecutor()
    outcome = service.execute_protected(
        delegated_intent,
        receipt,
        credential,
        executor,
        current_policy=policy,
    )
    assert outcome.status.value == "success"
    consumed = state.get_capability_lease(lease.lease_id)
    assert consumed is not None
    assert consumed.remaining_uses == 0
    assert consumed.status == CapabilityLeaseStatus.EXHAUSTED
    assert executor.calls[0].authority_grant_id == child.grant_id
    assert executor.calls[0].authority_lease_id == lease.lease_id
    assert executor.calls[0].authority_chain_digest == reference.chain_digest
    audit_types = [event.event_type.value for event in state.list_events()]
    assert "authority.lease.consumed" in audit_types


def test_concurrent_last_lease_use_has_one_execution_winner(
    intent, policy, signer, verifier, state
):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    service, broker, _ = _authority_service(signer, verifier, state, authority_signer)
    root = service.issue_root_authority(
        intent.principal, _scope(calls=1, delegable=False, depth=0), authority_signer
    )
    lease = service.issue_capability_lease(root.grant_id, intent.principal, maximum_uses=1)
    reference = service.authority_reference(root.grant_id, lease.lease_id)

    def build_request(suffix: str):
        request_intent = intent.model_copy(
            update={"request_id": f"lease-race-{suffix}", "authority": reference}
        )
        receipt, credential = _credential_for(service, broker, request_intent, policy)
        return request_intent, receipt, credential

    first = build_request("a")
    second = build_request("b")
    executor = DeterministicFakeExecutor()

    def execute(values):
        try:
            return service.execute_protected(
                values[0], values[1], values[2], executor, current_policy=policy
            ).status.value
        except (ExecutionGuardError, AuthorityError) as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(execute, (first, second)))

    assert results.count("success") == 1
    assert sum("authority.lease" in result for result in results) == 1
    assert len(executor.calls) == 1
    assert len(state.list_executions()) == 1


def test_scope_amplification_and_cross_tenant_delegation_are_rejected(
    intent, signer, verifier, state
):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    service, _, _ = _authority_service(signer, verifier, state, authority_signer)
    root = service.issue_root_authority(intent.principal, _scope(), authority_signer)

    amplified = _scope(calls=3)
    with pytest.raises(AuthorityError, match="scope_amplification"):
        service.delegate_authority(
            root.grant_id,
            intent.principal,
            intent.principal,
            amplified,
            authority_signer,
        )

    other_tenant = Principal(
        agent_id="other",
        workload_id="prod/support-agent-v3",
        tenant_id="other-tenant",
        identity_verified=True,
    )
    with pytest.raises(AuthorityError, match="cross_tenant"):
        service.delegate_authority(
            root.grant_id,
            intent.principal,
            other_tenant,
            _scope(calls=1, delegable=False, depth=0),
            authority_signer,
        )


def test_parent_revocation_cascades_to_descendant_grants_and_leases(
    intent, signer, verifier, state
):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    service, _, _ = _authority_service(signer, verifier, state, authority_signer)
    root = service.issue_root_authority(intent.principal, _scope(), authority_signer)
    child = service.delegate_authority(
        root.grant_id,
        intent.principal,
        intent.principal,
        _scope(calls=1, delegable=False, depth=0),
        authority_signer,
    )
    lease = service.issue_capability_lease(child.grant_id, intent.principal, maximum_uses=1)

    service.revoke_authority(root.grant_id, reason="security-incident")

    assert state.get_authority_grant(root.grant_id).status.value == "revoked"
    assert state.get_authority_grant(child.grant_id).status.value == "revoked"
    assert state.get_capability_lease(lease.lease_id).status == CapabilityLeaseStatus.REVOKED
    with pytest.raises(AuthorityError, match="grant_revoked"):
        service.authority_reference(child.grant_id, lease.lease_id)


def test_tampered_chain_digest_and_subject_fail_before_policy_execution(
    intent, policy, signer, verifier, state
):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    service, _, _ = _authority_service(signer, verifier, state, authority_signer)
    root = service.issue_root_authority(
        intent.principal, _scope(calls=1, delegable=False, depth=0), authority_signer
    )
    lease = service.issue_capability_lease(root.grant_id, intent.principal, maximum_uses=1)
    reference = service.authority_reference(root.grant_id, lease.lease_id)

    tampered_reference = reference.model_copy(update={"chain_digest": "sha256:" + "0" * 64})
    tampered_intent = intent.model_copy(update={"authority": tampered_reference})
    with pytest.raises(AuthorityError, match="chain_digest_mismatch"):
        service.authorize(tampered_intent, policy)

    other_principal = intent.principal.model_copy(update={"agent_id": "substituted"})
    subject_mismatch = intent.model_copy(
        update={"principal": other_principal, "authority": reference}
    )
    with pytest.raises(AuthorityError, match="subject_mismatch"):
        service.authorize(subject_mismatch, policy)


def test_delegation_and_lease_issuance_require_bound_holder_identity(
    intent, signer, verifier, state
):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    service, _, _ = _authority_service(signer, verifier, state, authority_signer)
    root = service.issue_root_authority(intent.principal, _scope(), authority_signer)
    impostor = intent.principal.model_copy(update={"agent_id": "impostor"})

    with pytest.raises(AuthorityError, match="delegator_mismatch"):
        service.delegate_authority(
            root.grant_id,
            impostor,
            intent.principal,
            _scope(calls=1, delegable=False, depth=0),
            authority_signer,
        )

    with pytest.raises(AuthorityError, match="holder_mismatch"):
        service.issue_capability_lease(root.grant_id, impostor, maximum_uses=1)


def test_sibling_delegations_share_parent_call_budget(intent, signer, verifier, state):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    service, _, _ = _authority_service(signer, verifier, state, authority_signer)
    root = service.issue_root_authority(
        intent.principal,
        _scope(calls=3, delegable=True, depth=2),
        authority_signer,
    )
    first_subject = intent.principal.model_copy(update={"agent_id": "child-a"})
    second_subject = intent.principal.model_copy(update={"agent_id": "child-b"})
    service.delegate_authority(
        root.grant_id,
        intent.principal,
        first_subject,
        _scope(calls=2, delegable=False, depth=0),
        authority_signer,
    )

    with pytest.raises(AuthorityError, match="call_budget_exhausted"):
        service.delegate_authority(
            root.grant_id,
            intent.principal,
            second_subject,
            _scope(calls=2, delegable=False, depth=0),
            authority_signer,
        )

    record = state.get_authority_grant(root.grant_id)
    assert record is not None
    assert record.remaining_calls == 1


def test_multiple_leases_share_grant_call_budget(intent, signer, verifier, state):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    service, _, _ = _authority_service(signer, verifier, state, authority_signer)
    root = service.issue_root_authority(
        intent.principal,
        _scope(calls=2, delegable=False, depth=0),
        authority_signer,
    )
    service.issue_capability_lease(root.grant_id, intent.principal, maximum_uses=1)

    with pytest.raises(AuthorityError, match="call_budget_exhausted"):
        service.issue_capability_lease(root.grant_id, intent.principal, maximum_uses=2)

    record = state.get_authority_grant(root.grant_id)
    assert record is not None
    assert record.remaining_calls == 1


def test_require_authority_mode_fails_closed_without_reference(
    intent, policy, signer, verifier, state
):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    authority_verifier = Ed25519Verifier({authority_signer.key_id: authority_signer.public_key()})
    broker = MockCredentialBroker()
    service = AgentGuardService(
        signer,
        verifier,
        state,
        broker.verifier,
        authority_verifier=authority_verifier,
        require_authority=True,
    )

    with pytest.raises(AuthorityError, match="authority.required"):
        service.authorize(intent, policy)

    root = service.issue_root_authority(
        intent.principal,
        _scope(calls=1, delegable=False, depth=0),
        authority_signer,
    )
    lease = service.issue_capability_lease(root.grant_id, intent.principal, maximum_uses=1)
    reference = service.authority_reference(root.grant_id, lease.lease_id)
    bound_intent = intent.model_copy(update={"authority": reference})
    receipt = service.authorize(bound_intent, policy)
    assert receipt.intent_digest


def test_reserved_execution_can_resume_after_its_last_lease_use_is_claimed(
    intent, policy, signer, verifier, state
):
    authority_signer = Ed25519Signer.generate("authority-ed25519")
    service, broker, _ = _authority_service(signer, verifier, state, authority_signer)
    root = service.issue_root_authority(
        intent.principal, _scope(calls=1, delegable=False, depth=0), authority_signer
    )
    lease = service.issue_capability_lease(root.grant_id, intent.principal, maximum_uses=1)
    reference = service.authority_reference(root.grant_id, lease.lease_id)
    bound_intent = intent.model_copy(
        update={"request_id": "authority-resume-last-use", "authority": reference}
    )
    receipt, credential = _credential_for(service, broker, bound_intent, policy)
    execution_id = "exec_authority_resume_last_use"
    verified = validate_execution_authority(
        bound_intent,
        receipt,
        credential,
        verifier,
        execution_id=execution_id,
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
    )
    reservation_error = state.reserve_execution(verified, verified.verified_at)
    assert reservation_error is None
    consumed = state.get_capability_lease(lease.lease_id)
    assert consumed is not None
    assert consumed.remaining_uses == 0
    assert consumed.status == CapabilityLeaseStatus.EXHAUSTED

    executor = DeterministicFakeExecutor()
    outcome = service.resume_reserved_execution(
        execution_id,
        bound_intent,
        receipt,
        credential,
        executor,
        current_policy=policy,
    )
    assert outcome.status.value == "success"
    assert len(executor.calls) == 1
