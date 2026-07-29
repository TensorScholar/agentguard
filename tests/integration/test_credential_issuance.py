from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.application import AgentGuardService
from agentguard.domain import CredentialCeiling, CredentialRequest, Effect
from agentguard.domain.policy import ActionMatcher, PolicyRule
from agentguard.engine.credentials import CredentialVerificationError


class CountingBroker:
    def __init__(self, delegate: MockCredentialBroker, *, fail: bool = False) -> None:
        self.delegate = delegate
        self.fail = fail
        self.calls = 0
        self._lock = Lock()

    def issue(self, receipt, request, approval=None):
        with self._lock:
            self.calls += 1
        if self.fail:
            raise RuntimeError("simulated broker failure")
        return self.delegate.issue(receipt, request, approval)


def _request(receipt, request_id: str, approval_id: str | None = None):
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    return CredentialRequest(
        request_id=request_id,
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=min(30, ceiling.maximum_ttl_seconds),
        tenant_id=ceiling.tenant_id,
        approval_id=approval_id,
    )


def _approval_policy(policy, *, single_use: bool):
    rule = PolicyRule(
        id="approved-refund",
        priority=2000,
        effect=Effect.REQUIRE_APPROVAL,
        action=ActionMatcher(tools=frozenset({"refund.create"})),
        credential=CredentialCeiling(
            audience="payments.internal",
            scopes=frozenset({"refund:create"}),
            maximum_ttl_seconds=60,
            single_use=single_use,
            tenant_id="acme",
        ),
        execution_budget=policy.rules[1].execution_budget,
        reason_code="approval.refund_required",
    )
    return policy.model_copy(update={"rules": (rule,)})


def test_concurrent_single_use_issuance_has_exactly_one_winner(
    intent, policy, signer, verifier, state
):
    mock = MockCredentialBroker()
    broker = CountingBroker(mock)
    service = AgentGuardService(signer, verifier, state, mock.verifier)
    receipt = service.authorize(intent, policy)

    def issue(index: int) -> bool:
        try:
            service.request_credential(
                intent,
                receipt,
                _request(receipt, f"credential-{index}"),
                broker,
            )
            return True
        except CredentialVerificationError:
            return False

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(issue, range(20)))

    assert sum(results) == 1
    assert broker.calls == 1


def test_approval_maximum_uses_is_consumed_atomically(intent, policy, signer, verifier, state):
    mock = MockCredentialBroker()
    broker = CountingBroker(mock)
    service = AgentGuardService(signer, verifier, state, mock.verifier)
    receipt = service.authorize(intent, _approval_policy(policy, single_use=False))
    approval = service.approve(
        intent,
        receipt,
        approver_subject="security",
        reason="one credential only",
        maximum_uses=1,
    )

    def issue(index: int) -> bool:
        try:
            service.request_credential(
                intent,
                receipt,
                _request(receipt, f"approved-{index}", approval.approval_id),
                broker,
                approval,
            )
            return True
        except CredentialVerificationError:
            return False

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(issue, range(20)))

    assert sum(results) == 1
    assert broker.calls == 1


def test_failed_single_use_broker_attempt_is_terminal(intent, policy, signer, verifier, state):
    mock = MockCredentialBroker()
    broker = CountingBroker(mock, fail=True)
    service = AgentGuardService(signer, verifier, state, mock.verifier)
    receipt = service.authorize(intent, policy)

    with pytest.raises(RuntimeError, match="simulated broker failure"):
        service.request_credential(
            intent,
            receipt,
            _request(receipt, "failed-first"),
            broker,
        )
    with pytest.raises(CredentialVerificationError, match="issuance_already_consumed"):
        service.request_credential(
            intent,
            receipt,
            _request(receipt, "failed-retry"),
            broker,
        )
    assert broker.calls == 1


def test_service_rejects_tampered_broker_grant(intent, policy, signer, verifier, state):
    mock = MockCredentialBroker()
    service = AgentGuardService(signer, verifier, state, mock.verifier)
    receipt = service.authorize(intent, policy)

    class TamperingBroker:
        def issue(self, receipt, request, approval=None):
            return mock.issue(receipt, request, approval).model_copy(
                update={"audience": "attacker"}
            )

    with pytest.raises(CredentialVerificationError, match="attestation_invalid"):
        service.request_credential(
            intent,
            receipt,
            _request(receipt, "tampered-grant"),
            TamperingBroker(),
        )
