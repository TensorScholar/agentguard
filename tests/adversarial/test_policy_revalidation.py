from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.domain import CredentialRequest
from agentguard.engine.execution import ExecutionGuardError, preflight_execution
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import issue_decision_receipt


def _receipt_and_grant(intent, policy, signer):
    receipt = issue_decision_receipt(intent, evaluate_policy(policy, intent), signer)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="policy-revalidation",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    broker = MockCredentialBroker()
    return receipt, broker.issue(receipt, request), broker.verifier


def _authorize(intent, receipt, grant, verifier, state, broker_verifier, policy):
    preflight_execution(
        intent,
        receipt,
        grant,
        verifier,
        state,
        broker_grant_verifier=broker_verifier,
        current_policy=policy,
    )


def test_unchanged_current_policy_allows_execution(
    intent, policy, signer, verifier, tmp_path: Path
):
    receipt, grant, broker_verifier = _receipt_and_grant(intent, policy, signer)
    _authorize(
        intent,
        receipt,
        grant,
        verifier,
        SQLiteState(tmp_path / "unchanged.sqlite"),
        broker_verifier,
        policy,
    )


@pytest.mark.parametrize("change", ["revision", "rule"])
def test_changed_policy_rejected_before_nonce_consumption(
    intent, policy, signer, verifier, tmp_path: Path, change
):
    receipt, grant, broker_verifier = _receipt_and_grant(intent, policy, signer)
    changed = (
        policy.model_copy(update={"metadata": policy.metadata.model_copy(update={"revision": 2})})
        if change == "revision"
        else policy.model_copy(
            update={
                "rules": (
                    *policy.rules[:-1],
                    policy.rules[-1].model_copy(update={"reason_code": "policy.changed"}),
                )
            }
        )
    )
    state = SQLiteState(tmp_path / f"{change}.sqlite")

    with pytest.raises(ExecutionGuardError, match="execution.policy_changed"):
        _authorize(
            intent,
            receipt,
            grant,
            verifier,
            state,
            broker_verifier,
            changed,
        )

    # Policy mismatch is checked before the execution nonce is consumed.
    _authorize(intent, receipt, grant, verifier, state, broker_verifier, policy)


def test_missing_current_policy_fails_closed(intent, policy, signer, verifier, tmp_path: Path):
    receipt, grant, broker_verifier = _receipt_and_grant(intent, policy, signer)

    with pytest.raises(ExecutionGuardError, match="execution.policy_unavailable"):
        preflight_execution(
            intent,
            receipt,
            grant,
            verifier,
            SQLiteState(tmp_path / "missing.sqlite"),
            broker_grant_verifier=broker_verifier,
            current_policy=None,
        )


def test_signed_forged_expected_digest_cannot_replace_current_policy(
    intent, policy, signer, verifier, tmp_path: Path
):
    forged_policy = policy.model_copy(
        update={"metadata": policy.metadata.model_copy(update={"revision": 999})}
    )
    forged_evaluation = replace(
        evaluate_policy(policy, intent),
        policy_digest=evaluate_policy(forged_policy, intent).policy_digest,
    )
    receipt = issue_decision_receipt(intent, forged_evaluation, signer)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="forged-policy-digest",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    broker = MockCredentialBroker()
    grant = broker.issue(receipt, request)

    with pytest.raises(ExecutionGuardError, match="execution.policy_changed"):
        _authorize(
            intent,
            receipt,
            grant,
            verifier,
            SQLiteState(tmp_path / "forged.sqlite"),
            broker.verifier,
            policy,
        )
