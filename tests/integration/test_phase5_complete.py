from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.executor import DeterministicFakeExecutor
from agentguard.application import AgentGuardService
from agentguard.domain import (
    CausalConstraint,
    Effect,
    FieldIntegrityConstraint,
    FieldReleaseType,
    PolicyDocument,
    PolicyIntelligenceFindingType,
    PreparedExecutionStatus,
    ProvenanceLabel,
    ReversibilityMode,
    StagingRequirement,
)
from agentguard.engine.attestation import verify_execution_attestation
from agentguard.engine.execution import ExecutionGuardError, validate_execution_authority
from agentguard.engine.field_integrity import (
    FieldIntegrityError,
    issue_field_provenance_statement,
    issue_field_release,
    validate_field_integrity,
)
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.policy_intelligence import (
    analyze_authority,
    analyze_policy_counterfactuals,
    derive_minimal_authority,
)


def _policy_with_bounded_rule(policy: PolicyDocument, **updates) -> PolicyDocument:
    rules = []
    for rule in policy.rules:
        if rule.id == "bounded-refund":
            updates = {"credential": None, **updates}
            rules.append(rule.model_copy(update=updates))
        else:
            rules.append(rule)
    return policy.model_copy(update={"rules": tuple(rules)})


def _field_policy(policy: PolicyDocument) -> PolicyDocument:
    return _policy_with_bounded_rule(
        policy,
        field_integrity=(
            FieldIntegrityConstraint(
                field_path="/order_id",
                semantic_type="order_id",
                denied_labels=frozenset({ProvenanceLabel.EXTERNAL_EMAIL}),
                permitted_release_types=frozenset({FieldReleaseType.HUMAN_ENDORSEMENT}),
            ),
        ),
    )


def _field_material(intent):
    provenance_signer = Ed25519Signer.generate("provenance-ed25519")
    release_signer = Ed25519Signer.generate("field-release-ed25519")
    provenance_verifier = Ed25519Verifier(
        {provenance_signer.key_id: provenance_signer.public_key()}
    )
    release_verifier = Ed25519Verifier({release_signer.key_id: release_signer.public_key()})
    statement = issue_field_provenance_statement(
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        tenant_id=intent.principal.tenant_id,
        field_path="/order_id",
        value=intent.arguments["order_id"],
        semantic_type="order_id",
        labels=frozenset({ProvenanceLabel.EXTERNAL_EMAIL}),
        signer=provenance_signer,
        ttl_seconds=300,
    )
    intent_with_statement = intent.model_copy(update={"field_provenance": (statement,)})
    release = issue_field_release(
        intent_with_statement,
        statement,
        release_type=FieldReleaseType.HUMAN_ENDORSEMENT,
        reason="verified by account owner",
        signer=release_signer,
        ttl_seconds=120,
    )
    protected_intent = intent_with_statement.model_copy(update={"field_releases": (release,)})
    return (
        protected_intent,
        statement,
        release,
        provenance_signer,
        release_signer,
        provenance_verifier,
        release_verifier,
    )


def _service(signer, verifier, state, provenance_verifier=None, release_verifier=None):
    return AgentGuardService(
        signer,
        verifier,
        state,
        provenance_verifier=provenance_verifier,
        release_verifier=release_verifier,
    )


def test_5e_external_field_requires_typed_release(intent, policy, signer, verifier, state):
    field_policy = _field_policy(policy)
    (
        protected_intent,
        statement,
        _,
        _,
        _,
        provenance_verifier,
        release_verifier,
    ) = _field_material(intent)
    service = _service(signer, verifier, state, provenance_verifier, release_verifier)

    without_release = protected_intent.model_copy(update={"field_releases": ()})
    with pytest.raises(ExecutionGuardError, match="field_integrity.release_required"):
        service.authorize(without_release, field_policy)

    receipt = service.authorize(protected_intent, field_policy)
    assert receipt.field_integrity_digest is not None
    assert receipt.field_release_set_digest is not None
    assert receipt.field_integrity_expires_at is not None
    outcome = service.execute_protected(
        protected_intent,
        receipt,
        None,
        DeterministicFakeExecutor(),
        current_policy=field_policy,
    )
    record = state.get_execution(outcome.execution_id)
    assert record is not None
    assert record.field_integrity_digest == receipt.field_integrity_digest
    assert record.field_release_set_digest == receipt.field_release_set_digest
    assert ProvenanceLabel.EXTERNAL_EMAIL in record.causal_labels
    assert statement.statement_id in {s.statement_id for s in protected_intent.field_provenance}

    attestation_signer = Ed25519Signer.generate("attestation-ed25519")
    attestation = service.issue_execution_attestation(outcome.execution_id, attestation_signer)
    attestation_verifier = Ed25519Verifier(
        {attestation_signer.key_id: attestation_signer.public_key()}
    )
    verify_execution_attestation(attestation, attestation_verifier)
    assert attestation.payload.field_integrity_digest == receipt.field_integrity_digest
    assert attestation.payload.field_release_set_digest == receipt.field_release_set_digest
    assert attestation.payload.causal_digest == record.causal_digest


def test_5e_release_is_single_use_across_decisions(intent, policy, signer, verifier, state):
    field_policy = _field_policy(policy)
    (
        protected_intent,
        _,
        release,
        _,
        _,
        provenance_verifier,
        release_verifier,
    ) = _field_material(intent)
    service = _service(signer, verifier, state, provenance_verifier, release_verifier)
    first_receipt = service.authorize(protected_intent, field_policy)
    second_receipt = service.authorize(protected_intent, field_policy)
    executor = DeterministicFakeExecutor()

    service.execute_protected(
        protected_intent, first_receipt, None, executor, current_policy=field_policy
    )
    with pytest.raises(ExecutionGuardError, match="field_integrity.release_replayed"):
        service.execute_protected(
            protected_intent,
            second_receipt,
            None,
            executor,
            current_policy=field_policy,
        )
    assert len(executor.calls) == 1
    with state._connect() as connection:  # test-only forensic assertion
        rows = connection.execute("SELECT release_id FROM consumed_field_releases").fetchall()
    assert [str(row[0]) for row in rows] == [release.release_id]


def test_5e_concurrent_release_use_has_one_winner(intent, policy, signer, verifier, state):
    field_policy = _field_policy(policy)
    (
        protected_intent,
        _,
        _,
        _,
        _,
        provenance_verifier,
        release_verifier,
    ) = _field_material(intent)
    service = _service(signer, verifier, state, provenance_verifier, release_verifier)
    receipts = [service.authorize(protected_intent, field_policy) for _ in range(2)]
    executor = DeterministicFakeExecutor()

    def run(receipt) -> str:
        try:
            return service.execute_protected(
                protected_intent, receipt, None, executor, current_policy=field_policy
            ).status.value
        except ExecutionGuardError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, receipts))
    assert sorted(results) == ["field_integrity.release_replayed", "success"]
    assert len(executor.calls) == 1


def test_5e_lineage_cannot_strip_parent_labels(intent, policy):
    field_policy = _field_policy(policy)
    provenance_signer = Ed25519Signer.generate("provenance-ed25519")
    release_signer = Ed25519Signer.generate("field-release-ed25519")
    provenance_verifier = Ed25519Verifier(
        {provenance_signer.key_id: provenance_signer.public_key()}
    )
    release_verifier = Ed25519Verifier({release_signer.key_id: release_signer.public_key()})
    parent = issue_field_provenance_statement(
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        tenant_id=intent.principal.tenant_id,
        field_path="/order_id",
        value=intent.arguments["order_id"],
        semantic_type="order_id",
        labels=frozenset({ProvenanceLabel.EXTERNAL_EMAIL}),
        signer=provenance_signer,
    )
    child = issue_field_provenance_statement(
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        tenant_id=intent.principal.tenant_id,
        field_path="/order_id",
        value=intent.arguments["order_id"],
        semantic_type="order_id",
        labels=frozenset({ProvenanceLabel.AUTHENTICATED_USER_INPUT}),
        signer=provenance_signer,
        parent_statement_ids=(parent.statement_id,),
        transformation="copy",
    )
    tainted = intent.model_copy(update={"field_provenance": (parent, child)})
    evaluation = evaluate_policy(field_policy, tainted)
    with pytest.raises(FieldIntegrityError, match="label_stripping"):
        validate_field_integrity(
            tainted,
            evaluation.matched_rules,
            provenance_verifier,
            release_verifier,
        )


def test_5e_release_context_rebinding_fails(intent, policy, signer, verifier, state):
    field_policy = _field_policy(policy)
    (
        protected_intent,
        _,
        _,
        _,
        _,
        provenance_verifier,
        release_verifier,
    ) = _field_material(intent)
    service = _service(signer, verifier, state, provenance_verifier, release_verifier)
    changed_principal = protected_intent.principal.model_copy(update={"agent_id": "other-agent"})
    rebound = protected_intent.model_copy(update={"principal": changed_principal})
    with pytest.raises(ExecutionGuardError, match="release_context_binding_mismatch"):
        service.authorize(rebound, field_policy)


def test_5e_expiry_is_rechecked_at_external_boundary(
    intent, policy, signer, verifier, state, monkeypatch
):
    field_policy = _field_policy(policy)
    (
        protected_intent,
        _,
        _,
        _,
        _,
        provenance_verifier,
        release_verifier,
    ) = _field_material(intent)
    service = _service(signer, verifier, state, provenance_verifier, release_verifier)
    receipt = service.authorize(protected_intent, field_policy, ttl_seconds=300)
    verified = validate_execution_authority(
        protected_intent,
        receipt,
        None,
        verifier,
        execution_id="exec_expiry_boundary",
        current_policy=field_policy,
        provenance_verifier=provenance_verifier,
        release_verifier=release_verifier,
        execution_repository=state,
    )
    assert verified.field_integrity_expires_at is not None
    reserve_at = verified.field_integrity_expires_at - timedelta(microseconds=1)
    assert state.reserve_execution(verified, reserve_at) is None

    expires_at = verified.field_integrity_expires_at

    class ControlledDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is None:
                return expires_at.replace(tzinfo=None)
            return expires_at.astimezone(tz)

    monkeypatch.setattr("agentguard.adapters.storage.sqlite.state.datetime", ControlledDateTime)
    with pytest.raises(RuntimeError, match="field_integrity.expired_before_dispatch"):
        state.mark_execution_dispatching(verified)


def _staging_policy(policy: PolicyDocument, *, fresh_approval: bool = False) -> PolicyDocument:
    return _policy_with_bounded_rule(
        policy,
        effect=Effect.REQUIRE_APPROVAL if fresh_approval else Effect.ALLOW,
        staging=StagingRequirement(
            required=True,
            minimum_delay_seconds=0,
            maximum_commit_window_seconds=60,
            reversibility=ReversibilityMode.IRREVERSIBLE,
            require_fresh_approval=fresh_approval,
        ),
    )


def test_5f_staging_blocks_direct_dispatch_and_commits_once(
    intent, policy, signer, verifier, state
):
    staging_policy = _staging_policy(policy)
    service = _service(signer, verifier, state)
    receipt = service.authorize(intent, staging_policy)
    executor = DeterministicFakeExecutor()
    with pytest.raises(ExecutionGuardError, match="execution.staging_required"):
        service.execute_protected(intent, receipt, None, executor, current_policy=staging_policy)

    prepared = service.prepare_protected_execution(
        intent, receipt, None, current_policy=staging_policy
    )
    assert prepared.status == PreparedExecutionStatus.PREPARED
    outcome = service.commit_prepared_execution(
        prepared.prepared_id,
        intent,
        receipt,
        None,
        executor,
        current_policy=staging_policy,
    )
    assert outcome.status.value == "success"
    stored = state.get_prepared_execution(prepared.prepared_id)
    assert stored is not None and stored.status == PreparedExecutionStatus.COMMITTED
    record = state.get_execution(outcome.execution_id)
    assert record is not None and record.prepared_id == prepared.prepared_id
    assert len(executor.calls) == 1


def test_5f_cancelled_preparation_never_dispatches(intent, policy, signer, verifier, state):
    staging_policy = _staging_policy(policy)
    service = _service(signer, verifier, state)
    receipt = service.authorize(intent, staging_policy)
    prepared = service.prepare_protected_execution(
        intent, receipt, None, current_policy=staging_policy
    )
    cancelled = service.cancel_prepared_execution(prepared.prepared_id)
    assert cancelled.status == PreparedExecutionStatus.CANCELLED
    executor = DeterministicFakeExecutor()
    with pytest.raises(ExecutionGuardError, match="execution.prepared_not_active"):
        service.commit_prepared_execution(
            prepared.prepared_id,
            intent,
            receipt,
            None,
            executor,
            current_policy=staging_policy,
        )
    assert executor.calls == []


def test_5f_concurrent_commit_has_one_dispatch_winner(intent, policy, signer, verifier, state):
    staging_policy = _staging_policy(policy)
    service = _service(signer, verifier, state)
    receipt = service.authorize(intent, staging_policy)
    prepared = service.prepare_protected_execution(
        intent, receipt, None, current_policy=staging_policy
    )
    executor = DeterministicFakeExecutor()

    def run() -> str:
        try:
            return service.commit_prepared_execution(
                prepared.prepared_id,
                intent,
                receipt,
                None,
                executor,
                current_policy=staging_policy,
            ).status.value
        except ExecutionGuardError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert "success" in results
    assert any(
        result in {"execution.prepared_not_active", "decision_receipt.replayed"}
        for result in results
    )
    assert len(executor.calls) == 1


def test_5f_fresh_commit_approval_is_enforced(intent, policy, signer, verifier, state):
    staging_policy = _staging_policy(policy, fresh_approval=True)
    service = _service(signer, verifier, state)
    receipt = service.authorize(intent, staging_policy)
    approval_before = service.approve(
        intent, receipt, approver_subject="user-482", reason="prepare review"
    )
    prepared = service.prepare_protected_execution(
        intent,
        receipt,
        None,
        approval_before,
        current_policy=staging_policy,
    )
    with pytest.raises(ExecutionGuardError, match="execution.fresh_approval_required"):
        service.commit_prepared_execution(
            prepared.prepared_id,
            intent,
            receipt,
            None,
            DeterministicFakeExecutor(),
            approval_before,
            current_policy=staging_policy,
        )
    approval_after = service.approve(
        intent, receipt, approver_subject="user-482", reason="fresh commit review"
    )
    assert approval_after.issued_at >= prepared.prepared_at
    outcome = service.commit_prepared_execution(
        prepared.prepared_id,
        intent,
        receipt,
        None,
        DeterministicFakeExecutor(),
        approval_after,
        current_policy=staging_policy,
    )
    assert outcome.status.value == "success"


def test_5g_causal_ancestry_blocks_cross_tool_laundering(intent, policy, signer, verifier, state):
    field_policy = _field_policy(policy)
    (
        protected_intent,
        _,
        _,
        _,
        _,
        provenance_verifier,
        release_verifier,
    ) = _field_material(intent)
    service = _service(signer, verifier, state, provenance_verifier, release_verifier)
    first_receipt = service.authorize(protected_intent, field_policy)
    first = service.execute_protected(
        protected_intent,
        first_receipt,
        None,
        DeterministicFakeExecutor(),
        current_policy=field_policy,
    )

    causal_policy = _policy_with_bounded_rule(
        policy,
        causal=CausalConstraint(denied_labels=frozenset({ProvenanceLabel.EXTERNAL_EMAIL})),
    )
    downstream = intent.model_copy(
        update={
            "request_id": "req_causal_downstream",
            "trace_id": "trc_causal_downstream",
            "causal_parent_execution_ids": (first.execution_id,),
        }
    )
    with pytest.raises(ExecutionGuardError, match="causal.denied_ancestry"):
        service.authorize(downstream, causal_policy)


def test_5g_causal_digest_and_depth_are_signed_and_durable(intent, policy, signer, verifier, state):
    service = _service(signer, verifier, state)
    base_policy = _policy_with_bounded_rule(policy)
    first_receipt = service.authorize(intent, base_policy)
    first = service.execute_protected(
        intent,
        first_receipt,
        None,
        DeterministicFakeExecutor(),
        current_policy=base_policy,
    )
    second_intent = intent.model_copy(
        update={
            "request_id": "req_causal_2",
            "trace_id": "trc_causal_2",
            "causal_parent_execution_ids": (first.execution_id,),
        }
    )
    causal_policy = _policy_with_bounded_rule(policy, causal=CausalConstraint(maximum_depth=4))
    second_receipt = service.authorize(second_intent, causal_policy)
    assert second_receipt.causal_digest is not None
    assert second_receipt.causal_depth == 1
    second = service.execute_protected(
        second_intent,
        second_receipt,
        None,
        DeterministicFakeExecutor(),
        current_policy=causal_policy,
    )
    second_record = state.get_execution(second.execution_id)
    assert second_record is not None
    assert second_record.causal_digest == second_receipt.causal_digest
    assert second_record.causal_depth == 1


def test_5h_minimal_authority_solver_and_overprivilege_findings(intent):
    recommendation = derive_minimal_authority(intent)
    scope = recommendation.scope
    assert scope.protocols == frozenset({intent.action.protocol})
    assert scope.tools == frozenset({intent.action.tool})
    assert scope.maximum_calls == 1
    assert scope.delegable is False

    broad = scope.model_copy(
        update={
            "capabilities": scope.capabilities | {"production_mutation"},
            "maximum_calls": 25,
            "delegable": True,
            "maximum_delegation_depth": 4,
        }
    )
    analysis = analyze_authority(intent, broad)
    finding_types = {finding.finding_type for finding in analysis.findings}
    assert PolicyIntelligenceFindingType.OVERPRIVILEGED_CAPABILITY in finding_types
    assert PolicyIntelligenceFindingType.EXCESS_CALL_BUDGET in finding_types
    assert PolicyIntelligenceFindingType.UNNEEDED_DELEGATION in finding_types
    assert analysis.least_privilege is False
    assert analyze_authority(intent, scope).least_privilege is True


def test_5h_counterfactual_policy_analysis_is_deterministic(intent, policy):
    analysis = analyze_policy_counterfactuals(policy, intent)
    assert analysis.effect == Effect.ALLOW
    assert analysis.selected_rule_id == "bounded-refund"
    assert analysis.matched_rule_ids == ("bounded-refund",)
    assert len(analysis.counterfactuals) == 1
    counterfactual = analysis.counterfactuals[0]
    assert counterfactual.removed_rule_id == "bounded-refund"
    assert counterfactual.effect == Effect.DENY
    assert analyze_policy_counterfactuals(policy, intent) == analysis


def test_5e_matched_rule_with_no_release_permission_cannot_be_shadowed(
    intent, policy, signer, verifier, state
):
    protected_intent, *_material, provenance_verifier, release_verifier = _field_material(intent)
    base = next(rule for rule in policy.rules if rule.id == "bounded-refund")
    allow_release = base.model_copy(
        update={
            "id": "field-release-allowed",
            "priority": 700,
            "credential": None,
            "field_integrity": (
                FieldIntegrityConstraint(
                    field_path="/order_id",
                    semantic_type="order_id",
                    denied_labels=frozenset({ProvenanceLabel.EXTERNAL_EMAIL}),
                    permitted_release_types=frozenset({FieldReleaseType.HUMAN_ENDORSEMENT}),
                ),
            ),
        }
    )
    forbid_release = base.model_copy(
        update={
            "id": "field-release-forbidden",
            "priority": 600,
            "credential": None,
            "field_integrity": (
                FieldIntegrityConstraint(
                    field_path="/order_id",
                    semantic_type="order_id",
                    denied_labels=frozenset({ProvenanceLabel.EXTERNAL_EMAIL}),
                    permitted_release_types=frozenset(),
                ),
            ),
        }
    )
    multi = policy.model_copy(update={"rules": (allow_release, forbid_release)})
    service = _service(signer, verifier, state, provenance_verifier, release_verifier)
    with pytest.raises(ExecutionGuardError, match="field_integrity.release_required"):
        service.authorize(protected_intent, multi)


def test_5e_conflicting_release_capabilities_fail_closed(intent, policy):
    protected_intent, *_material, provenance_verifier, release_verifier = _field_material(intent)
    base = next(rule for rule in policy.rules if rule.id == "bounded-refund")
    first = base.model_copy(
        update={
            "id": "release-human",
            "credential": None,
            "field_integrity": (
                FieldIntegrityConstraint(
                    field_path="/order_id",
                    semantic_type="order_id",
                    denied_labels=frozenset({ProvenanceLabel.EXTERNAL_EMAIL}),
                    permitted_release_types=frozenset({FieldReleaseType.HUMAN_ENDORSEMENT}),
                ),
            ),
        }
    )
    second = base.model_copy(
        update={
            "id": "release-system",
            "credential": None,
            "field_integrity": (
                FieldIntegrityConstraint(
                    field_path="/order_id",
                    semantic_type="order_id",
                    denied_labels=frozenset({ProvenanceLabel.EXTERNAL_EMAIL}),
                    permitted_release_types=frozenset({FieldReleaseType.SYSTEM_ATTESTATION}),
                ),
            ),
        }
    )
    multi = policy.model_copy(update={"rules": (first, second)})
    evaluation = evaluate_policy(multi, protected_intent)
    with pytest.raises(FieldIntegrityError, match="policy_conflict.release_types"):
        validate_field_integrity(
            protected_intent,
            evaluation.matched_rules,
            provenance_verifier,
            release_verifier,
        )


def test_5e_raw_argument_named_field_provenance_is_not_trusted_metadata(
    intent, policy, signer, verifier, state
):
    field_policy = _field_policy(policy)
    smuggled = intent.model_copy(
        update={
            "arguments": {
                **intent.arguments,
                "field_provenance": {
                    "labels": ["internal_database"],
                    "trusted": True,
                },
            }
        }
    )
    provenance_signer = Ed25519Signer.generate("provenance-ed25519")
    release_signer = Ed25519Signer.generate("field-release-ed25519")
    service = _service(
        signer,
        verifier,
        state,
        Ed25519Verifier({provenance_signer.key_id: provenance_signer.public_key()}),
        Ed25519Verifier({release_signer.key_id: release_signer.public_key()}),
    )
    with pytest.raises(ExecutionGuardError, match="field_integrity.provenance_missing"):
        service.authorize(smuggled, field_policy)


def test_5e_future_and_wrong_key_provenance_fail_closed(intent, policy):
    field_policy = _field_policy(policy)
    provenance_signer = Ed25519Signer.generate("provenance-ed25519")
    wrong_signer = Ed25519Signer.generate("other-provenance")
    release_signer = Ed25519Signer.generate("field-release-ed25519")
    now = datetime.now(UTC)
    future = issue_field_provenance_statement(
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        tenant_id=intent.principal.tenant_id,
        field_path="/order_id",
        value=intent.arguments["order_id"],
        semantic_type="order_id",
        labels=frozenset({ProvenanceLabel.INTERNAL_DATABASE}),
        signer=provenance_signer,
        now=now + timedelta(seconds=30),
    )
    evaluation = evaluate_policy(field_policy, intent)
    with pytest.raises(FieldIntegrityError, match="provenance_not_yet_valid"):
        validate_field_integrity(
            intent.model_copy(update={"field_provenance": (future,)}),
            evaluation.matched_rules,
            Ed25519Verifier({provenance_signer.key_id: provenance_signer.public_key()}),
            Ed25519Verifier({release_signer.key_id: release_signer.public_key()}),
            now=now,
        )
    valid = issue_field_provenance_statement(
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        tenant_id=intent.principal.tenant_id,
        field_path="/order_id",
        value=intent.arguments["order_id"],
        semantic_type="order_id",
        labels=frozenset({ProvenanceLabel.INTERNAL_DATABASE}),
        signer=provenance_signer,
        now=now,
    )
    with pytest.raises(FieldIntegrityError, match="provenance_signature_invalid"):
        validate_field_integrity(
            intent.model_copy(update={"field_provenance": (valid,)}),
            evaluation.matched_rules,
            Ed25519Verifier({wrong_signer.key_id: wrong_signer.public_key()}),
            Ed25519Verifier({release_signer.key_id: release_signer.public_key()}),
            now=now,
        )


def test_5f_commit_rejects_mutated_intent(intent, policy, signer, verifier, state):
    staging_policy = _staging_policy(policy)
    service = _service(signer, verifier, state)
    receipt = service.authorize(intent, staging_policy)
    prepared = service.prepare_protected_execution(
        intent, receipt, None, current_policy=staging_policy
    )
    mutated = intent.model_copy(update={"arguments": {**intent.arguments, "amount_minor": 1}})
    executor = DeterministicFakeExecutor()
    with pytest.raises(ExecutionGuardError):
        service.commit_prepared_execution(
            prepared.prepared_id,
            mutated,
            receipt,
            None,
            executor,
            current_policy=staging_policy,
        )
    assert executor.calls == []


def test_5f_expired_preparation_cannot_reserve_execution(
    intent, policy, signer, verifier, state, monkeypatch
):
    staging_policy = _staging_policy(policy)
    service = _service(signer, verifier, state)
    receipt = service.authorize(intent, staging_policy)
    prepared = service.prepare_protected_execution(
        intent, receipt, None, current_policy=staging_policy
    )
    verified = validate_execution_authority(
        intent,
        receipt,
        None,
        verifier,
        execution_id=prepared.execution_id,
        current_policy=staging_policy,
        execution_repository=state,
        prepared_id=prepared.prepared_id,
    )
    admission_at = prepared.expires_at + timedelta(microseconds=1)
    with monkeypatch.context() as patched:
        patched.setattr(state, "_transaction_now", lambda: admission_at)
        result = state.reserve_prepared_execution(prepared.prepared_id, verified, admission_at)
    assert result == "execution.prepared_expired"
    assert state.get_execution(prepared.execution_id) is None
    stored = state.get_prepared_execution(prepared.prepared_id)
    assert stored is not None and stored.status == PreparedExecutionStatus.EXPIRED


def test_5f_cancel_commit_race_has_at_most_one_effect(intent, policy, signer, verifier, state):
    staging_policy = _staging_policy(policy)
    service = _service(signer, verifier, state)
    receipt = service.authorize(intent, staging_policy)
    prepared = service.prepare_protected_execution(
        intent, receipt, None, current_policy=staging_policy
    )
    executor = DeterministicFakeExecutor()

    def cancel() -> str:
        try:
            return service.cancel_prepared_execution(prepared.prepared_id).status.value
        except ExecutionGuardError as exc:
            return str(exc)

    def commit() -> str:
        try:
            return service.commit_prepared_execution(
                prepared.prepared_id,
                intent,
                receipt,
                None,
                executor,
                current_policy=staging_policy,
            ).status.value
        except ExecutionGuardError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        cancel_future = pool.submit(cancel)
        commit_future = pool.submit(commit)
        results = {cancel_future.result(), commit_future.result()}
    assert len(executor.calls) <= 1
    stored = state.get_prepared_execution(prepared.prepared_id)
    assert stored is not None
    assert stored.status in {PreparedExecutionStatus.CANCELLED, PreparedExecutionStatus.COMMITTED}
    if stored.status == PreparedExecutionStatus.CANCELLED:
        assert executor.calls == []
    else:
        assert len(executor.calls) == 1
    assert "success" in results or PreparedExecutionStatus.CANCELLED.value in results


def test_5g_missing_parent_and_policy_depth_fail_closed(intent, policy, signer, verifier, state):
    service = _service(signer, verifier, state)
    causal_policy = _policy_with_bounded_rule(policy, causal=CausalConstraint(maximum_depth=0))
    missing = intent.model_copy(
        update={
            "request_id": "req_missing_parent",
            "trace_id": "trc_missing_parent",
            "causal_parent_execution_ids": ("exec_does_not_exist",),
        }
    )
    with pytest.raises(ExecutionGuardError, match="causal.parent_missing"):
        service.authorize(missing, causal_policy)

    base_policy = _policy_with_bounded_rule(policy)
    first_receipt = service.authorize(intent, base_policy)
    first = service.execute_protected(
        intent, first_receipt, None, DeterministicFakeExecutor(), current_policy=base_policy
    )
    child = intent.model_copy(
        update={
            "request_id": "req_depth_child",
            "trace_id": "trc_depth_child",
            "causal_parent_execution_ids": (first.execution_id,),
        }
    )
    with pytest.raises(ExecutionGuardError, match="causal.policy_depth_exceeded"):
        service.authorize(child, causal_policy)


def test_5g_cross_tenant_parent_fails_closed(intent, policy, signer, verifier, state):
    service = _service(signer, verifier, state)
    base_policy = _policy_with_bounded_rule(policy)
    receipt = service.authorize(intent, base_policy)
    parent = service.execute_protected(
        intent, receipt, None, DeterministicFakeExecutor(), current_policy=base_policy
    )
    beta_principal = intent.principal.model_copy(update={"tenant_id": "beta"})
    beta_resource = (
        intent.resource.model_copy(update={"owner_tenant": "beta"}) if intent.resource else None
    )
    beta_intent = intent.model_copy(
        update={
            "request_id": "req_beta",
            "trace_id": "trc_beta",
            "principal": beta_principal,
            "resource": beta_resource,
            "causal_parent_execution_ids": (parent.execution_id,),
        }
    )
    bounded = next(rule for rule in policy.rules if rule.id == "bounded-refund")
    beta_rule = bounded.model_copy(
        update={
            "credential": None,
            "principal": bounded.principal.model_copy(update={"tenant_ids": frozenset({"beta"})}),
            "causal": CausalConstraint(maximum_depth=4),
        }
    )
    beta_policy = policy.model_copy(update={"rules": (beta_rule,)})
    with pytest.raises(ExecutionGuardError, match="causal.parent_tenant_mismatch"):
        service.authorize(beta_intent, beta_policy)


def test_5g_causal_graph_reconstructs_declared_ancestry_without_raw_arguments(
    intent, policy, signer, verifier, state
):
    from agentguard.engine.causal import build_causal_execution_graph

    service = _service(signer, verifier, state)
    base_policy = _policy_with_bounded_rule(policy)
    first_receipt = service.authorize(intent, base_policy)
    first = service.execute_protected(
        intent, first_receipt, None, DeterministicFakeExecutor(), current_policy=base_policy
    )
    child_intent = intent.model_copy(
        update={
            "request_id": "req_graph_child",
            "trace_id": "trc_graph_child",
            "causal_parent_execution_ids": (first.execution_id,),
        }
    )
    causal_policy = _policy_with_bounded_rule(policy, causal=CausalConstraint(maximum_depth=4))
    child_receipt = service.authorize(child_intent, causal_policy)
    child = service.execute_protected(
        child_intent,
        child_receipt,
        None,
        DeterministicFakeExecutor(),
        current_policy=causal_policy,
    )
    graph = build_causal_execution_graph(child.execution_id, state)
    assert graph.root_execution_id == child.execution_id
    assert {node.execution_id for node in graph.nodes} == {first.execution_id, child.execution_id}
    child_node = next(node for node in graph.nodes if node.execution_id == child.execution_id)
    assert child_node.parent_execution_ids == (first.execution_id,)
    serialized = graph.model_dump_json()
    assert "order_id" not in serialized
    assert "amount_minor" not in serialized
    assert graph.graph_digest.startswith("sha256:")
