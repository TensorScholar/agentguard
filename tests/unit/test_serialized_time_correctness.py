"""Lock-wait regressions for security decisions made inside SQLite transactions.

These are unittest cases so the same tests run under pytest and with the standard library.
The writer lock and connection events make the interleaving independent of wall time.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from typing import Iterator

import yaml

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.executor import DeterministicFakeExecutor
from agentguard.adapters.storage.sqlite import (
    ReconciliationLeaseError,
    SQLiteFencedReconciliationState,
    SQLiteState,
)
from agentguard.application import AgentGuardService
from agentguard.domain import (
    ActionIntent,
    ApprovalReceipt,
    AuthorityGrant,
    CapabilityLease,
    CapabilityScope,
    CredentialRequest,
    EvidenceTrustLevel,
    PreparedExecution,
    PolicyDocument,
    ReconciliationEvidence,
    ReconciliationStatus,
    ReversibilityMode,
    VerifiedExecution,
)
from agentguard.engine.authority import AuthorityError
from agentguard.engine.canonical import digest
from agentguard.engine.execution import ExecutionGuardError, prepared_execution_binding_digest

START = datetime(2026, 9, 2, 20, 0, tzinfo=UTC)
INTENT_PATH = Path(__file__).parents[2] / "src/agentguard/resources/demo-intent.json"


class _SignallingConnection(sqlite3.Connection):
    begin_attempt: Event | None = None

    def execute(self, sql: str, parameters=()):  # type: ignore[no-untyped-def]
        if sql == "BEGIN IMMEDIATE" and self.begin_attempt is not None:
            self.begin_attempt.set()
        return super().execute(sql, parameters)


class _TransactionTime:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class _LockAwareMixin:
    clock: _TransactionTime
    begin_attempt: Event | None

    def _transaction_now(self) -> datetime:
        return self.clock.now()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, factory=_SignallingConnection
        )
        try:
            connection.begin_attempt = self.begin_attempt
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA secure_delete=ON")
            with connection:
                yield connection
        finally:
            connection.close()


class _State(_LockAwareMixin, SQLiteState):
    def __init__(self, path: Path, clock: _TransactionTime) -> None:
        self.clock = clock
        self.begin_attempt = None
        super().__init__(path)


class _FencedState(_LockAwareMixin, SQLiteFencedReconciliationState):
    def __init__(self, path: Path, clock: _TransactionTime) -> None:
        self.clock = clock
        self.begin_attempt = None
        super().__init__(path)


def _intent() -> ActionIntent:
    return ActionIntent.model_validate_json(INTENT_PATH.read_text())


def _grant(intent: ActionIntent, *, parent: str | None = None) -> AuthorityGrant:
    return AuthorityGrant(
        grant_id="grant_child" if parent else "grant_root",
        parent_grant_id=parent,
        issuer="test",
        subject=intent.principal,
        scope=CapabilityScope(maximum_calls=2),
        depth=1 if parent else 0,
        issued_at=START,
        expires_at=START + timedelta(seconds=5),
        key_id="test-key",
        signature="test-signature",
    )


def _lease() -> CapabilityLease:
    return CapabilityLease(
        lease_id="lease_test",
        grant_id="grant_root",
        maximum_uses=1,
        remaining_uses=1,
        issued_at=START,
        expires_at=START + timedelta(seconds=5),
    )


def _verified(intent: ActionIntent, *, prepared: bool = False) -> VerifiedExecution:
    return VerifiedExecution(
        execution_id="exec_test",
        decision_id="decision_test",
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        intent=intent,
        intent_digest=digest(intent),
        policy_digest=digest("policy"),
        nonce="nonce_test",
        authority_grant_id="grant_root",
        authority_lease_id="lease_test",
        prepared_id="prep_test" if prepared else None,
        authorization_expires_at=START + timedelta(seconds=60),
        verified_at=START,
    )


def _unknown(state: SQLiteState) -> None:
    with sqlite3.connect(state.path) as connection:
        connection.execute(
            """INSERT INTO executions(
                 execution_id,decision_id,nonce,trace_id,request_id,intent_digest,
                 authority_digest,state,reserved_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "exec_unknown", "decision_unknown", "nonce_unknown", "trace_unknown",
                "request_unknown", digest("intent"), digest("authority"), "unknown",
                START.isoformat(),
            ),
        )


def _evidence() -> ReconciliationEvidence:
    return ReconciliationEvidence(
        status=ReconciliationStatus.STILL_UNKNOWN,
        source="provider",
        evidence_digest=digest("provider-result"),
        trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
        observed_at=START,
    )


class SerializedTimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "state.sqlite"
        self.clock = _TransactionTime(START)

    def _blocked(self, state: _State | _FencedState, operation, *, after: datetime):
        attempted = Event()
        state.begin_attempt = attempted
        with closing(sqlite3.connect(state.path, isolation_level=None)) as blocker:
            blocker.execute("BEGIN IMMEDIATE")
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(operation)
                self.assertTrue(attempted.wait(5), "worker did not attempt BEGIN IMMEDIATE")
                self.clock.value = after
                blocker.execute("COMMIT")
                result = future.result(timeout=5)
        state.begin_attempt = None
        return result

    def test_lease_expiring_behind_writer_lock_cannot_reserve(self) -> None:
        state = _State(self.path, self.clock)
        intent = _intent()
        state.store_authority_grant(_grant(intent))
        state.store_capability_lease(_lease())
        verified = _verified(intent)

        error = self._blocked(
            state, lambda: state.reserve_execution(verified, START),
            after=START + timedelta(seconds=6),
        )
        self.assertEqual(error, "authority.lease_unavailable")
        self.assertIsNone(state.get_execution(verified.execution_id))
        lease = state.get_capability_lease("lease_test")
        self.assertIsNotNone(lease)
        self.assertEqual(lease.remaining_uses, 1)

    def test_concurrent_last_use_still_has_one_reservation_winner(self) -> None:
        state = _State(self.path, self.clock)
        intent = _intent()
        state.store_authority_grant(_grant(intent))
        state.store_capability_lease(_lease())
        first = _verified(intent)
        second = first.model_copy(
            update={
                "execution_id": "exec_second",
                "decision_id": "decision_second",
                "nonce": "nonce_second",
            }
        )
        start = Event()

        def reserve(verified: VerifiedExecution) -> str | None:
            self.assertTrue(start.wait(5))
            return state.reserve_execution(verified, START)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [pool.submit(reserve, verified) for verified in (first, second)]
            start.set()
            outcomes = [future.result(timeout=5) for future in results]
        self.assertEqual(outcomes.count(None), 1)
        self.assertEqual(outcomes.count("authority.lease_unavailable"), 1)
        self.assertEqual(len(state.list_executions()), 1)

    def test_service_never_dispatches_when_reservation_admission_expires(self) -> None:
        self.clock.value = datetime.now(UTC)
        state = _State(self.path, self.clock)
        intent = _intent()
        policy = PolicyDocument.model_validate_json(
            json.dumps(yaml.safe_load((INTENT_PATH.parent / "default_policy_v2.yaml").read_text()))
        )
        signer = Ed25519Signer.generate()
        verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
        authority_signer = Ed25519Signer.generate("test-authority")
        authority_verifier = Ed25519Verifier(
            {authority_signer.key_id: authority_signer.public_key()}
        )
        broker = MockCredentialBroker()
        service = AgentGuardService(
            signer, verifier, state, broker.verifier, authority_verifier=authority_verifier
        )
        scope = CapabilityScope(
            capabilities=frozenset({"financial_mutation"}),
            maximum_calls=1,
        )
        root = service.issue_root_authority(intent.principal, scope, authority_signer)
        lease = service.issue_capability_lease(
            root.grant_id, intent.principal, maximum_uses=1, ttl_seconds=60
        )
        bound = intent.model_copy(
            update={"authority": service.authority_reference(root.grant_id, lease.lease_id)}
        )
        receipt = service.authorize(bound, policy)
        ceiling = receipt.credential_ceiling
        self.assertIsNotNone(ceiling)
        request = CredentialRequest(
            request_id="serialized-time-credential", trace_id=receipt.trace_id,
            decision_id=receipt.decision_id, audience=ceiling.audience,
            scopes=ceiling.scopes, requested_ttl_seconds=30, tenant_id=ceiling.tenant_id,
        )
        credential = service.request_credential(bound, receipt, request, broker)
        executor = DeterministicFakeExecutor()

        def execute() -> str:
            try:
                service.execute_protected(
                    bound, receipt, credential, executor, current_policy=policy
                )
            except ExecutionGuardError as exc:
                return str(exc)
            return "dispatched"

        result = self._blocked(
            state, execute, after=lease.expires_at + timedelta(microseconds=1)
        )
        self.assertEqual(result, "authority.lease_unavailable")
        self.assertEqual(executor.calls, [])
        self.assertEqual(state.list_executions(), ())

    def test_prepared_reservation_cannot_consume_expired_lease(self) -> None:
        state = _State(self.path, self.clock)
        intent = _intent()
        state.store_authority_grant(_grant(intent))
        state.store_capability_lease(_lease())
        verified = _verified(intent, prepared=True)
        state.store_prepared_execution(
            PreparedExecution(
                prepared_id="prep_test", execution_id=verified.execution_id,
                decision_id=verified.decision_id, request_id=verified.request_id,
                trace_id=verified.trace_id, intent_digest=verified.intent_digest,
                prepared_binding_digest=prepared_execution_binding_digest(verified),
                reversibility=ReversibilityMode.IRREVERSIBLE,
                prepared_at=START, commit_not_before=START,
                expires_at=START + timedelta(seconds=30),
            )
        )
        error = self._blocked(
            state, lambda: state.reserve_prepared_execution("prep_test", verified, START),
            after=START + timedelta(seconds=6),
        )
        self.assertEqual(error, "authority.lease_unavailable")
        self.assertIsNone(state.get_execution(verified.execution_id))

    def test_expired_preparation_behind_writer_lock_cannot_commit(self) -> None:
        state = _State(self.path, self.clock)
        intent = _intent()
        state.store_authority_grant(_grant(intent))
        state.store_capability_lease(_lease())
        verified = _verified(intent, prepared=True)
        state.store_prepared_execution(
            PreparedExecution(
                prepared_id="prep_test", execution_id=verified.execution_id,
                decision_id=verified.decision_id, request_id=verified.request_id,
                trace_id=verified.trace_id, intent_digest=verified.intent_digest,
                prepared_binding_digest=prepared_execution_binding_digest(verified),
                reversibility=ReversibilityMode.IRREVERSIBLE,
                prepared_at=START, commit_not_before=START,
                expires_at=START + timedelta(seconds=2),
            )
        )
        error = self._blocked(
            state, lambda: state.reserve_prepared_execution("prep_test", verified, START),
            after=START + timedelta(seconds=3),
        )
        self.assertEqual(error, "execution.prepared_expired")
        self.assertIsNone(state.get_execution(verified.execution_id))

    def test_preparation_becoming_ready_behind_writer_lock_can_commit(self) -> None:
        state = _State(self.path, self.clock)
        intent = _intent()
        verified = _verified(intent, prepared=True).model_copy(
            update={"authority_grant_id": None, "authority_lease_id": None}
        )
        state.store_prepared_execution(
            PreparedExecution(
                prepared_id="prep_test", execution_id=verified.execution_id,
                decision_id=verified.decision_id, request_id=verified.request_id,
                trace_id=verified.trace_id, intent_digest=verified.intent_digest,
                prepared_binding_digest=prepared_execution_binding_digest(verified),
                reversibility=ReversibilityMode.IRREVERSIBLE,
                prepared_at=START, commit_not_before=START + timedelta(seconds=3),
                expires_at=START + timedelta(seconds=30),
            )
        )
        error = self._blocked(
            state, lambda: state.reserve_prepared_execution("prep_test", verified, START),
            after=START + timedelta(seconds=4),
        )
        self.assertIsNone(error)
        self.assertIsNotNone(state.get_execution(verified.execution_id))

    def test_expired_reconciliation_lease_cannot_commit_resolution(self) -> None:
        state = _FencedState(self.path, self.clock)
        _unknown(state)
        lease = state.claim_reconciliation_lease(
            "exec_unknown", "worker", now=START, lease_seconds=5
        )
        self.assertIsNotNone(lease)

        def resolve() -> str:
            with state.resolution_lease(lease):
                try:
                    state.record_execution_resolution("exec_unknown", _evidence(), START)
                except ReconciliationLeaseError as exc:
                    return str(exc)
            return "committed"

        result = self._blocked(state, resolve, after=START + timedelta(seconds=6))
        self.assertEqual(result, "reconciliation.lease_lost")
        self.assertEqual(state.list_execution_resolutions("exec_unknown"), ())

    def test_lease_acquisition_starts_at_serialized_time(self) -> None:
        state = _FencedState(self.path, self.clock)
        _unknown(state)
        lease = self._blocked(
            state,
            lambda: state.claim_reconciliation_lease(
                "exec_unknown", "worker", now=START, lease_seconds=5
            ),
            after=START + timedelta(seconds=6),
        )
        self.assertIsNotNone(lease)
        self.assertEqual(lease.acquired_at, START + timedelta(seconds=6))
        self.assertEqual(lease.expires_at, START + timedelta(seconds=11))
        self.assertEqual(state.get_reconciliation_lease("exec_unknown"), lease)

    def test_expiry_during_lock_wait_allows_fenced_takeover(self) -> None:
        state = _FencedState(self.path, self.clock)
        _unknown(state)
        first = state.claim_reconciliation_lease(
            "exec_unknown", "worker-one", now=START, lease_seconds=5
        )
        self.assertIsNotNone(first)
        second = self._blocked(
            state,
            lambda: state.claim_reconciliation_lease(
                "exec_unknown", "worker-two", now=START, lease_seconds=5
            ),
            after=START + timedelta(seconds=6),
        )
        self.assertIsNotNone(second)
        self.assertEqual(second.owner_id, "worker-two")
        self.assertGreater(second.fencing_token, first.fencing_token)

    def test_concurrent_reconciliation_claim_still_has_one_winner(self) -> None:
        state = _FencedState(self.path, self.clock)
        _unknown(state)
        start = Event()

        def claim(owner: str):
            self.assertTrue(start.wait(5))
            return state.claim_reconciliation_lease(
                "exec_unknown", owner, now=START, lease_seconds=5
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [pool.submit(claim, owner) for owner in ("worker-one", "worker-two")]
            start.set()
            leases = [future.result(timeout=5) for future in results]
        self.assertEqual(sum(lease is not None for lease in leases), 1)
        self.assertEqual(state.get_reconciliation_lease("exec_unknown"), next(
            lease for lease in leases if lease is not None
        ))

    def test_expired_lease_cannot_be_renewed_after_writer_lock(self) -> None:
        state = _FencedState(self.path, self.clock)
        _unknown(state)
        lease = state.claim_reconciliation_lease(
            "exec_unknown", "worker", now=START, lease_seconds=5
        )
        self.assertIsNotNone(lease)

        def renew() -> str:
            try:
                state.renew_reconciliation_lease(lease, now=START, lease_seconds=30)
            except ReconciliationLeaseError as exc:
                return str(exc)
            return "renewed"

        result = self._blocked(state, renew, after=START + timedelta(seconds=6))
        self.assertEqual(result, "reconciliation.lease_lost")
        self.assertEqual(state.get_reconciliation_lease("exec_unknown"), lease)

    def test_parent_grant_expiring_behind_lock_cannot_delegate(self) -> None:
        state = _State(self.path, self.clock)
        intent = _intent()
        state.store_authority_grant(_grant(intent))
        child = _grant(intent, parent="grant_root")

        def delegate() -> str:
            try:
                state.store_authority_grant(child)
            except RuntimeError as exc:
                return str(exc)
            return "delegated"

        result = self._blocked(state, delegate, after=START + timedelta(seconds=6))
        self.assertNotEqual(result, "delegated")
        self.assertIsNone(state.get_authority_grant("grant_child"))
        self.assertEqual(state.get_authority_grant("grant_root").remaining_calls, 2)

    def test_root_grant_expiring_behind_lock_cannot_be_issued(self) -> None:
        state = _State(self.path, self.clock)
        root = _grant(_intent())

        def issue() -> str:
            try:
                state.store_authority_grant(root)
            except RuntimeError as exc:
                return str(exc)
            return "issued"

        result = self._blocked(state, issue, after=START + timedelta(seconds=6))
        self.assertNotEqual(result, "issued")
        self.assertIsNone(state.get_authority_grant("grant_root"))

    def test_service_reports_expired_root_grant_without_issuing_it(self) -> None:
        self.clock.value = datetime.now(UTC)
        state = _State(self.path, self.clock)
        signer = Ed25519Signer.generate()
        verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
        service = AgentGuardService(signer, verifier, state)
        authority_signer = Ed25519Signer.generate("test-authority")

        def issue() -> str:
            try:
                service.issue_root_authority(
                    _intent().principal, CapabilityScope(maximum_calls=1),
                    authority_signer, ttl_seconds=60,
                )
            except AuthorityError as exc:
                return str(exc)
            return "issued"

        result = self._blocked(
            state, issue, after=self.clock.value + timedelta(seconds=61)
        )
        self.assertEqual(result, "authority.grant_expired")
        self.assertEqual(state.list_events(), [])

    def test_expired_lease_cannot_be_issued_behind_lock(self) -> None:
        state = _State(self.path, self.clock)
        state.store_authority_grant(_grant(_intent()))

        def issue() -> str:
            try:
                state.store_capability_lease(_lease())
            except RuntimeError as exc:
                return str(exc)
            return "issued"

        result = self._blocked(state, issue, after=START + timedelta(seconds=6))
        self.assertNotEqual(result, "issued")
        self.assertIsNone(state.get_capability_lease("lease_test"))
        self.assertEqual(state.get_authority_grant("grant_root").remaining_calls, 2)

    def test_expired_approval_cannot_be_consumed_behind_lock(self) -> None:
        state = _State(self.path, self.clock)
        approval = ApprovalReceipt(
            approval_id="approval_test", decision_id="decision_test", trace_id="trace_test",
            approver_subject="approver", approved_action_digest=digest("action"),
            approved_arguments_digest=digest("arguments"), reason="test",
            issued_at=START, expires_at=START + timedelta(seconds=5),
            key_id="test-key", signature="test-signature",
        )
        state.register_approval(approval)
        error = self._blocked(
            state,
            lambda: state.claim_credential_issuance(
                request_id="request_test", decision_id="decision_test",
                approval_id="approval_test", single_use=True, claimed_at=START,
            ),
            after=START + timedelta(seconds=6),
        )
        self.assertEqual(error, "credential.approval_expired")
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(
                connection.execute("SELECT used_count FROM approvals").fetchone()[0], 0
            )
            self.assertEqual(
                connection.execute("SELECT count(*) FROM credential_issuance_claims").fetchone()[0],
                0,
            )


if __name__ == "__main__":
    unittest.main()
