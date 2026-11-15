from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from decisionlock.adapters.storage.sqlite import (
    SQLiteFencedReconciliationState as _SQLiteFencedReconciliationState,
)

NOW = datetime(2026, 9, 2, 20, 0, tzinfo=UTC)


class SQLiteFencedReconciliationState(_SQLiteFencedReconciliationState):
    def __init__(self, path) -> None:
        self.serialized_now = NOW
        super().__init__(path)

    def _transaction_now(self) -> datetime:
        return self.serialized_now


def _insert_unknown(path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO executions(
                execution_id,decision_id,nonce,trace_id,request_id,intent_digest,
                authority_digest,state,reserved_at,dispatching_at,completed_at,error_code
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "exec_time",
                "decision_time",
                "nonce_time",
                "trace_time",
                "request_time",
                "sha256:" + "1" * 64,
                "sha256:" + "2" * 64,
                "unknown",
                (NOW - timedelta(seconds=2)).isoformat(),
                (NOW - timedelta(seconds=1)).isoformat(),
                NOW.isoformat(),
                "execution.outcome_ambiguous",
            ),
        )


def test_lease_times_are_canonicalized_to_utc_across_offsets(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path)

    plus_two = datetime.fromisoformat("2026-09-02T22:00:00+02:00")
    lease = state.claim_reconciliation_lease(
        "exec_time",
        "worker-a",
        now=plus_two,
        lease_seconds=30,
    )
    assert lease is not None
    assert lease.acquired_at == NOW
    assert lease.acquired_at.tzinfo is UTC
    assert lease.expires_at == NOW + timedelta(seconds=30)

    minus_five = datetime.fromisoformat("2026-09-02T15:00:05-05:00")
    state.serialized_now = NOW + timedelta(seconds=5)
    renewed = state.renew_reconciliation_lease(
        lease,
        now=minus_five,
        lease_seconds=30,
    )
    assert renewed.acquired_at == NOW
    assert renewed.expires_at == NOW + timedelta(seconds=35)
    persisted = state.get_reconciliation_lease("exec_time")
    assert persisted == renewed
    assert persisted is not None
    assert persisted.expires_at.tzinfo is UTC
