from __future__ import annotations

import multiprocessing
import sqlite3
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agentguard.adapters.storage.sqlite import SQLiteFencedReconciliationState

NOW = datetime(2026, 9, 2, 21, 0, tzinfo=UTC)


def _insert_unknown(path: Path) -> None:
    state = SQLiteFencedReconciliationState(path)
    del state
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO executions(
                execution_id,decision_id,nonce,trace_id,request_id,intent_digest,
                authority_digest,state,reserved_at,dispatching_at,completed_at,error_code
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "exec_process_race",
                "decision_process_race",
                "nonce_process_race",
                "trace_process_race",
                "request_process_race",
                "sha256:" + "1" * 64,
                "sha256:" + "2" * 64,
                "unknown",
                (NOW - timedelta(seconds=2)).isoformat(),
                (NOW - timedelta(seconds=1)).isoformat(),
                NOW.isoformat(),
                "execution.outcome_ambiguous",
            ),
        )


def _claim_in_process(path: str, owner_id: str, now_iso: str) -> int | None:
    state = SQLiteFencedReconciliationState(Path(path))
    lease = state.claim_reconciliation_lease(
        "exec_process_race",
        owner_id,
        now=datetime.fromisoformat(now_iso),
        lease_seconds=30,
    )
    return lease.fencing_token if lease is not None else None


def test_two_spawned_processes_cannot_own_same_reconciliation_work(tmp_path) -> None:
    path = tmp_path / "multiprocess.sqlite"
    _insert_unknown(path)
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=2, mp_context=context) as executor:
        futures = [
            executor.submit(_claim_in_process, str(path), "worker-a", NOW.isoformat()),
            executor.submit(_claim_in_process, str(path), "worker-b", NOW.isoformat()),
        ]
        results = [future.result(timeout=20) for future in futures]

    winners = [token for token in results if token is not None]
    assert len(winners) == 1
    assert winners[0] >= 1

    persisted = SQLiteFencedReconciliationState(path).get_reconciliation_lease("exec_process_race")
    assert persisted is not None
    assert persisted.fencing_token == winners[0]
