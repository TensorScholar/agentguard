from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime

import pytest

import decisionlock.reconcile_worker_cli as worker_cli
from decisionlock.application import (
    ReconciliationTickResult,
    ReconciliationWorkerHealth,
)


class FakeWorker:
    def __init__(self, health: ReconciliationWorkerHealth) -> None:
        self._health = health

    def health(self) -> ReconciliationWorkerHealth:
        return self._health


def test_worker_profile_normalizes_operator_status_values() -> None:
    args = argparse.Namespace(
        status_tool="operation_status",
        status_lookup_argument="requestId",
        status_field="status",
        provider_operation_id_field="none",
        success_value=["DONE"],
        failure_value=["BROKEN"],
        pending_value=["WAITING"],
    )
    profile = worker_cli._profile(
        args,
        {
            "inputSchema": {
                "type": "object",
                "properties": {"requestId": {"type": "string"}},
            }
        },
    )
    assert profile.succeeded_values == frozenset({"done"})
    assert profile.failed_values == frozenset({"broken"})
    assert profile.pending_values == frozenset({"waiting"})
    assert profile.provider_operation_id_field is None


def test_worker_health_and_tick_payloads_are_bounded_operational_metadata() -> None:
    started = datetime(2026, 9, 2, 20, 0, tzinfo=UTC)
    completed = datetime(2026, 9, 2, 20, 0, 1, tzinfo=UTC)
    worker = FakeWorker(
        ReconciliationWorkerHealth(
            owner_id="worker-a",
            live=True,
            ready=True,
            last_tick_started_at=started,
            last_tick_completed_at=completed,
            last_error=None,
            consecutive_failed_ticks=0,
        )
    )
    health = worker_cli._health_payload(worker)  # type: ignore[arg-type]
    assert health == {
        "owner_id": "worker-a",
        "live": True,
        "ready": True,
        "last_tick_started_at": started.isoformat(),
        "last_tick_completed_at": completed.isoformat(),
        "last_error": None,
        "consecutive_failed_ticks": 0,
    }

    tick = worker_cli._tick_payload(  # type: ignore[arg-type]
        worker,
        ReconciliationTickResult(
            scanned=4,
            eligible=3,
            claimed=2,
            reconciled=1,
            busy=1,
            lease_lost=0,
            failed=1,
        ),
    )
    assert tick["event"] == "reconciliation_tick"
    assert tick["owner_id"] == "worker-a"
    assert tick["scanned"] == 4
    assert tick["failed"] == 1
    assert set(tick) == {
        "event",
        "observed_at",
        "owner_id",
        "scanned",
        "eligible",
        "claimed",
        "reconciled",
        "busy",
        "lease_lost",
        "failed",
    }
    json.dumps(tick)


def test_worker_cli_rejects_lease_that_cannot_cover_provider_timeout(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "decisionlock-reconcile-worker",
            "--server-id",
            "filesystem",
            "--upstream-url",
            "https://provider.example/mcp",
            "--status-tool",
            "operation_status",
            "--status-schema",
            str(tmp_path / "unused.json"),
            "--timeout-seconds",
            "30",
            "--lease-seconds",
            "35",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        worker_cli.entrypoint()
    assert exc.value.code == 2
    assert "must exceed --timeout-seconds by more than 5 seconds" in capsys.readouterr().err


def test_default_worker_owner_is_nonempty_and_process_scoped() -> None:
    owner = worker_cli._default_owner_id()
    assert owner.strip()
    assert ":" in owner
