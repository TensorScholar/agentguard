from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass(frozen=True)
class FenceLease:
    alpha: str
    owner: str
    token: int
    expires_at: datetime


class ConventionalReconciliationFence:
    """Minimal transactional fencing for the strong conventional B4 baseline."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS fence_counter(singleton INTEGER PRIMARY KEY, next_token INTEGER NOT NULL);
    INSERT OR IGNORE INTO fence_counter(singleton,next_token) VALUES(1,1);
    CREATE TABLE IF NOT EXISTS leases(
        alpha TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        token INTEGER NOT NULL,
        expires_at TEXT NOT NULL
    );
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.executescript(self._SCHEMA)

    def claim(
        self, alpha: str, owner: str, *, now: datetime, lease_seconds: int
    ) -> FenceLease | None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        now = now.astimezone(UTC)
        expires_at = now + timedelta(seconds=lease_seconds)
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT owner,token,expires_at FROM leases WHERE alpha=?", (alpha,)
            ).fetchone()
            if row is not None and datetime.fromisoformat(str(row[2])).astimezone(UTC) > now:
                connection.execute("COMMIT")
                return None
            token_row = connection.execute(
                "SELECT next_token FROM fence_counter WHERE singleton=1"
            ).fetchone()
            if token_row is None:
                connection.execute("ROLLBACK")
                raise RuntimeError("fence.counter_missing")
            token = int(token_row[0])
            connection.execute(
                "UPDATE fence_counter SET next_token=? WHERE singleton=1", (token + 1,)
            )
            connection.execute(
                """
                INSERT INTO leases(alpha,owner,token,expires_at) VALUES(?,?,?,?)
                ON CONFLICT(alpha) DO UPDATE SET owner=excluded.owner,token=excluded.token,
                                                 expires_at=excluded.expires_at
                """,
                (alpha, owner, token, expires_at.isoformat()),
            )
            connection.execute("COMMIT")
        return FenceLease(alpha, owner, token, expires_at)

    def commit_is_current(self, lease: FenceLease, *, now: datetime) -> bool:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        now = now.astimezone(UTC)
        with sqlite3.connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT owner,token,expires_at FROM leases WHERE alpha=?", (lease.alpha,)
            ).fetchone()
            valid = bool(
                row is not None
                and str(row[0]) == lease.owner
                and int(row[1]) == lease.token
                and datetime.fromisoformat(str(row[2])).astimezone(UTC) > now
            )
            connection.execute("COMMIT")
        return valid
