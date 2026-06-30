from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .models import AuditEvent, Decision


class AuditLedger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def record(self, event: AuditEvent) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, agent_id, source, tool_name, call_id,
                    decision, reason, rule_id, arguments_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.agent_id,
                    event.source,
                    event.tool_name,
                    event.call_id,
                    event.decision.value,
                    event.reason,
                    event.rule_id,
                    json.dumps(event.arguments, sort_keys=True),
                ),
            )

    def list_events(self) -> list[AuditEvent]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT event_id, timestamp, agent_id, source, tool_name, call_id,
                       decision, reason, rule_id, arguments_json
                FROM audit_events
                ORDER BY timestamp ASC
                """
            ).fetchall()
        return [
            AuditEvent(
                event_id=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                agent_id=row[2],
                source=row[3],
                tool_name=row[4],
                call_id=row[5],
                decision=Decision(row[6]),
                reason=row[7],
                rule_id=row[8],
                arguments=json.loads(row[9]),
            )
            for row in rows
        ]

    def _init_schema(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    arguments_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_events_decision
                ON audit_events(decision)
                """
            )
