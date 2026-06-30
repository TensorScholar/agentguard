from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .models import AuditEvent, Capability, Decision, RiskLevel, ToolInventoryItem


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

    def upsert_tool_inventory(self, tools: list[ToolInventoryItem]) -> None:
        if not tools:
            return
        with sqlite3.connect(self.path) as conn:
            conn.executemany(
                """
                INSERT INTO tool_inventory (
                    source, name, description, input_schema_json, output_schema_json,
                    capabilities_json, risk_level, reasons_json, discovered_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source, name) DO UPDATE SET
                    description = excluded.description,
                    input_schema_json = excluded.input_schema_json,
                    output_schema_json = excluded.output_schema_json,
                    capabilities_json = excluded.capabilities_json,
                    risk_level = excluded.risk_level,
                    reasons_json = excluded.reasons_json,
                    discovered_at = excluded.discovered_at
                """,
                [
                    (
                        tool.source,
                        tool.name,
                        tool.description,
                        json.dumps(tool.input_schema, sort_keys=True),
                        json.dumps(tool.output_schema, sort_keys=True),
                        json.dumps([capability.value for capability in tool.capabilities]),
                        tool.risk_level.value,
                        json.dumps(list(tool.reasons)),
                        tool.discovered_at.isoformat(),
                    )
                    for tool in tools
                ],
            )

    def list_tool_inventory(self) -> list[ToolInventoryItem]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                """
                SELECT source, name, description, input_schema_json, output_schema_json,
                       capabilities_json, risk_level, reasons_json, discovered_at
                FROM tool_inventory
                ORDER BY risk_level DESC, source ASC, name ASC
                """
            ).fetchall()
        return [
            ToolInventoryItem(
                source=row[0],
                name=row[1],
                description=row[2],
                input_schema=json.loads(row[3]),
                output_schema=json.loads(row[4]),
                capabilities=tuple(Capability(value) for value in json.loads(row[5])),
                risk_level=RiskLevel(row[6]),
                reasons=tuple(json.loads(row[7])),
                discovered_at=datetime.fromisoformat(row[8]),
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tool_inventory (
                    source TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    input_schema_json TEXT NOT NULL,
                    output_schema_json TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    reasons_json TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    PRIMARY KEY (source, name)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tool_inventory_risk
                ON tool_inventory(risk_level)
                """
            )
