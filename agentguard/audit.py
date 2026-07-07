from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    ApprovalGrant,
    AuditEvent,
    Capability,
    Decision,
    RiskLevel,
    ToolCall,
    ToolInventoryItem,
)


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
            _upsert_tool_inventory(conn, tools)

    def replace_tool_inventory(self, source: str, tools: list[ToolInventoryItem]) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("DELETE FROM tool_inventory WHERE source = ?", (source,))
            _upsert_tool_inventory(conn, tools)

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

    def get_tool_inventory(self, source: str, name: str) -> ToolInventoryItem | None:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                """
                SELECT source, name, description, input_schema_json, output_schema_json,
                       capabilities_json, risk_level, reasons_json, discovered_at
                FROM tool_inventory
                WHERE source = ? AND name = ?
                """,
                (source, name),
            ).fetchone()
        if row is None:
            return None
        return ToolInventoryItem(
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

    def add_approval_grant(self, grant: ApprovalGrant) -> None:
        if grant.max_uses < 1:
            raise ValueError("approval grant max_uses must be greater than zero")
        if grant.expires_at <= grant.created_at:
            raise ValueError("approval grant expires_at must be after created_at")
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT INTO approval_grants (
                    grant_id, created_at, expires_at, agent_id, source, tool_name,
                    arguments_hash, approved_by, reason, max_uses, used_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _approval_grant_row(grant),
            )

    def list_approval_grants(self, include_expired: bool = False) -> list[ApprovalGrant]:
        now = datetime.now(timezone.utc).isoformat()
        where = "" if include_expired else "WHERE expires_at >= ? AND used_count < max_uses"
        params: tuple[str, ...] = () if include_expired else (now,)
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                f"""
                SELECT grant_id, created_at, expires_at, agent_id, source, tool_name,
                       arguments_hash, approved_by, reason, max_uses, used_count
                FROM approval_grants
                {where}
                ORDER BY expires_at ASC, created_at ASC
                """,
                params,
            ).fetchall()
        return [_approval_grant_from_row(row) for row in rows]

    def consume_approval_grant(self, call: ToolCall) -> ApprovalGrant | None:
        now = datetime.now(timezone.utc).isoformat()
        arguments_hash = hash_tool_arguments(call.arguments)
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                """
                SELECT grant_id, created_at, expires_at, agent_id, source, tool_name,
                       arguments_hash, approved_by, reason, max_uses, used_count
                FROM approval_grants
                WHERE agent_id = ?
                  AND source = ?
                  AND tool_name = ?
                  AND arguments_hash = ?
                  AND expires_at >= ?
                  AND used_count < max_uses
                ORDER BY expires_at ASC, created_at ASC
                LIMIT 1
                """,
                (call.agent_id, call.source, call.tool_name, arguments_hash, now),
            ).fetchone()
            if row is None:
                return None
            grant = _approval_grant_from_row(row)
            result = conn.execute(
                """
                UPDATE approval_grants
                SET used_count = used_count + 1
                WHERE grant_id = ? AND used_count < max_uses
                """,
                (grant.grant_id,),
            )
            if result.rowcount != 1:
                return None
        return replace(grant, used_count=grant.used_count + 1)

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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_grants (
                    grant_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments_hash TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    max_uses INTEGER NOT NULL,
                    used_count INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_approval_grants_lookup
                ON approval_grants(agent_id, source, tool_name, arguments_hash, expires_at)
                """
            )


def _upsert_tool_inventory(conn: sqlite3.Connection, tools: list[ToolInventoryItem]) -> None:
    if not tools:
        return
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


def hash_tool_arguments(arguments: dict[str, object]) -> str:
    payload = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _approval_grant_row(grant: ApprovalGrant) -> tuple[object, ...]:
    return (
        grant.grant_id,
        grant.created_at.isoformat(),
        grant.expires_at.isoformat(),
        grant.agent_id,
        grant.source,
        grant.tool_name,
        grant.arguments_hash,
        grant.approved_by,
        grant.reason,
        grant.max_uses,
        grant.used_count,
    )


def _approval_grant_from_row(row: sqlite3.Row | tuple[object, ...]) -> ApprovalGrant:
    return ApprovalGrant(
        grant_id=str(row[0]),
        created_at=datetime.fromisoformat(str(row[1])),
        expires_at=datetime.fromisoformat(str(row[2])),
        agent_id=str(row[3]),
        source=str(row[4]),
        tool_name=str(row[5]),
        arguments_hash=str(row[6]),
        approved_by=str(row[7]),
        reason=str(row[8]),
        max_uses=int(row[9]),
        used_count=int(row[10]),
    )
