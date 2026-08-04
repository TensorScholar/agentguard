from __future__ import annotations

from agentguard.audit import AuditLedger
from agentguard.engine.canonical import digest
from agentguard.mcp_identity import mcp_source_id
from agentguard.ports import ResolvedToolSchema


class AuditLedgerToolSchemaResolver:
    """Expose the preserved v0.1 MCP inventory through the v2 schema resolver port."""

    def __init__(self, ledger: AuditLedger) -> None:
        self.ledger = ledger

    def resolve(self, server: str, tool: str) -> ResolvedToolSchema | None:
        if server != server.strip():
            return None
        try:
            source = mcp_source_id(server_command=[], server_id=server)
        except ValueError:
            return None
        item = self.ledger.get_tool_inventory(source, tool)
        if item is None:
            return None
        schema = {
            "inputSchema": item.input_schema,
            "outputSchema": item.output_schema,
        }
        return ResolvedToolSchema(
            schema=schema,
            schema_digest=digest(schema),
            discovered_at=item.discovered_at,
        )
