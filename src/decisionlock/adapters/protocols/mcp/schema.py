from __future__ import annotations

from decisionlock.audit import AuditLedger
from decisionlock.engine.canonical import digest
from decisionlock.ports import ResolvedToolSchema


class AuditLedgerToolSchemaResolver:
    """Expose the preserved v0.1 MCP inventory through the v2 schema resolver port."""

    def __init__(self, ledger: AuditLedger, *, source: str = "mcp_stdio") -> None:
        self.ledger = ledger
        self.source = source

    def resolve(self, server: str, tool: str) -> ResolvedToolSchema | None:
        del server  # The configured inventory source identifies the concrete server connection.
        item = self.ledger.get_tool_inventory(self.source, tool)
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
