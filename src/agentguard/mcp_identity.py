from __future__ import annotations

import hashlib


def derive_server_id(server_command: list[str]) -> str:
    if not server_command:
        raise ValueError("server command is required")
    return hashlib.sha256("\0".join(server_command).encode("utf-8")).hexdigest()[:16]


def mcp_source_id(server_command: list[str], server_id: str | None = None) -> str:
    resolved = (server_id or derive_server_id(server_command)).strip()
    if not resolved or any(character.isspace() for character in resolved):
        raise ValueError("server_id must be a non-empty token without whitespace")
    return f"mcp_stdio:{resolved}"
