from __future__ import annotations
import json
from typing import Any

class MCPProtocolError(ValueError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code

def parse_message(raw: bytes, max_bytes: int = 1_000_000) -> dict[str, Any]:
    if len(raw) > max_bytes:
        raise MCPProtocolError(-32600, "message too large")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MCPProtocolError(-32700, "parse error") from exc
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise MCPProtocolError(-32600, "invalid JSON-RPC request")
    return value

def encode_message(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

def error_response(request_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> bytes:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return encode_message({"jsonrpc": "2.0", "id": request_id, "error": error})
