"""Local fake MCP provider for the AgentGuard happy-path demo.

Standard library only. Not part of the AgentGuard package and not installed by it.

It exists to make two things runnable that otherwise a new user cannot see:

1. A real side-effecting tool (``refund.create``) behind a protected MCP path, so
   the happy path has an actual upstream to execute against.
2. A genuinely ambiguous outcome. ``--ambiguous`` makes the provider **commit the
   refund to its own durable ledger and then never respond**, which is what a real
   lost-connection-after-send looks like. AgentGuard cannot tell whether the
   effect committed and must record ``UNKNOWN``.

The provider keeps its own ledger in ``--ledger``. The reconciler reads it back
through the ``refund.status`` tool, so the confirmation in the demo comes from the
provider's own state rather than from anything AgentGuard asserts.

This is a demo harness, not a model of a real payment provider. See README.md for
exactly what the demo proves and what it does not.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

TOOLS = [
    {
        "name": "refund.create",
        "description": (
            "Refund a customer for an order. Side-effecting and irreversible: "
            "writes a ledger entry and applies a payment adjustment. Not undoable."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "string"},
                "amount_minor": {"type": "integer"},
                "currency": {"type": "string"},
                "requestId": {"type": "string"},
            },
            "required": ["order_id", "amount_minor", "currency", "requestId"],
        },
    },
    {
        "name": "refund.status",
        "description": "Read the refund status record for a previously submitted refund.",
        "inputSchema": {
            "type": "object",
            "properties": {"requestId": {"type": "string"}},
            "required": ["requestId"],
        },
    },
]

# Reentrant because should_go_ambiguous() holds the lock while calling lookup().
_lock = threading.RLock()


class ProviderState:
    def __init__(self, ledger: Path, ambiguous: bool, ambiguous_for: frozenset[str]) -> None:
        self.ledger = ledger
        self.ambiguous = ambiguous
        # Client-supplied request ids that should go ambiguous. Empty means "the
        # first refund submitted", which is what --ambiguous alone does.
        self.ambiguous_for = ambiguous_for
        self.ambiguous_fired: set[str] = set()
        self.ledger.parent.mkdir(parents=True, exist_ok=True)

    def commit(self, record: dict[str, object]) -> None:
        with _lock, self.ledger.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()

    def lookup(self, request_id: str) -> dict[str, object] | None:
        if not self.ledger.is_file():
            return None
        with _lock:
            for line in reversed(self.ledger.read_text(encoding="utf-8").splitlines()):
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("requestId") == request_id:
                    return record
        return None

    def should_go_ambiguous(self, request_id: str, client_request_id: object) -> bool:
        """Ambiguous once per selected request id."""

        if not self.ambiguous:
            return False
        key = str(client_request_id or "")
        with _lock:
            if self.ambiguous_for:
                if key not in self.ambiguous_for or key in self.ambiguous_fired:
                    return False
            else:
                if self.ambiguous_fired or self.lookup(request_id) is None:
                    return False
            self.ambiguous_fired.add(key if self.ambiguous_for else "__first__")
            return True


def _result(
    request_id: object, payload: object, *, structured: dict[str, object] | None = None
) -> dict[str, object]:
    result: dict[str, object] = {
        "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}]
    }
    if structured is not None:
        result["structuredContent"] = structured
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


class Handler(BaseHTTPRequestHandler):
    state: ProviderState

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        sys.stderr.write("provider: " + (format % args) + "\n")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length)
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(
                400,
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
            )
            return

        rpc_id = message.get("id")
        method = message.get("method")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}

        if method == "tools/list":
            self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": TOOLS}})
            return

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if name == "refund.create":
                # Key on the JSON-RPC request id. AgentGuard sets that to its
                # execution id on a protected dispatch, so this is the handle the
                # provider status tool can be queried with later. The client's own
                # requestId is retained as an opaque application field only.
                record = {
                    "requestId": str(rpc_id),
                    "clientRequestId": arguments.get("requestId"),
                    "order_id": arguments.get("order_id"),
                    "amount_minor": arguments.get("amount_minor"),
                    "currency": arguments.get("currency"),
                    "status": "succeeded",
                    "providerOperationId": "ch_" + uuid4().hex,
                }
                # Commit FIRST. This is the whole point: the side effect exists at
                # the provider even when the caller never learns about it.
                self.state.commit(record)
                if self.state.should_go_ambiguous(record["requestId"], record["clientRequestId"]):
                    sys.stderr.write(
                        "provider: committed refund then dropping the connection "
                        "(ambiguous outcome)\n"
                    )
                    sys.stderr.flush()
                    # Hard close without a response. The caller cannot distinguish
                    # this from a network failure after send, which is exactly the
                    # ambiguity being demonstrated. Dropping the socket (rather than
                    # sleeping) keeps the provider healthy for the reconciliation
                    # step that follows.
                    self.close_connection = True
                    try:
                        self.connection.close()
                    except OSError:
                        pass
                    return
                self._send(
                    200,
                    _result(
                        rpc_id,
                        {
                            "status": "succeeded",
                            "providerOperationId": record["providerOperationId"],
                        },
                    ),
                )
                return
            if name == "refund.status":
                record = self.state.lookup(str(arguments.get("requestId", "")))
                if record is None:
                    self._send(
                        200,
                        _result(
                            rpc_id,
                            {"status": "failed", "reason": "unknown requestId"},
                            structured={"status": "failed", "reason": "unknown requestId"},
                        ),
                    )
                    return
                # The reconciler reads `structuredContent`, which is the MCP
                # structured-output channel. Returning text only would be rejected
                # as provider_status.structured_content_required.
                self._send(
                    200,
                    _result(
                        rpc_id,
                        {
                            "status": record["status"],
                            "providerOperationId": record["providerOperationId"],
                        },
                        structured={
                            "status": record["status"],
                            "providerOperationId": record["providerOperationId"],
                        },
                    ),
                )
                return

        self._send(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {}})

    def _send(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fake MCP provider for the AgentGuard demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9010)
    parser.add_argument("--ledger", type=Path, default=Path("provider-ledger.jsonl"))
    parser.add_argument(
        "--ambiguous",
        action="store_true",
        help="commit then drop the connection, producing UNKNOWN",
    )
    parser.add_argument(
        "--ambiguous-for",
        action="append",
        default=[],
        help=(
            "client requestId that should go ambiguous (repeatable). Without this, "
            "the first refund submitted goes ambiguous."
        ),
    )
    args = parser.parse_args()

    Handler.state = ProviderState(args.ledger, args.ambiguous, frozenset(args.ambiguous_for))
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    sys.stderr.write(f"provider: listening on http://{args.host}:{args.port}/mcp\n")
    sys.stderr.write(f"provider: ledger {args.ledger}\n")
    sys.stderr.write(f"provider: ambiguous={'on' if args.ambiguous else 'off'}\n")
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
