from __future__ import annotations

import argparse
import json
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ignore-eof", action="store_true")
    parser.add_argument("--burst-count", type=int, default=0)
    parser.add_argument("--burst-bytes", type=int, default=128)
    args = parser.parse_args()

    for line in sys.stdin.buffer:
        message = json.loads(line.decode("utf-8"))
        request_id = message.get("id")
        method = message.get("method")

        if method == "tools/list":
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "Echo arguments back to the caller",
                                "inputSchema": {"type": "object"},
                            },
                            {
                                "name": "read_secret",
                                "description": "Read credentials from local secret storage",
                                "inputSchema": {"type": "object"},
                            },
                            {
                                "name": "burst",
                                "description": "Emit many progress notifications before returning",
                                "inputSchema": {"type": "object"},
                            },
                        ]
                    },
                }
            )
            continue

        if method == "tools/call":
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            tool_name = params.get("name")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if tool_name == "echo":
                _write({"jsonrpc": "2.0", "id": request_id, "result": {"content": [arguments]}})
            elif tool_name == "burst":
                _write_burst(request_id, args.burst_count, args.burst_bytes)
            elif tool_name == "read_secret":
                _write(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": "OPENAI_API_KEY=sk-testsecretabcdefghijklmnopqrstuvwxyz",
                                }
                            ]
                        },
                    }
                )
            else:
                _write(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32601, "message": "unknown fake tool"},
                    }
                )
            continue

        _write({"jsonrpc": "2.0", "id": request_id, "result": {}})

    if args.ignore_eof:
        while True:
            time.sleep(1)
    return 0


def _write(payload: object) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    sys.stdout.flush()


def _write_burst(request_id: object, count: int, payload_bytes: int) -> None:
    payload = "x" * max(payload_bytes, 0)
    for index in range(max(count, 0)):
        _write(
            {
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"index": index, "payload": payload},
            }
        )
    _write(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": f"burst:{count}"}]},
        }
    )


if __name__ == "__main__":
    raise SystemExit(main())
