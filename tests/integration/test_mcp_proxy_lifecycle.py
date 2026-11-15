from __future__ import annotations

import io
import signal
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from decisionlock.adapters.protocols.mcp.stdio import (
    MCPStdioProxy,
    ProcessResult,
    _bounded_lines,
    _kill_process,
    _terminate_process,
    _write_locked,
)


class PassthroughProcessor:
    max_message_bytes = 128

    def process_client(self, raw: bytes) -> ProcessResult:
        return ProcessResult(to_server=raw)


class RejectingProcessor:
    max_message_bytes = 8

    def process_client(self, raw: bytes) -> ProcessResult:
        return ProcessResult(to_client=b'{"error":"denied"}\n')


class BrokenServer(io.BytesIO):
    def write(self, value: bytes) -> int:
        raise BrokenPipeError


class BlockingInput:
    def __init__(self, release: threading.Event) -> None:
        self.release = release

    def readline(self, size: int = -1) -> bytes:
        del size
        self.release.wait(timeout=2)
        return b""


def proxy(processor: object | None = None, command: list[str] | None = None) -> MCPStdioProxy:
    return MCPStdioProxy(
        processor or PassthroughProcessor(),  # type: ignore[arg-type]
        command or [sys.executable, "-c", "pass"],
        shutdown_timeout_seconds=1.0,
    )


def test_proxy_constructor_rejects_invalid_settings() -> None:
    with pytest.raises(ValueError, match="server command"):
        MCPStdioProxy(PassthroughProcessor(), [])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="cannot be negative"):
        MCPStdioProxy(
            PassthroughProcessor(),
            ["server"],
            shutdown_timeout_seconds=-1,  # type: ignore[arg-type]
        )


def test_bounded_lines_drains_oversized_frame() -> None:
    stream = io.BytesIO(b"0123456789abcdef\nnext\n")
    assert list(_bounded_lines(stream, 8)) == [None, b"next\n"]
    assert list(_bounded_lines(io.BytesIO(b"ok"), 8)) == [b"ok"]


def test_write_locked_flushes() -> None:
    output = io.BytesIO()
    _write_locked(output, b"payload", threading.Lock())
    assert output.getvalue() == b"payload"


def test_client_relay_handles_oversize_denial_and_broken_pipe() -> None:
    output = io.BytesIO()
    completed = threading.Event()
    value = proxy(RejectingProcessor())
    value._relay_client(
        io.BytesIO(b"0123456789\nshort\n"),
        io.BytesIO(),
        output,
        threading.Lock(),
        completed,
    )
    assert completed.is_set()
    assert b"exceeds configured limit" in output.getvalue()
    assert b"denied" in output.getvalue()

    completed.clear()
    value._relay_client(
        io.BytesIO(b"ok\n"),
        BrokenServer(),
        io.BytesIO(),
        threading.Lock(),
        completed,
    )
    assert completed.is_set()


def test_server_relay_handles_oversize_and_passthrough() -> None:
    output = io.BytesIO()
    completed = threading.Event()
    proxy(RejectingProcessor())._relay_server(
        io.BytesIO(b"0123456789\nreply\n"),
        output,
        threading.Lock(),
        completed,
    )
    assert completed.is_set()
    assert b"server message exceeds" in output.getvalue()
    assert b"reply\n" in output.getvalue()


def test_proxy_round_trip_and_hanging_server_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    incoming = io.BytesIO(b'{"jsonrpc":"2.0"}\n')
    outgoing = io.BytesIO()
    monkeypatch.setattr(
        "decisionlock.adapters.protocols.mcp.stdio.sys.stdin", SimpleNamespace(buffer=incoming)
    )
    monkeypatch.setattr(
        "decisionlock.adapters.protocols.mcp.stdio.sys.stdout", SimpleNamespace(buffer=outgoing)
    )
    echo = [
        sys.executable,
        "-c",
        (
            "import sys; data=sys.stdin.buffer.readline(); "
            "sys.stdout.buffer.write(data); sys.stdout.buffer.flush()"
        ),
    ]
    assert proxy(command=echo).run() == 0
    assert outgoing.getvalue() == b'{"jsonrpc":"2.0"}\n'

    monkeypatch.setattr(
        "decisionlock.adapters.protocols.mcp.stdio.sys.stdin",
        SimpleNamespace(buffer=io.BytesIO(b"")),
    )
    sleeper = [sys.executable, "-c", "import time; time.sleep(30)"]
    assert proxy(command=sleeper).run() == 1


def test_proxy_returns_when_server_exits_while_client_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = threading.Event()
    output = io.BytesIO()
    monkeypatch.setattr(
        "decisionlock.adapters.protocols.mcp.stdio.sys.stdin",
        SimpleNamespace(buffer=BlockingInput(release)),
    )
    monkeypatch.setattr(
        "decisionlock.adapters.protocols.mcp.stdio.sys.stdout", SimpleNamespace(buffer=output)
    )
    try:
        assert proxy(command=[sys.executable, "-c", "pass"]).run() == 0
    finally:
        release.set()


def test_process_signal_helpers_are_idempotent() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    try:
        _terminate_process(process)
        process.wait(timeout=2)
        _terminate_process(process)
        _kill_process(process)
    finally:
        if process.poll() is None:
            if hasattr(signal, "SIGKILL"):
                process.kill()
            process.wait()
