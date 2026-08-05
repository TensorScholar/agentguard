from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from pytest import CaptureFixture, MonkeyPatch

from agentguard import cli


def test_public_mcp_proxy_refuses_before_legacy_or_subprocess_use(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("default_action: allow\n", encoding="utf-8")

    monkeypatch.setattr(
        cli._v1_cli,
        "main",
        lambda _args: pytest.fail("primary mcp-proxy must not enter the legacy CLI"),
    )
    monkeypatch.setattr(
        cli._v1_cli,
        "MCPStdioProxy",
        lambda *_args, **_kwargs: pytest.fail("primary mcp-proxy must not construct MCPStdioProxy"),
    )
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("primary mcp-proxy must not spawn a process"),
    )

    exit_code = cli.entrypoint(
        [
            "mcp-proxy",
            "--policy",
            str(policy),
            "--",
            "valid-server-command",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "MCP execution refused" in captured.err
    assert "secure v2 MCP execution path is not yet integrated" in captured.err
    assert "fails closed without starting the server" in captured.err
    assert "agentguard legacy-mcp-proxy" in captured.err
    assert "legacy v1 compatibility" in captured.err


def test_public_main_api_also_refuses_mcp_proxy(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli._v1_cli,
        "main",
        lambda _args: pytest.fail("public main API must not enter legacy mcp-proxy"),
    )

    assert cli.main(["mcp-proxy", "--", "valid-server-command"]) == 2
    assert "MCP execution refused" in capsys.readouterr().err


def test_explicit_legacy_mcp_proxy_routes_to_v1(
    monkeypatch: MonkeyPatch,
) -> None:
    observed: list[list[str] | None] = []

    def fake_v1_main(args: list[str] | None) -> int:
        observed.append(args)
        return 17

    monkeypatch.setattr(cli._v1_cli, "main", fake_v1_main)

    exit_code = cli.entrypoint(
        ["legacy-mcp-proxy", "--policy", "legacy-policy.yaml", "--", "server"]
    )

    assert exit_code == 17
    assert observed == [["legacy-mcp-proxy", "--policy", "legacy-policy.yaml", "--", "server"]]


def test_help_distinguishes_primary_refusal_and_legacy_compatibility(
    capsys: CaptureFixture[str],
) -> None:
    assert cli.entrypoint(["--help"]) == 0
    captured = capsys.readouterr()

    assert "mcp-proxy" in captured.out
    assert "refuses execution" in captured.out
    assert "legacy-mcp-proxy" in captured.out
    assert "legacy v1 compatibility" in captured.out


def test_primary_mcp_proxy_help_describes_fail_closed_state(
    capsys: CaptureFixture[str],
) -> None:
    assert cli.entrypoint(["mcp-proxy", "--help"]) == 0
    captured = capsys.readouterr()

    assert "Refuse MCP execution" in captured.out
    assert captured.err == ""


def test_legacy_mcp_proxy_help_is_explicitly_compatibility_only(
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.entrypoint(["legacy-mcp-proxy", "--help"])
    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "usage: agentguard legacy-mcp-proxy" in captured.out
    assert "Legacy v1 compatibility only" in captured.out
    assert "does not provide the secure v2 execution boundary" in " ".join(captured.out.split())
