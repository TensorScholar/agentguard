from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from pytest import MonkeyPatch

from agentguard.changed import ChangedConfigError, changed_paths, filter_config_paths


def test_filter_config_paths_selects_existing_mcp_configs(tmp_path: Path) -> None:
    mcp_config = tmp_path / ".cursor" / "mcp.json"
    normal_json = tmp_path / "package.json"
    nested_mcp_config = tmp_path / "config" / "mcp_servers.json"
    mcp_config.parent.mkdir()
    nested_mcp_config.parent.mkdir()
    mcp_config.write_text("{}", encoding="utf-8")
    normal_json.write_text("{}", encoding="utf-8")
    nested_mcp_config.write_text("{}", encoding="utf-8")

    paths = filter_config_paths(
        [
            Path(".cursor/mcp.json"),
            Path("package.json"),
            Path("config/mcp_servers.json"),
            Path("deleted/mcp.json"),
        ],
        tmp_path,
    )

    assert paths == [mcp_config, nested_mcp_config]


def test_changed_paths_uses_git_diff_name_only(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="mcp.json\nREADME.md\n", stderr="")

    monkeypatch.setattr("agentguard.changed.subprocess.run", fake_run)

    paths = changed_paths("origin/main", "HEAD", tmp_path)

    assert paths == [Path("mcp.json"), Path("README.md")]
    assert calls == [
        [
            "git",
            "-C",
            str(tmp_path),
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            "origin/main...HEAD",
        ]
    ]


def test_changed_paths_raises_clear_error(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=128, stdout="", stderr="bad revision")

    monkeypatch.setattr("agentguard.changed.subprocess.run", fake_run)

    try:
        changed_paths("missing", "HEAD", tmp_path)
    except ChangedConfigError as exc:
        assert "bad revision" in str(exc)
    else:
        raise AssertionError("expected ChangedConfigError")
