from __future__ import annotations

import subprocess
from pathlib import Path


class ChangedConfigError(RuntimeError):
    pass


CONFIG_FILENAMES = {
    "claude_desktop_config.json",
    "mcp.json",
    "mcp_config.json",
}


def changed_config_paths(
    base_ref: str,
    head_ref: str = "HEAD",
    repo: Path | None = None,
) -> list[Path]:
    repo_path = repo or Path.cwd()
    paths = changed_paths(base_ref=base_ref, head_ref=head_ref, repo=repo_path)
    return filter_config_paths(paths, repo_path)


def changed_paths(base_ref: str, head_ref: str = "HEAD", repo: Path | None = None) -> list[Path]:
    repo_path = repo or Path.cwd()
    comparison = f"{base_ref}...{head_ref}"
    process = subprocess.run(  # noqa: S603 - explicit argv, never shell=True.
        ["git", "-C", str(repo_path), "diff", "--name-only", "--diff-filter=ACMR", comparison],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise ChangedConfigError(process.stderr.strip() or "git diff failed")
    return [Path(line.strip()) for line in process.stdout.splitlines() if line.strip()]


def filter_config_paths(paths: list[Path], repo: Path | None = None) -> list[Path]:
    repo_path = repo or Path.cwd()
    output: list[Path] = []
    for path in paths:
        if not _looks_like_mcp_config(path):
            continue
        absolute = path if path.is_absolute() else repo_path / path
        if absolute.exists() and absolute.is_file():
            output.append(absolute)
    return output


def _looks_like_mcp_config(path: Path) -> bool:
    normalized = path.as_posix().lower()
    if path.name.lower() in CONFIG_FILENAMES:
        return True
    return path.suffix.lower() == ".json" and "/mcp" in normalized
