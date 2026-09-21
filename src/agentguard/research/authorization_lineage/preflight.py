from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

import agentguard

from .models import PROTOCOL_ID

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_DEFAULT_IDENTITY = Path("research/authorization_lineage/CONFIRMATORY_RUNTIME_IDENTITY.json")


class ConfirmatoryPreflightError(RuntimeError):
    pass


def _git(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _command(*args: str) -> str:
    completed = subprocess.run(list(args), check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def _object_dict(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ConfirmatoryPreflightError(f"identity field {name} must be an object")
    return cast(dict[str, object], value)


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfirmatoryPreflightError(f"identity field {name} must be a non-empty string")
    return value


def _load_identity(path: Path) -> dict[str, object]:
    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfirmatoryPreflightError("confirmatory runtime identity is unreadable") from exc
    if not isinstance(decoded, dict):
        raise ConfirmatoryPreflightError("confirmatory runtime identity must be a JSON object")
    return cast(dict[str, object], decoded)


def _lock_versions(path: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfirmatoryPreflightError("confirmatory runtime lock is unreadable") from exc
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise ConfirmatoryPreflightError(f"runtime lock entry is not exact: {line}")
        name, version = line.split("==", 1)
        if not name or not version or name in versions:
            raise ConfirmatoryPreflightError(f"runtime lock entry is invalid: {line}")
        versions[name] = version
    if not versions:
        raise ConfirmatoryPreflightError("confirmatory runtime lock is empty")
    return versions


def _agentguard_source() -> Path:
    source = getattr(agentguard, "__file__", None)
    if not isinstance(source, str) or not source:
        raise ConfirmatoryPreflightError("AgentGuard package source provenance is unavailable")
    return Path(source).resolve()


def _runtime_sys_path() -> tuple[Path, ...]:
    resolved: list[Path] = []
    for entry in sys.path:
        if not entry:
            continue
        resolved.append(Path(entry).resolve())
    return tuple(resolved)


def _verify_import_provenance(repo_root: Path) -> dict[str, object]:
    pythonpath = os.environ.get("PYTHONPATH", "")
    if pythonpath.strip():
        raise ConfirmatoryPreflightError("unexpected PYTHONPATH import-path injection")

    expected_source = (repo_root / "src" / "agentguard" / "__init__.py").resolve()
    actual_source = _agentguard_source()
    if actual_source != expected_source:
        raise ConfirmatoryPreflightError(
            f"AgentGuard package provenance drift: expected={expected_source}, actual={actual_source}"
        )

    repo_root_resolved = repo_root.resolve()
    source_root = (repo_root / "src").resolve()
    prefix = Path(sys.prefix).resolve()
    base_prefix = Path(sys.base_prefix).resolve()
    observed_paths = _runtime_sys_path()
    unexpected: list[str] = []
    for path in observed_paths:
        if path in {repo_root_resolved, source_root}:
            continue
        if path.is_relative_to(prefix) or path.is_relative_to(base_prefix):
            continue
        unexpected.append(str(path))
    if unexpected:
        raise ConfirmatoryPreflightError(
            "unexpected import-path provenance: " + ", ".join(sorted(unexpected))
        )

    return {
        "agentguard_source": str(actual_source),
        "repo_source_root": str(source_root),
        "pythonpath": "",
        "sys_path": [str(path) for path in observed_paths],
    }


def preflight_digest(report: dict[str, object]) -> str:
    canonical = json.dumps(report, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def run_confirmatory_preflight(
    *,
    repo_root: Path,
    expected_git_commit: str,
    identity_path: Path | None = None,
) -> dict[str, object]:
    """Fail closed on drift from the frozen confirmatory runtime + clarification identity."""

    repo_root = repo_root.resolve()
    if _SHA40.fullmatch(expected_git_commit) is None:
        raise ConfirmatoryPreflightError("expected Git commit must be exact lowercase 40-hex")

    identity_file = identity_path or repo_root / _DEFAULT_IDENTITY
    identity = _load_identity(identity_file)
    if identity.get("protocol") != PROTOCOL_ID:
        raise ConfirmatoryPreflightError("confirmatory runtime identity protocol mismatch")

    head = _git(repo_root, "rev-parse", "HEAD")
    if head != expected_git_commit:
        raise ConfirmatoryPreflightError(
            f"Git commit drift: expected={expected_git_commit}, actual={head}"
        )
    tree = _git(repo_root, "rev-parse", "HEAD^{tree}")
    working_tree = _git(repo_root, "status", "--porcelain", "--untracked-files=all")
    if working_tree:
        raise ConfirmatoryPreflightError(
            "repository working tree contains tracked or untracked drift"
        )

    import_provenance = _verify_import_provenance(repo_root)

    runtime = _object_dict(identity.get("runtime"), "runtime")
    observed_runtime = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "macos_version": _command("sw_vers", "-productVersion"),
        "macos_build": _command("sw_vers", "-buildVersion"),
        "pip_version": importlib.metadata.version("pip"),
        "git_version": _git(repo_root, "--version").removeprefix("git version "),
    }
    for name, actual in observed_runtime.items():
        expected = _string(runtime.get(name), f"runtime.{name}")
        if actual != expected:
            raise ConfirmatoryPreflightError(
                f"runtime drift for {name}: expected={expected}, actual={actual}"
            )

    lock = _object_dict(identity.get("lock"), "lock")
    lock_relative = _string(lock.get("path"), "lock.path")
    lock_path = repo_root / lock_relative
    expected_lock_sha = _string(lock.get("sha256"), "lock.sha256")
    actual_lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    if actual_lock_sha != expected_lock_sha:
        raise ConfirmatoryPreflightError("confirmatory runtime lock SHA-256 mismatch")

    expected_versions = _lock_versions(lock_path)
    installed_versions: dict[str, str] = {}
    for distribution, expected_version in sorted(expected_versions.items()):
        try:
            actual_version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise ConfirmatoryPreflightError(
                f"required runtime distribution is not installed: {distribution}"
            ) from exc
        if actual_version != expected_version:
            raise ConfirmatoryPreflightError(
                f"runtime dependency drift for {distribution}: "
                f"expected={expected_version}, actual={actual_version}"
            )
        installed_versions[distribution] = actual_version

    git_objects = _object_dict(identity.get("git_objects"), "git_objects")
    verified_objects: dict[str, str] = {}
    for label, raw_spec in sorted(git_objects.items()):
        spec = _object_dict(raw_spec, f"git_objects.{label}")
        kind = _string(spec.get("kind"), f"git_objects.{label}.kind")
        path = _string(spec.get("path"), f"git_objects.{label}.path")
        expected_sha = _string(spec.get("sha"), f"git_objects.{label}.sha")
        if kind == "tree":
            actual_sha = _git(repo_root, "rev-parse", f"HEAD:{path}")
        elif kind == "blob":
            actual_sha = _git(repo_root, "hash-object", path)
        else:
            raise ConfirmatoryPreflightError(f"unsupported Git object kind: {kind}")
        if actual_sha != expected_sha:
            raise ConfirmatoryPreflightError(
                f"Git object drift for {label}: expected={expected_sha}, actual={actual_sha}"
            )
        verified_objects[label] = actual_sha

    clarification = _object_dict(identity.get("clarification"), "clarification")
    clarification_path = repo_root / _string(clarification.get("path"), "clarification.path")
    expected_clarification_sha = _string(clarification.get("sha256"), "clarification.sha256")
    actual_clarification_sha = hashlib.sha256(clarification_path.read_bytes()).hexdigest()
    if actual_clarification_sha != expected_clarification_sha:
        raise ConfirmatoryPreflightError("protocol clarification SHA-256 mismatch")
    clarification_blob = verified_objects.get("protocol_clarification")
    if clarification_blob is None:
        raise ConfirmatoryPreflightError(
            "protocol clarification must be bound as git_objects.protocol_clarification"
        )

    identity_sha = hashlib.sha256(identity_file.read_bytes()).hexdigest()
    return {
        "protocol": PROTOCOL_ID,
        "status": "PASS",
        "expected_git_commit": expected_git_commit,
        "actual_git_commit": head,
        "actual_git_tree": tree,
        "runtime_identity_sha256": identity_sha,
        "runtime": observed_runtime,
        "runtime_lock_sha256": actual_lock_sha,
        "runtime_dependencies": installed_versions,
        "git_objects": verified_objects,
        "clarification_sha256": actual_clarification_sha,
        "clarification_git_blob": clarification_blob,
        "import_provenance": import_provenance,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="AG-LINEAGE-v1.0 confirmatory runtime preflight")
    parser.add_argument("--expected-git-commit", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = run_confirmatory_preflight(
            repo_root=args.repo_root,
            expected_git_commit=args.expected_git_commit,
            identity_path=args.identity,
        )
    except (ConfirmatoryPreflightError, OSError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
