from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ._meta import package_version


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class DoctorReport:
    version: str
    checks: tuple[DoctorCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.status != "fail" for check in self.checks)


def run_doctor(workdir: Path | None = None) -> DoctorReport:
    root = workdir or Path.cwd()
    checks = [
        _python_version_check(),
        _sqlite_check(),
        _git_check(),
        _package_version_check(),
        _local_output_check(root),
    ]
    return DoctorReport(version=package_version(), checks=tuple(checks))


def render_doctor_markdown(report: DoctorReport) -> str:
    lines = [
        "# AgentGuard Doctor",
        "",
        f"Version: `{report.version}`",
        f"Status: **{'ok' if report.ok else 'failed'}**",
        "",
        "| Check | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for check in report.checks:
        lines.append(f"| {check.name} | {check.status} | {check.detail.replace('|', '\\|')} |")
    return "\n".join(lines) + "\n"


def _python_version_check() -> DoctorCheck:
    current = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):
        return DoctorCheck("python", "pass", f"Python {current}")
    return DoctorCheck("python", "fail", f"Python {current}; requires Python 3.11+")


def _sqlite_check() -> DoctorCheck:
    try:
        with sqlite3.connect(":memory:") as conn:
            conn.execute("SELECT 1").fetchone()
    except sqlite3.Error as exc:
        return DoctorCheck("sqlite", "fail", str(exc))
    return DoctorCheck("sqlite", "pass", f"sqlite3 {sqlite3.sqlite_version}")


def _git_check() -> DoctorCheck:
    git_path = shutil.which("git")
    if git_path is None:
        return DoctorCheck("git", "warn", "git not found; --changed-from scans will not work")
    return DoctorCheck("git", "pass", git_path)


def _package_version_check() -> DoctorCheck:
    value = package_version()
    if value:
        return DoctorCheck("package", "pass", f"agentguard {value}")
    return DoctorCheck("package", "fail", "package version could not be resolved")


def _local_output_check(root: Path) -> DoctorCheck:
    if not root.exists():
        return DoctorCheck("local_output", "fail", f"{root} does not exist")
    if not root.is_dir():
        return DoctorCheck("local_output", "fail", f"{root} is not a directory")
    if not _can_write_directory(root):
        return DoctorCheck("local_output", "fail", f"{root} is not writable")
    return DoctorCheck("local_output", "pass", f"{root} is writable")


def _can_write_directory(path: Path) -> bool:
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path,
            prefix=".agentguard-doctor-",
            delete=True,
        ) as handle:
            handle.write("ok\n")
    except OSError:
        return False
    return True
