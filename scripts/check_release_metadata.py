from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_HEADING = re.compile(r"^##\s+([0-9]+\.[0-9]+\.[0-9]+(?:rc[0-9]+)?)\s*$", re.MULTILINE)


def _module_version(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return node.value.value
    raise ValueError(f"{path}: literal __version__ assignment not found")


def _citation_version(path: Path) -> str:
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("version:"):
            value = raw.partition(":")[2].strip()
            if value:
                return value
    raise ValueError(f"{path}: version field not found")


def _changelog_version(path: Path) -> str:
    match = VERSION_HEADING.search(path.read_text(encoding="utf-8"))
    if match is None:
        raise ValueError(f"{path}: release heading not found")
    return match.group(1)


def collect_versions(root: Path = ROOT) -> dict[str, str]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return {
        "pyproject": str(project["version"]),
        "runtime": _module_version(root / "src" / "agentguard" / "_version.py"),
        "citation": _citation_version(root / "CITATION.cff"),
        "changelog": _changelog_version(root / "CHANGELOG.md"),
    }


def main() -> int:
    versions = collect_versions()
    unique = set(versions.values())
    if len(unique) != 1:
        details = ", ".join(f"{name}={value}" for name, value in sorted(versions.items()))
        raise SystemExit(f"release metadata version mismatch: {details}")
    version = unique.pop()
    print(f"release metadata ok: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
