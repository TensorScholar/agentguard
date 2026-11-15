from __future__ import annotations

import argparse
import hashlib
import json
import os
import tomllib
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    moment = datetime.fromtimestamp(int(epoch), tz=UTC) if epoch else datetime.now(tz=UTC)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(dist: Path, commit: str) -> dict[str, object]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    artifacts = [
        {
            "name": path.name,
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(dist.iterdir(), key=lambda item: item.name)
        if path.is_file()
    ]
    if not artifacts:
        raise ValueError("release distribution directory is empty")
    return {
        "schema_version": 1,
        "project": str(project["name"]),
        "version": str(project["version"]),
        "commit": commit,
        "generated_at": _timestamp(),
        "artifacts": artifacts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic DecisionLock release manifest"
    )
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.commit.strip():
        parser.error("--commit must be non-empty")
    payload = build_manifest(args.dist, args.commit.strip())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
