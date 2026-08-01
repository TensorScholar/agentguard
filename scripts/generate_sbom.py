from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
PIN_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")


def _timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    moment = datetime.fromtimestamp(int(epoch), tz=UTC) if epoch else datetime.now(tz=UTC)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _validated_components() -> list[dict[str, object]]:
    pins: list[tuple[str, str]] = []
    constraints = (ROOT / "requirements" / "runtime-validated.txt").read_text(encoding="utf-8")
    for raw in constraints.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN_RE.fullmatch(line)
        if match is None:
            raise ValueError(f"runtime constraint must be exact: {line}")
        pins.append((match.group(1), match.group(2)))

    components: list[dict[str, object]] = []
    for name, version in sorted(pins, key=lambda item: item[0].lower()):
        normalized = name.lower().replace("_", "-")
        components.append(
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/{quote(normalized)}@{quote(version)}",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{quote(normalized)}@{quote(version)}",
                "scope": "required",
                "properties": [{"name": "agentguard:validation-scope", "value": "direct-runtime"}],
            }
        )
    return components


def build_sbom() -> dict[str, object]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    components = _validated_components()
    project_ref = f"pkg:pypi/agentguard@{project['version']}"
    dependency_refs = [str(component["bom-ref"]) for component in components]
    fingerprint = hashlib.sha256(
        json.dumps([project["version"], dependency_refs], separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, fingerprint)}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "component": {
                "type": "application",
                "bom-ref": project_ref,
                "name": project["name"],
                "version": project["version"],
                "purl": project_ref,
            },
            "properties": [
                {
                    "name": "agentguard:sbom-scope",
                    "value": "project plus validated direct runtime dependencies; not transitive",
                }
            ],
        },
        "components": components,
        "dependencies": [{"ref": project_ref, "dependsOn": dependency_refs}],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the deterministic AgentGuard project SBOM"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(build_sbom(), indent=2, sort_keys=True) + "\n"
    args.output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
