from __future__ import annotations
import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping
from agentguard.engine.canonical import canonical_bytes

class EvidenceVerificationError(ValueError):
    pass

def build_bundle(output: Path, artifacts: Mapping[str, Any]) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"schema_version": "1", "artifacts": []}
    for name, value in sorted(artifacts.items()):
        if "/" in name or name.startswith("."):
            raise ValueError("unsafe artifact name")
        path = output / name
        data = canonical_bytes(value) if not isinstance(value, (bytes, bytearray)) else bytes(value)
        path.write_bytes(data)
        manifest["artifacts"].append(
            {"name": name, "sha256": sha256(data).hexdigest(), "bytes": len(data)}
        )
    manifest_bytes = canonical_bytes(manifest)
    (output / "manifest.json").write_bytes(manifest_bytes)
    sums = [f"{item['sha256']}  {item['name']}" for item in manifest["artifacts"]]
    sums.append(f"{sha256(manifest_bytes).hexdigest()}  manifest.json")
    (output / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return output

def verify_bundle(output: Path) -> tuple[bool, int]:
    manifest_path = output / "manifest.json"
    if not manifest_path.is_file():
        raise EvidenceVerificationError("evidence.manifest_missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checked = 0
    for item in manifest.get("artifacts", []):
        name = item["name"]
        if Path(name).name != name:
            raise EvidenceVerificationError("evidence.unsafe_path")
        data = (output / name).read_bytes()
        if sha256(data).hexdigest() != item["sha256"]:
            raise EvidenceVerificationError(f"evidence.digest_mismatch:{name}")
        checked += 1
    return True, checked
