from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agentguard.engine.canonical import canonical_bytes
from agentguard.secrets import redact_value


class EvidenceVerificationError(ValueError):
    pass


def build_bundle(output: Path, artifacts: Mapping[str, Any]) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"schema_version": "1", "artifacts": []}
    for name, value in sorted(artifacts.items()):
        if not name or "/" in name or "\\" in name or name.startswith("."):
            raise ValueError("unsafe artifact name")
        path = output / name
        if isinstance(value, (bytes, bytearray)):
            raise TypeError("binary evidence artifacts are not accepted")
        data = canonical_bytes(_sanitize(value))
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


def _sanitize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _sanitize(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            normalized = name.lower().replace("-", "_")
            if normalized in {
                "credential_handle",
                "password",
                "private_key",
                "secret",
                "token",
            }:
                sanitized[name] = "[REDACTED]"
            else:
                sanitized[name] = _sanitize(item)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return {_sanitize(item) for item in value}
    return redact_value(value)


def verify_bundle(output: Path) -> tuple[bool, int]:
    manifest_path = output / "manifest.json"
    sums_path = output / "SHA256SUMS"
    if not manifest_path.is_file():
        raise EvidenceVerificationError("evidence.manifest_missing")
    if not sums_path.is_file():
        raise EvidenceVerificationError("evidence.checksums_missing")
    checksums: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        try:
            checksum, name = line.split("  ", 1)
        except ValueError as exc:
            raise EvidenceVerificationError("evidence.checksums_invalid") from exc
        if (
            len(checksum) != 64
            or any(character not in "0123456789abcdef" for character in checksum)
            or Path(name).name != name
            or name in checksums
        ):
            raise EvidenceVerificationError("evidence.checksums_invalid")
        checksums[name] = checksum
    manifest_bytes = manifest_path.read_bytes()
    if checksums.get("manifest.json") != sha256(manifest_bytes).hexdigest():
        raise EvidenceVerificationError("evidence.manifest_digest_mismatch")
    try:
        manifest: object = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise EvidenceVerificationError("evidence.manifest_invalid") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("artifacts"), list):
        raise EvidenceVerificationError("evidence.manifest_invalid")
    checked = 0
    artifact_names: set[str] = set()
    for item in manifest["artifacts"]:
        if not isinstance(item, dict):
            raise EvidenceVerificationError("evidence.manifest_invalid")
        artifact_name = item.get("name")
        expected_digest = item.get("sha256")
        if (
            not isinstance(artifact_name, str)
            or Path(artifact_name).name != artifact_name
            or artifact_name.startswith(".")
            or artifact_name in artifact_names
        ):
            raise EvidenceVerificationError("evidence.unsafe_path")
        if not isinstance(expected_digest, str):
            raise EvidenceVerificationError("evidence.manifest_invalid")
        artifact_names.add(artifact_name)
        data = (output / artifact_name).read_bytes()
        actual_digest = sha256(data).hexdigest()
        if actual_digest != expected_digest or checksums.get(artifact_name) != actual_digest:
            raise EvidenceVerificationError(f"evidence.digest_mismatch:{artifact_name}")
        checked += 1
    if set(checksums) != artifact_names | {"manifest.json"}:
        raise EvidenceVerificationError("evidence.checksums_invalid")
    return True, checked
