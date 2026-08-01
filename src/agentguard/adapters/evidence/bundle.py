from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from agentguard.adapters.crypto import decode_signature, encode_signature
from agentguard.domain import EvidenceAttestation
from agentguard.engine.canonical import canonical_bytes
from agentguard.ports import SignatureVerifier, Signer
from agentguard.secrets import redact_value
from agentguard.security.files import (
    UnsafeFilesystemTargetError,
    read_regular_file,
    secure_atomic_write,
)


class EvidenceVerificationError(ValueError):
    pass


MAX_EVIDENCE_ARTIFACTS = 256
MAX_EVIDENCE_METADATA_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_TOTAL_BYTES = 256 * 1024 * 1024
_RESERVED_EVIDENCE_NAMES = {"manifest.json", "attestation.json", "SHA256SUMS"}


def build_bundle(
    output: Path,
    artifacts: Mapping[str, Any],
    *,
    signer: Signer | None = None,
) -> Path:
    try:
        if output.exists():
            if output.is_symlink() or not output.is_dir():
                raise EvidenceVerificationError("evidence.unsafe_output")
            if any(output.iterdir()):
                raise EvidenceVerificationError("evidence.output_not_empty")
        output.mkdir(parents=True, exist_ok=True)
    except (OSError, UnsafeFilesystemTargetError) as exc:
        raise EvidenceVerificationError("evidence.unsafe_output") from exc
    if len(artifacts) > MAX_EVIDENCE_ARTIFACTS:
        raise EvidenceVerificationError("evidence.too_many_artifacts")
    manifest: dict[str, Any] = {"schema_version": "1", "artifacts": []}
    total_bytes = 0
    for name, value in sorted(artifacts.items()):
        if (
            not name
            or "/" in name
            or "\\" in name
            or name.startswith(".")
            or name in _RESERVED_EVIDENCE_NAMES
        ):
            raise ValueError("unsafe artifact name")
        path = output / name
        if isinstance(value, (bytes, bytearray)):
            raise TypeError("binary evidence artifacts are not accepted")
        data = canonical_bytes(_sanitize(value))
        if len(data) > MAX_EVIDENCE_ARTIFACT_BYTES:
            raise EvidenceVerificationError(f"evidence.artifact_too_large:{name}")
        total_bytes += len(data)
        if total_bytes > MAX_EVIDENCE_TOTAL_BYTES:
            raise EvidenceVerificationError("evidence.bundle_too_large")
        secure_atomic_write(path, data, mode=0o600)
        manifest["artifacts"].append(
            {"name": name, "sha256": sha256(data).hexdigest(), "bytes": len(data)}
        )
    manifest_bytes = canonical_bytes(manifest)
    secure_atomic_write(output / "manifest.json", manifest_bytes, mode=0o600)
    sums = [f"{item['sha256']}  {item['name']}" for item in manifest["artifacts"]]
    sums.append(f"{sha256(manifest_bytes).hexdigest()}  manifest.json")
    if signer is not None:
        attestation = _issue_attestation(manifest_bytes, signer)
        attestation_bytes = canonical_bytes(attestation)
        secure_atomic_write(output / "attestation.json", attestation_bytes, mode=0o600)
        sums.append(f"{sha256(attestation_bytes).hexdigest()}  attestation.json")
    secure_atomic_write(
        output / "SHA256SUMS", ("\n".join(sums) + "\n").encode("utf-8"), mode=0o600
    )
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
        sanitized = [_sanitize(item) for item in value]
        return sorted(sanitized, key=canonical_bytes)
    return redact_value(value)


def verify_bundle(
    output: Path,
    *,
    verifier: SignatureVerifier | None = None,
    require_signature: bool = False,
    now: datetime | None = None,
    maximum_clock_skew_seconds: int = 300,
) -> tuple[bool, int]:
    manifest_path = output / "manifest.json"
    sums_path = output / "SHA256SUMS"
    if not manifest_path.is_file():
        raise EvidenceVerificationError("evidence.manifest_missing")
    if not sums_path.is_file():
        raise EvidenceVerificationError("evidence.checksums_missing")
    checksums: dict[str, str] = {}
    checksum_lines = read_regular_file(
        sums_path, maximum_bytes=MAX_EVIDENCE_METADATA_BYTES
    ).decode("utf-8").splitlines()
    for line in checksum_lines:
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
    manifest_bytes = read_regular_file(manifest_path, maximum_bytes=MAX_EVIDENCE_METADATA_BYTES)
    if checksums.get("manifest.json") != sha256(manifest_bytes).hexdigest():
        raise EvidenceVerificationError("evidence.manifest_digest_mismatch")
    try:
        manifest: object = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise EvidenceVerificationError("evidence.manifest_invalid") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "artifacts"}
        or manifest.get("schema_version") != "1"
        or not isinstance(manifest.get("artifacts"), list)
        or len(manifest["artifacts"]) > MAX_EVIDENCE_ARTIFACTS
    ):
        raise EvidenceVerificationError("evidence.manifest_invalid")
    attestation_path = output / "attestation.json"
    has_attestation = attestation_path.is_file() and not attestation_path.is_symlink()
    if require_signature and not has_attestation:
        raise EvidenceVerificationError("evidence.attestation_missing")
    if has_attestation:
        attestation_bytes = read_regular_file(
            attestation_path, maximum_bytes=MAX_EVIDENCE_METADATA_BYTES
        )
        if checksums.get("attestation.json") != sha256(attestation_bytes).hexdigest():
            raise EvidenceVerificationError("evidence.attestation_digest_mismatch")
        try:
            attestation = EvidenceAttestation.model_validate_json(attestation_bytes)
        except ValueError as exc:
            raise EvidenceVerificationError("evidence.attestation_invalid") from exc
        _verify_attestation(
            attestation,
            manifest_bytes,
            verifier=verifier,
            require_signature=require_signature,
            now=now,
            maximum_clock_skew_seconds=maximum_clock_skew_seconds,
        )
    declared_total_bytes = sum(
        item.get("bytes", 0)
        for item in manifest["artifacts"]
        if isinstance(item, dict) and isinstance(item.get("bytes"), int)
    )
    if declared_total_bytes > MAX_EVIDENCE_TOTAL_BYTES:
        raise EvidenceVerificationError("evidence.bundle_too_large")

    checked = 0
    artifact_names: set[str] = set()
    for item in manifest["artifacts"]:
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "bytes"}:
            raise EvidenceVerificationError("evidence.manifest_invalid")
        artifact_name = item.get("name")
        expected_digest = item.get("sha256")
        if (
            not isinstance(artifact_name, str)
            or Path(artifact_name).name != artifact_name
            or artifact_name.startswith(".")
            or artifact_name in _RESERVED_EVIDENCE_NAMES
            or artifact_name in artifact_names
        ):
            raise EvidenceVerificationError("evidence.unsafe_path")
        if not isinstance(expected_digest, str):
            raise EvidenceVerificationError("evidence.manifest_invalid")
        artifact_names.add(artifact_name)
        artifact_path = output / artifact_name
        if not artifact_path.is_file() or artifact_path.is_symlink():
            raise EvidenceVerificationError(f"evidence.missing_artifact:{artifact_name}")
        expected_bytes = item.get("bytes")
        if (
            not isinstance(expected_bytes, int)
            or expected_bytes < 0
            or expected_bytes > MAX_EVIDENCE_ARTIFACT_BYTES
        ):
            raise EvidenceVerificationError(f"evidence.size_mismatch:{artifact_name}")
        if checked + 1 > MAX_EVIDENCE_ARTIFACTS:
            raise EvidenceVerificationError("evidence.too_many_artifacts")
        data = read_regular_file(
            artifact_path, maximum_bytes=MAX_EVIDENCE_ARTIFACT_BYTES
        )
        if expected_bytes != len(data):
            raise EvidenceVerificationError(f"evidence.size_mismatch:{artifact_name}")
        actual_digest = sha256(data).hexdigest()
        if actual_digest != expected_digest or checksums.get(artifact_name) != actual_digest:
            raise EvidenceVerificationError(f"evidence.digest_mismatch:{artifact_name}")
        checked += 1
    metadata_files = {"manifest.json"}
    if has_attestation:
        metadata_files.add("attestation.json")
    if set(checksums) != artifact_names | metadata_files:
        raise EvidenceVerificationError("evidence.checksums_invalid")
    expected_files = artifact_names | metadata_files | {"SHA256SUMS"}
    regular_files: set[str] = set()
    directories: set[str] = set()
    for path in output.rglob("*"):
        relative = path.relative_to(output).as_posix()
        if path.is_symlink():
            raise EvidenceVerificationError(f"evidence.unsafe_file:{relative}")
        if path.is_dir():
            directories.add(relative)
        elif path.is_file():
            regular_files.add(relative)
    unexpected = regular_files - expected_files
    if unexpected:
        raise EvidenceVerificationError("evidence.unexpected_file:" + ",".join(sorted(unexpected)))
    missing = expected_files - regular_files
    if missing:
        raise EvidenceVerificationError("evidence.missing_artifact:" + ",".join(sorted(missing)))
    if directories:
        raise EvidenceVerificationError(
            "evidence.unexpected_directory:" + ",".join(sorted(directories))
        )
    return True, checked


def _unsigned_attestation(attestation: EvidenceAttestation) -> dict[str, Any]:
    value = attestation.model_dump(mode="python")
    value["signature"] = ""
    return value


def _issue_attestation(manifest: bytes, signer: Signer) -> EvidenceAttestation:
    attestation = EvidenceAttestation(
        manifest_sha256=sha256(manifest).hexdigest(),
        issued_at=datetime.now(UTC),
        key_id=signer.key_id,
        signature="",
    )
    signature = signer.sign(canonical_bytes(_unsigned_attestation(attestation)))
    return attestation.model_copy(update={"signature": encode_signature(signature)})


def _verify_attestation(
    attestation: EvidenceAttestation,
    manifest: bytes,
    *,
    verifier: SignatureVerifier | None,
    require_signature: bool,
    now: datetime | None,
    maximum_clock_skew_seconds: int,
) -> None:
    if attestation.manifest_sha256 != sha256(manifest).hexdigest():
        raise EvidenceVerificationError("evidence.attestation_manifest_mismatch")
    if maximum_clock_skew_seconds < 0 or maximum_clock_skew_seconds > 3600:
        raise EvidenceVerificationError("evidence.clock_skew_invalid")
    current = now or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise EvidenceVerificationError("evidence.timestamp_invalid")
    if attestation.issued_at > current + timedelta(seconds=maximum_clock_skew_seconds):
        raise EvidenceVerificationError("evidence.attestation_not_yet_valid")
    if verifier is None:
        if require_signature:
            raise EvidenceVerificationError("evidence.verifier_required")
        return
    try:
        signature = decode_signature(attestation.signature)
    except ValueError as exc:
        raise EvidenceVerificationError("evidence.attestation_signature_invalid") from exc
    if not verifier.verify(
        attestation.key_id,
        canonical_bytes(_unsigned_attestation(attestation)),
        signature,
    ):
        raise EvidenceVerificationError("evidence.attestation_signature_invalid")
