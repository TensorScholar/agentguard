from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
COMMIT_HEX_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class ReleaseVerificationError(Exception):
    """Raised when release verification fails."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sshsig(
    *,
    checksums_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
    signer_identity: str,
    namespace: str,
) -> str:
    if not checksums_path.is_file():
        raise ReleaseVerificationError(f"checksum file not found: {checksums_path}")
    if not signature_path.is_file():
        raise ReleaseVerificationError(f"signature file not found: {signature_path}")
    if not allowed_signers_path.is_file():
        raise ReleaseVerificationError(f"allowed_signers file not found: {allowed_signers_path}")
    if not signer_identity.strip():
        raise ReleaseVerificationError("signer identity must not be empty")
    if not namespace.strip():
        raise ReleaseVerificationError("namespace must not be empty")

    checksum_bytes = checksums_path.read_bytes()
    cmd = [
        "ssh-keygen",
        "-Y",
        "verify",
        "-f",
        str(allowed_signers_path.resolve()),
        "-I",
        signer_identity.strip(),
        "-n",
        namespace.strip(),
        "-s",
        str(signature_path.resolve()),
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=checksum_bytes,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ReleaseVerificationError(f"ssh-keygen command not found: {exc}") from exc

    if proc.returncode != 0:
        err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
        out_msg = proc.stdout.decode("utf-8", errors="replace").strip()
        details = err_msg or out_msg or f"exit code {proc.returncode}"
        raise ReleaseVerificationError(f"SSHSIG verification failed: {details}")

    return (
        proc.stdout.decode("utf-8", errors="replace").strip()
        or proc.stderr.decode("utf-8", errors="replace").strip()
    )


def parse_checksums(
    checksums_path: Path,
    artifact_root: Path,
    signature_path: Path,
    allowed_signers_path: Path,
) -> dict[str, str]:
    if not checksums_path.is_file():
        raise ReleaseVerificationError(f"checksum file not found: {checksums_path}")

    root_resolved = artifact_root.resolve()
    sig_resolved = signature_path.resolve()
    signers_resolved = allowed_signers_path.resolve()

    checksum_map: dict[str, str] = {}
    raw_lines = checksums_path.read_text(encoding="utf-8").splitlines()
    if not raw_lines:
        raise ReleaseVerificationError("checksum file is empty")

    for line_num, line in enumerate(raw_lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ReleaseVerificationError(
                f"malformed checksum entry at line {line_num}: expected '<hash>  <path>'"
            )
        file_hash, raw_rel_path = parts[0].strip(), parts[1].strip()
        if raw_rel_path.startswith("*"):
            raw_rel_path = raw_rel_path[1:].strip()

        if not SHA256_HEX_RE.fullmatch(file_hash):
            raise ReleaseVerificationError(
                f"invalid SHA-256 digest at line {line_num}: {file_hash!r}"
            )
        file_hash = file_hash.lower()

        if not raw_rel_path:
            raise ReleaseVerificationError(f"empty path at line {line_num}")
        if raw_rel_path.startswith(("/", "\\")):
            raise ReleaseVerificationError(
                f"absolute path forbidden at line {line_num}: {raw_rel_path!r}"
            )
        if "\\" in raw_rel_path:
            raise ReleaseVerificationError(
                f"unexpected backslash in path at line {line_num}: {raw_rel_path!r}"
            )

        path_parts = Path(raw_rel_path).parts
        if any(part in ("..", ".", "") for part in path_parts):
            raise ReleaseVerificationError(
                f"path traversal forbidden at line {line_num}: {raw_rel_path!r}"
            )

        normalized_rel = Path(raw_rel_path).as_posix()
        if normalized_rel in checksum_map:
            raise ReleaseVerificationError(
                f"duplicate checksum entry at line {line_num}: {normalized_rel}"
            )

        target_path = artifact_root / raw_rel_path
        if target_path.is_symlink():
            raise ReleaseVerificationError(f"symlink forbidden at line {line_num}: {raw_rel_path}")

        try:
            target_resolved = target_path.resolve()
        except OSError as exc:
            raise ReleaseVerificationError(
                f"cannot resolve path at line {line_num}: {exc}"
            ) from exc

        try:
            target_resolved.relative_to(root_resolved)
        except ValueError:
            raise ReleaseVerificationError(
                f"path escapes artifact root at line {line_num}: {raw_rel_path}"
            )

        if target_resolved == sig_resolved:
            raise ReleaseVerificationError(
                f"checksums must not reference signature file at line {line_num}: {raw_rel_path}"
            )
        if target_resolved == signers_resolved:
            raise ReleaseVerificationError(
                f"checksums must not reference allowed_signers at line {line_num}: {raw_rel_path}"
            )

        if not target_path.is_file():
            raise ReleaseVerificationError(f"referenced artifact does not exist: {raw_rel_path}")

        actual_hash = _sha256_file(target_path)
        if actual_hash != file_hash:
            raise ReleaseVerificationError(
                f"digest mismatch for {raw_rel_path}: recorded {file_hash}, computed {actual_hash}"
            )

        checksum_map[normalized_rel] = file_hash

    return checksum_map


def verify_manifest(
    *,
    manifest_path: Path,
    artifact_root: Path,
    checksum_map: dict[str, str],
    expected_project: str,
    expected_version: str,
    expected_commit: str,
) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise ReleaseVerificationError(f"release manifest not found: {manifest_path}")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ReleaseVerificationError(f"failed to parse release manifest JSON: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ReleaseVerificationError("release manifest root must be a JSON object")

    if manifest.get("schema_version") != 1:
        raise ReleaseVerificationError(
            f"unsupported manifest schema_version: {manifest.get('schema_version')!r}, expected 1"
        )

    project = manifest.get("project")
    if project != expected_project:
        raise ReleaseVerificationError(
            f"manifest project mismatch: got {project!r}, expected {expected_project!r}"
        )

    version = manifest.get("version")
    if version != expected_version:
        raise ReleaseVerificationError(
            f"manifest version mismatch: got {version!r}, expected {expected_version!r}"
        )

    norm_expected_commit = expected_commit.strip().lower()
    if not COMMIT_HEX_RE.fullmatch(norm_expected_commit):
        raise ReleaseVerificationError(
            f"expected-commit must be a full 40-character hex commit SHA: {expected_commit!r}"
        )

    manifest_commit = str(manifest.get("commit", "")).strip().lower()
    if not COMMIT_HEX_RE.fullmatch(manifest_commit):
        raise ReleaseVerificationError(
            f"manifest commit must be a full 40-character hex commit SHA: {manifest_commit!r}"
        )
    if manifest_commit != norm_expected_commit:
        raise ReleaseVerificationError(
            f"manifest commit mismatch: manifest has {manifest_commit}, expected {norm_expected_commit}"
        )

    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise ReleaseVerificationError("manifest artifacts must be a non-empty list")

    manifest_artifact_names: set[str] = set()
    manifest_entries_map: dict[str, dict[str, Any]] = {}

    for entry in raw_artifacts:
        if not isinstance(entry, dict):
            raise ReleaseVerificationError("manifest artifact entry must be a JSON object")
        name = entry.get("name")
        sha256 = entry.get("sha256")
        size_bytes = entry.get("size_bytes")

        if not isinstance(name, str) or not name.strip() or Path(name).name != name:
            raise ReleaseVerificationError(f"invalid manifest artifact name: {name!r}")
        if name in manifest_artifact_names:
            raise ReleaseVerificationError(f"duplicate artifact name in manifest: {name!r}")
        manifest_artifact_names.add(name)

        if not isinstance(sha256, str) or not SHA256_HEX_RE.fullmatch(sha256):
            raise ReleaseVerificationError(
                f"invalid manifest artifact sha256 for {name}: {sha256!r}"
            )
        sha256 = sha256.lower()

        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
            raise ReleaseVerificationError(
                f"invalid manifest artifact size_bytes for {name}: {size_bytes!r}"
            )

        manifest_entries_map[name] = {"name": name, "sha256": sha256, "size_bytes": size_bytes}

    manifest_rel_path = manifest_path.relative_to(artifact_root).as_posix()
    if manifest_rel_path not in checksum_map:
        raise ReleaseVerificationError(
            f"manifest file {manifest_rel_path!r} is missing from SHA256SUMS"
        )

    expected_cdx_rel = Path("release/agentguard.cdx.json").as_posix()
    if expected_cdx_rel not in checksum_map:
        raise ReleaseVerificationError(f"SBOM file {expected_cdx_rel!r} is missing from SHA256SUMS")

    dist_dir = artifact_root / "dist"
    if not dist_dir.is_dir():
        raise ReleaseVerificationError(f"distribution directory does not exist: {dist_dir}")

    actual_dist_names: set[str] = set()
    for item in dist_dir.iterdir():
        if item.is_symlink():
            raise ReleaseVerificationError(f"symlink forbidden in dist directory: {item.name}")
        if item.is_dir():
            raise ReleaseVerificationError(f"unexpected directory in dist directory: {item.name}")
        if not item.is_file():
            raise ReleaseVerificationError(f"non-regular file in dist directory: {item.name}")
        actual_dist_names.add(item.name)

    manifest_dist_names: set[str] = set(manifest_entries_map.keys())
    checksum_dist_names: set[str] = {Path(p).name for p in checksum_map if p.startswith("dist/")}

    # Strict semantic equivalence: ACTUAL_DIST_FILES == MANIFEST_DIST_FILES == SHA256SUMS_DIST_FILES
    if actual_dist_names != manifest_dist_names:
        extra_on_disk = sorted(actual_dist_names - manifest_dist_names)
        if extra_on_disk:
            raise ReleaseVerificationError(
                f"unmanifested distribution file in dist directory: {extra_on_disk[0]}"
            )
        missing_on_disk = sorted(manifest_dist_names - actual_dist_names)
        if missing_on_disk:
            raise ReleaseVerificationError(
                f"manifest distribution file missing from dist directory: {missing_on_disk[0]}"
            )

    if checksum_dist_names != manifest_dist_names:
        extra_in_checksums = sorted(checksum_dist_names - manifest_dist_names)
        if extra_in_checksums:
            raise ReleaseVerificationError(
                f"distribution file in SHA256SUMS absent from release manifest: {extra_in_checksums[0]}"
            )
        missing_in_checksums = sorted(manifest_dist_names - checksum_dist_names)
        if missing_in_checksums:
            raise ReleaseVerificationError(
                f"manifest artifact {missing_in_checksums[0]!r} (dist/{missing_in_checksums[0]}) is missing from SHA256SUMS"
            )

    for name, entry in manifest_entries_map.items():
        dist_rel = f"dist/{name}"
        if checksum_map[dist_rel] != entry["sha256"]:
            raise ReleaseVerificationError(
                f"digest disagreement for {name}: manifest has {entry['sha256']}, SHA256SUMS has {checksum_map[dist_rel]}"
            )
        dist_file = artifact_root / dist_rel
        if dist_file.stat().st_size != entry["size_bytes"]:
            raise ReleaseVerificationError(
                f"size disagreement for {name}: manifest declares {entry['size_bytes']} bytes, actual file has {dist_file.stat().st_size} bytes"
            )

    return manifest


def verify_release(
    *,
    artifact_root: Path,
    allowed_signers_path: Path,
    signer_identity: str,
    namespace: str = "agentguard-release-v1",
    expected_project: str = "agentguard",
    expected_version: str,
    expected_commit: str,
) -> dict[str, Any]:
    artifact_root = artifact_root.resolve()
    if not artifact_root.is_dir():
        raise ReleaseVerificationError(f"artifact root directory does not exist: {artifact_root}")

    allowed_signers_path = allowed_signers_path.resolve()
    if not allowed_signers_path.is_file():
        raise ReleaseVerificationError(
            f"allowed_signers file does not exist: {allowed_signers_path}"
        )

    if allowed_signers_path == artifact_root:
        raise ReleaseVerificationError(
            f"trust anchor must be external to release bundle: allowed_signers path is the artifact root: {allowed_signers_path}"
        )
    try:
        allowed_signers_path.relative_to(artifact_root)
        raise ReleaseVerificationError(
            f"trust anchor must be external to release bundle: allowed_signers path {allowed_signers_path} is located inside artifact root {artifact_root}"
        )
    except ValueError:
        pass  # Expected: allowed_signers is outside artifact_root

    checksums_path = artifact_root / "release" / "SHA256SUMS"
    signature_path = artifact_root / "release" / "SHA256SUMS.sig"
    manifest_path = artifact_root / "release" / "release-manifest.json"

    ssh_msg = verify_sshsig(
        checksums_path=checksums_path,
        signature_path=signature_path,
        allowed_signers_path=allowed_signers_path,
        signer_identity=signer_identity,
        namespace=namespace,
    )

    checksum_map = parse_checksums(
        checksums_path=checksums_path,
        artifact_root=artifact_root,
        signature_path=signature_path,
        allowed_signers_path=allowed_signers_path,
    )

    manifest = verify_manifest(
        manifest_path=manifest_path,
        artifact_root=artifact_root,
        checksum_map=checksum_map,
        expected_project=expected_project,
        expected_version=expected_version,
        expected_commit=expected_commit,
    )

    return {
        "ok": True,
        "status": "VERIFIED",
        "project": expected_project,
        "version": expected_version,
        "commit": manifest["commit"],
        "signer_identity": signer_identity,
        "namespace": namespace,
        "signature_verification": ssh_msg,
        "verified_artifacts_count": len(checksum_map),
        "distribution_artifacts": [a["name"] for a in manifest["artifacts"]],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify AgentGuard release authenticity and checksums via OpenSSH SSHSIG"
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        required=True,
        help="Root directory containing dist/ and release/ directories",
    )
    parser.add_argument(
        "--allowed-signers",
        type=Path,
        required=True,
        help="Path to trusted OpenSSH allowed_signers policy file",
    )
    parser.add_argument(
        "--signer-identity",
        required=True,
        help="Expected signer identity / principal declared in allowed_signers",
    )
    parser.add_argument(
        "--namespace",
        default="agentguard-release-v1",
        help="SSHSIG namespace (default: agentguard-release-v1)",
    )
    parser.add_argument(
        "--expected-project",
        default="agentguard",
        help="Expected project name in manifest (default: agentguard)",
    )
    parser.add_argument(
        "--expected-version",
        required=True,
        help="Expected release version (e.g. 0.2.0rc3)",
    )
    parser.add_argument(
        "--expected-commit",
        required=True,
        help="Expected exact 40-hex Git commit SHA",
    )

    args = parser.parse_args(argv)

    try:
        result = verify_release(
            artifact_root=args.artifact_root,
            allowed_signers_path=args.allowed_signers,
            signer_identity=args.signer_identity,
            namespace=args.namespace,
            expected_project=args.expected_project,
            expected_version=args.expected_version,
            expected_commit=args.expected_commit,
        )
        print(json.dumps(result, indent=2))
        return 0
    except ReleaseVerificationError as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"unexpected verification error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
