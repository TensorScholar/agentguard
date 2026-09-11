from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.verify_release import (
    ReleaseVerificationError,
    main,
    verify_release,
)

SAMPLE_COMMIT = "5c57bfe6d944cd05d268150277502bb42ca2e198"
WRONG_COMMIT = "1111111111111111111111111111111111111111"
SAMPLE_VERSION = "0.2.0rc3"
SAMPLE_PROJECT = "agentguard"
SAMPLE_IDENTITY = "release-signer@agentguard.dev"
SAMPLE_NAMESPACE = "agentguard-release-v1"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ssh_keygen_available() -> bool:
    return shutil.which("ssh-keygen") is not None


@pytest.fixture
def release_bundle(tmp_path: Path):
    if not _ssh_keygen_available():
        pytest.skip("ssh-keygen not available in environment")

    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    dist_dir = artifact_root / "dist"
    dist_dir.mkdir()
    release_dir = artifact_root / "release"
    release_dir.mkdir()

    wheel_content = b"PK-wheel-content-v0.2.0rc3"
    sdist_content = b"tar-gz-sdist-content-v0.2.0rc3"
    wheel_file = dist_dir / f"agentguard-{SAMPLE_VERSION}-py3-none-any.whl"
    sdist_file = dist_dir / f"agentguard-{SAMPLE_VERSION}.tar.gz"
    wheel_file.write_bytes(wheel_content)
    sdist_file.write_bytes(sdist_content)

    cdx_content = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}).encode("utf-8")
    cdx_file = release_dir / "agentguard.cdx.json"
    cdx_file.write_bytes(cdx_content)

    manifest_data = {
        "schema_version": 1,
        "project": SAMPLE_PROJECT,
        "version": SAMPLE_VERSION,
        "commit": SAMPLE_COMMIT,
        "generated_at": "2026-09-12T00:00:00Z",
        "artifacts": [
            {
                "name": wheel_file.name,
                "sha256": _sha256_bytes(wheel_content),
                "size_bytes": len(wheel_content),
            },
            {
                "name": sdist_file.name,
                "sha256": _sha256_bytes(sdist_content),
                "size_bytes": len(sdist_content),
            },
        ],
    }
    manifest_file = release_dir / "release-manifest.json"
    manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    checksums_lines = [
        f"{_sha256_bytes(wheel_content)}  dist/{wheel_file.name}",
        f"{_sha256_bytes(sdist_content)}  dist/{sdist_file.name}",
        f"{_sha256_bytes(cdx_content)}  release/agentguard.cdx.json",
        f"{_sha256_bytes(manifest_file.read_bytes())}  release/release-manifest.json",
    ]
    checksums_file = release_dir / "SHA256SUMS"
    checksums_file.write_text("\n".join(checksums_lines) + "\n", encoding="utf-8")

    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    key_file = key_dir / "id_ed25519_test"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_file), "-N", "", "-q"],
        capture_output=True,
        check=True,
    )
    pub_bytes = key_file.with_suffix(".pub").read_text(encoding="utf-8").strip()

    allowed_signers_file = tmp_path / "allowed_signers"
    allowed_signers_file.write_text(f"{SAMPLE_IDENTITY} {pub_bytes}\n", encoding="utf-8")

    subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(key_file),
            "-n",
            SAMPLE_NAMESPACE,
            str(checksums_file),
        ],
        capture_output=True,
        check=True,
    )

    def re_sign():
        sig_path = release_dir / "SHA256SUMS.sig"
        if sig_path.exists():
            sig_path.unlink()
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(key_file),
                "-n",
                SAMPLE_NAMESPACE,
                str(checksums_file),
            ],
            capture_output=True,
            check=True,
        )

    return {
        "artifact_root": artifact_root,
        "allowed_signers": allowed_signers_file,
        "signer_identity": SAMPLE_IDENTITY,
        "namespace": SAMPLE_NAMESPACE,
        "expected_project": SAMPLE_PROJECT,
        "expected_version": SAMPLE_VERSION,
        "expected_commit": SAMPLE_COMMIT,
        "checksums_file": checksums_file,
        "signature_file": release_dir / "SHA256SUMS.sig",
        "manifest_file": manifest_file,
        "wheel_file": wheel_file,
        "sdist_file": sdist_file,
        "key_file": key_file,
        "re_sign": re_sign,
    }


def test_verify_release_pass(release_bundle):
    result = verify_release(
        artifact_root=release_bundle["artifact_root"],
        allowed_signers_path=release_bundle["allowed_signers"],
        signer_identity=release_bundle["signer_identity"],
        namespace=release_bundle["namespace"],
        expected_project=release_bundle["expected_project"],
        expected_version=release_bundle["expected_version"],
        expected_commit=release_bundle["expected_commit"],
    )
    assert result["ok"] is True
    assert result["status"] == "VERIFIED"
    assert result["commit"] == SAMPLE_COMMIT
    assert result["verified_artifacts_count"] == 4


def test_artifact_tampering_fails(release_bundle):
    release_bundle["wheel_file"].write_bytes(b"tampered-content")
    with pytest.raises(ReleaseVerificationError, match="digest mismatch"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_sha256sums_tampering_fails(release_bundle):
    current = release_bundle["checksums_file"].read_text(encoding="utf-8")
    release_bundle["checksums_file"].write_text(current + "# comment\n", encoding="utf-8")
    with pytest.raises(ReleaseVerificationError, match="SSHSIG verification failed"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_invalid_signature_fails(release_bundle):
    release_bundle["signature_file"].write_text("not a signature", encoding="utf-8")
    with pytest.raises(ReleaseVerificationError, match="SSHSIG verification failed"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_wrong_signer_identity_fails(release_bundle):
    with pytest.raises(ReleaseVerificationError, match="SSHSIG verification failed"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity="attacker@evil.com",
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_wrong_namespace_fails(release_bundle):
    with pytest.raises(ReleaseVerificationError, match="SSHSIG verification failed"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace="unauthorized-namespace",
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_untrusted_signing_key_fails(release_bundle, tmp_path):
    evil_key = tmp_path / "evil_key"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(evil_key), "-N", "", "-q"], check=True)
    release_bundle["signature_file"].unlink()
    subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(evil_key),
            "-n",
            SAMPLE_NAMESPACE,
            str(release_bundle["checksums_file"]),
        ],
        check=True,
    )
    with pytest.raises(ReleaseVerificationError, match="SSHSIG verification failed"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_wrong_expected_commit_fails(release_bundle):
    with pytest.raises(ReleaseVerificationError, match="manifest commit mismatch"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=WRONG_COMMIT,
        )


def test_abbreviated_commit_fails(release_bundle):
    with pytest.raises(ReleaseVerificationError, match="full 40-character hex commit SHA"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=SAMPLE_COMMIT[:7],
        )


def test_wrong_project_fails(release_bundle):
    with pytest.raises(ReleaseVerificationError, match="manifest project mismatch"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project="wrong-project",
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_wrong_version_fails(release_bundle):
    with pytest.raises(ReleaseVerificationError, match="manifest version mismatch"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version="1.0.0",
            expected_commit=release_bundle["expected_commit"],
        )


def test_duplicate_checksum_entry_fails(release_bundle):
    current = release_bundle["checksums_file"].read_text(encoding="utf-8")
    lines = current.strip().splitlines()
    lines.append(lines[0])
    release_bundle["checksums_file"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    release_bundle["re_sign"]()

    with pytest.raises(ReleaseVerificationError, match="duplicate checksum entry"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_duplicate_manifest_artifact_fails(release_bundle):
    manifest = json.loads(release_bundle["manifest_file"].read_text(encoding="utf-8"))
    manifest["artifacts"].append(dict(manifest["artifacts"][0]))
    release_bundle["manifest_file"].write_text(json.dumps(manifest), encoding="utf-8")
    new_manifest_hash = _sha256_bytes(release_bundle["manifest_file"].read_bytes())

    lines = []
    for line in release_bundle["checksums_file"].read_text(encoding="utf-8").splitlines():
        if "release-manifest.json" in line:
            lines.append(f"{new_manifest_hash}  release/release-manifest.json")
        else:
            lines.append(line)
    release_bundle["checksums_file"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    release_bundle["re_sign"]()

    with pytest.raises(ReleaseVerificationError, match="duplicate artifact name in manifest"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_path_traversal_fails(release_bundle):
    current = release_bundle["checksums_file"].read_text(encoding="utf-8")
    release_bundle["checksums_file"].write_text(
        current + f"{'a' * 64}  dist/../secret.txt\n",
        encoding="utf-8",
    )
    release_bundle["re_sign"]()

    with pytest.raises(ReleaseVerificationError, match="path traversal forbidden"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_absolute_path_fails(release_bundle):
    current = release_bundle["checksums_file"].read_text(encoding="utf-8")
    release_bundle["checksums_file"].write_text(
        current + f"{'a' * 64}  /etc/passwd\n",
        encoding="utf-8",
    )
    release_bundle["re_sign"]()

    with pytest.raises(ReleaseVerificationError, match="absolute path forbidden"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_symlink_escape_fails(release_bundle, tmp_path):
    secret_target = tmp_path / "secret.txt"
    secret_target.write_text("secret")
    link_path = release_bundle["artifact_root"] / "dist" / "evil_link.whl"
    try:
        link_path.symlink_to(secret_target)
    except OSError:
        pytest.skip("symlink not supported")

    current = release_bundle["checksums_file"].read_text(encoding="utf-8")
    release_bundle["checksums_file"].write_text(
        current + f"{_sha256_bytes(b'secret')}  dist/evil_link.whl\n",
        encoding="utf-8",
    )
    release_bundle["re_sign"]()

    with pytest.raises(ReleaseVerificationError, match="symlink forbidden"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_missing_artifact_fails(release_bundle):
    release_bundle["sdist_file"].unlink()
    with pytest.raises(ReleaseVerificationError, match="referenced artifact does not exist"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_extra_dist_artifact_not_in_manifest_fails(release_bundle):
    extra_file = release_bundle["artifact_root"] / "dist" / "extra.whl"
    extra_content = b"extra"
    extra_file.write_bytes(extra_content)
    current = release_bundle["checksums_file"].read_text(encoding="utf-8")
    release_bundle["checksums_file"].write_text(
        current + f"{_sha256_bytes(extra_content)}  dist/extra.whl\n",
        encoding="utf-8",
    )
    release_bundle["re_sign"]()

    with pytest.raises(ReleaseVerificationError, match="absent from release manifest"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_manifest_checksum_digest_disagreement_fails(release_bundle):
    manifest = json.loads(release_bundle["manifest_file"].read_text(encoding="utf-8"))
    manifest["artifacts"][0]["sha256"] = "0" * 64
    release_bundle["manifest_file"].write_text(json.dumps(manifest), encoding="utf-8")
    new_manifest_hash = _sha256_bytes(release_bundle["manifest_file"].read_bytes())

    lines = []
    for line in release_bundle["checksums_file"].read_text(encoding="utf-8").splitlines():
        if "release-manifest.json" in line:
            lines.append(f"{new_manifest_hash}  release/release-manifest.json")
        else:
            lines.append(line)
    release_bundle["checksums_file"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    release_bundle["re_sign"]()

    with pytest.raises(ReleaseVerificationError, match="digest disagreement"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_manifest_size_disagreement_fails(release_bundle):
    manifest = json.loads(release_bundle["manifest_file"].read_text(encoding="utf-8"))
    manifest["artifacts"][0]["size_bytes"] = 999999
    release_bundle["manifest_file"].write_text(json.dumps(manifest), encoding="utf-8")
    new_manifest_hash = _sha256_bytes(release_bundle["manifest_file"].read_bytes())

    lines = []
    for line in release_bundle["checksums_file"].read_text(encoding="utf-8").splitlines():
        if "release-manifest.json" in line:
            lines.append(f"{new_manifest_hash}  release/release-manifest.json")
        else:
            lines.append(line)
    release_bundle["checksums_file"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    release_bundle["re_sign"]()

    with pytest.raises(ReleaseVerificationError, match="size disagreement"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_malformed_checksum_line_fails(release_bundle):
    current = release_bundle["checksums_file"].read_text(encoding="utf-8")
    release_bundle["checksums_file"].write_text(
        current + "not_a_valid_checksum_line\n",
        encoding="utf-8",
    )
    release_bundle["re_sign"]()

    with pytest.raises(ReleaseVerificationError, match="malformed checksum entry"):
        verify_release(
            artifact_root=release_bundle["artifact_root"],
            allowed_signers_path=release_bundle["allowed_signers"],
            signer_identity=release_bundle["signer_identity"],
            namespace=release_bundle["namespace"],
            expected_project=release_bundle["expected_project"],
            expected_version=release_bundle["expected_version"],
            expected_commit=release_bundle["expected_commit"],
        )


def test_cli_main(release_bundle, capsys):
    ret = main(
        [
            "--artifact-root",
            str(release_bundle["artifact_root"]),
            "--allowed-signers",
            str(release_bundle["allowed_signers"]),
            "--signer-identity",
            release_bundle["signer_identity"],
            "--namespace",
            release_bundle["namespace"],
            "--expected-project",
            release_bundle["expected_project"],
            "--expected-version",
            release_bundle["expected_version"],
            "--expected-commit",
            release_bundle["expected_commit"],
        ]
    )
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["ok"] is True
    assert data["status"] == "VERIFIED"

    ret_fail = main(
        [
            "--artifact-root",
            str(release_bundle["artifact_root"]),
            "--allowed-signers",
            str(release_bundle["allowed_signers"]),
            "--signer-identity",
            release_bundle["signer_identity"],
            "--namespace",
            release_bundle["namespace"],
            "--expected-project",
            release_bundle["expected_project"],
            "--expected-version",
            release_bundle["expected_version"],
            "--expected-commit",
            WRONG_COMMIT,
        ]
    )
    assert ret_fail == 1
