from __future__ import annotations

from hashlib import sha256

import pytest

from agentguard.adapters.evidence import EvidenceVerificationError, build_bundle, verify_bundle


def test_evidence_bundle_round_trip(tmp_path):
    build_bundle(tmp_path / "e", {"a.json": {"x": 1}, "b.json": {"y": 2}})
    assert verify_bundle(tmp_path / "e") == (True, 2)


def test_evidence_redacts_credential_handles(tmp_path):
    synthetic_handle = "opaque://" + "sensitive-capability-reference"
    out = build_bundle(tmp_path / "e", {"grant.json": {"credential_handle": synthetic_handle}})
    assert synthetic_handle not in (out / "grant.json").read_text()


def test_evidence_tamper_detected(tmp_path):
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}})
    (out / "a.json").write_text('{"x":2}')
    with pytest.raises(EvidenceVerificationError, match="digest_mismatch"):
        verify_bundle(out)


def test_unexpected_regular_file_rejected(tmp_path):
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}})
    (out / "unlisted.json").write_text('{"unexpected":true}', encoding="utf-8")
    with pytest.raises(EvidenceVerificationError, match="unexpected_file:unlisted.json"):
        verify_bundle(out)


def test_missing_listed_artifact_rejected(tmp_path):
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}})
    (out / "a.json").unlink()
    with pytest.raises(EvidenceVerificationError, match="missing_artifact:a.json"):
        verify_bundle(out)


def test_manifest_size_tamper_rejected(tmp_path):
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}})
    manifest = (out / "manifest.json").read_text(encoding="utf-8")
    tampered = manifest.replace('"bytes":7', '"bytes":8')
    (out / "manifest.json").write_text(tampered, encoding="utf-8")
    (out / "SHA256SUMS").write_text(
        "\n".join(
            line
            if not line.endswith("  manifest.json")
            else f"{sha256(tampered.encode()).hexdigest()}  manifest.json"
            for line in (out / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(EvidenceVerificationError, match="size_mismatch:a.json"):
        verify_bundle(out)


def test_manifest_and_checksum_tamper_detected(tmp_path):
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}})
    (out / "manifest.json").write_text('{"artifacts":[],"schema_version":"1"}', encoding="utf-8")
    with pytest.raises(EvidenceVerificationError, match="manifest_digest_mismatch"):
        verify_bundle(out)


def test_missing_checksum_file_rejected(tmp_path):
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}})
    (out / "SHA256SUMS").unlink()
    with pytest.raises(EvidenceVerificationError, match="checksums_missing"):
        verify_bundle(out)


def test_evidence_path_traversal_rejected(tmp_path):
    with pytest.raises(ValueError, match="unsafe"):
        build_bundle(tmp_path / "e", {"../x": {}})


def test_missing_manifest_rejected(tmp_path):
    with pytest.raises(EvidenceVerificationError, match="manifest_missing"):
        verify_bundle(tmp_path / "missing")


def test_unsafe_manifest_entry_rejected(tmp_path):
    out = tmp_path / "e"
    out.mkdir()
    manifest = b'{"artifacts":[{"name":"../x","sha256":"0"}]}'
    (out / "manifest.json").write_bytes(manifest)
    (out / "SHA256SUMS").write_text(
        f"{sha256(manifest).hexdigest()}  manifest.json\n", encoding="utf-8"
    )
    with pytest.raises(EvidenceVerificationError, match="unsafe_path"):
        verify_bundle(out)
