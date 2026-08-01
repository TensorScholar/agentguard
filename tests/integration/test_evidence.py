from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.evidence import EvidenceVerificationError, build_bundle, verify_bundle
from agentguard.engine.canonical import canonical_bytes


def test_evidence_bundle_round_trip(tmp_path):
    build_bundle(tmp_path / "e", {"a.json": {"x": 1}, "b.json": {"y": 2}})
    assert verify_bundle(tmp_path / "e") == (True, 2)


def test_signed_evidence_bundle_authenticates_manifest(tmp_path):
    signer = Ed25519Signer.generate("evidence-key")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}}, signer=signer)

    assert verify_bundle(out, verifier=verifier, require_signature=True) == (True, 1)


def test_signed_evidence_bundle_rejects_attestation_replacement(tmp_path):
    signer = Ed25519Signer.generate("evidence-key")
    attacker = Ed25519Signer.generate("attacker-key")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}}, signer=attacker)

    with pytest.raises(EvidenceVerificationError, match="signature_invalid"):
        verify_bundle(out, verifier=verifier, require_signature=True)


def test_evidence_requires_attestation_when_requested(tmp_path):
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}})
    with pytest.raises(EvidenceVerificationError, match="attestation_missing"):
        verify_bundle(out, require_signature=True)


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


def test_unexpected_nested_regular_file_rejected(tmp_path):
    out = build_bundle(tmp_path / "e", {"a.json": {"x": 1}})
    nested = out / "nested"
    nested.mkdir()
    (nested / "unlisted.json").write_text('{"unexpected":true}', encoding="utf-8")
    with pytest.raises(
        EvidenceVerificationError,
        match="unexpected_file:nested/unlisted.json",
    ):
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
    manifest = b'{"schema_version":"1","artifacts":[{"name":"../x","sha256":"0","bytes":0}]}'
    (out / "manifest.json").write_bytes(manifest)
    (out / "SHA256SUMS").write_text(
        f"{sha256(manifest).hexdigest()}  manifest.json\n", encoding="utf-8"
    )
    with pytest.raises(EvidenceVerificationError, match="unsafe_path"):
        verify_bundle(out)


def test_evidence_builder_rejects_symlink_output(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(EvidenceVerificationError, match="unsafe_output"):
        build_bundle(linked, {"a.json": {"x": 1}})


def test_evidence_builder_replaces_artifact_symlink_without_following(tmp_path):
    out = tmp_path / "e"
    out.mkdir()
    victim = tmp_path / "victim.json"
    victim.write_text("do-not-touch", encoding="utf-8")
    (out / "a.json").symlink_to(victim)
    with pytest.raises(EvidenceVerificationError, match="output_not_empty"):
        build_bundle(out, {"a.json": {"x": 1}})
    assert victim.read_text(encoding="utf-8") == "do-not-touch"
    assert (out / "a.json").is_symlink()


def test_builder_rejects_reserved_names_and_nonempty_output(tmp_path):
    with pytest.raises(ValueError, match="unsafe artifact name"):
        build_bundle(tmp_path / "reserved", {"manifest.json": {"x": 1}})

    output = tmp_path / "existing"
    output.mkdir()
    (output / "stale.json").write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceVerificationError, match="output_not_empty"):
        build_bundle(output, {"a.json": {"x": 1}})


def test_verifier_rejects_unknown_manifest_version(tmp_path):
    output = build_bundle(tmp_path / "e", {"a.json": {"x": 1}})
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = "999"
    manifest_bytes = canonical_bytes(manifest)
    manifest_path.write_bytes(manifest_bytes)
    lines = (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    lines = [
        f"{sha256(manifest_bytes).hexdigest()}  manifest.json"
        if line.endswith("  manifest.json")
        else line
        for line in lines
    ]
    (output / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(EvidenceVerificationError, match="manifest_invalid"):
        verify_bundle(output)


def test_evidence_set_artifacts_are_deterministic(tmp_path: Path) -> None:
    first = build_bundle(tmp_path / "first", {"values.json": {"values": {"b", "a"}}})
    second = build_bundle(tmp_path / "second", {"values.json": {"values": {"a", "b"}}})

    assert (first / "values.json").read_bytes() == (second / "values.json").read_bytes()
    assert (first / "manifest.json").read_bytes() == (second / "manifest.json").read_bytes()
