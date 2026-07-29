from __future__ import annotations
import json,pytest
from agentguard.adapters.evidence import build_bundle,verify_bundle,EvidenceVerificationError

def test_evidence_bundle_round_trip(tmp_path):
    build_bundle(tmp_path/'e',{"a.json":{"x":1},"b.json":{"y":2}})
    assert verify_bundle(tmp_path/'e')==(True,2)

def test_evidence_tamper_detected(tmp_path):
    out=build_bundle(tmp_path/'e',{"a.json":{"x":1}}); (out/'a.json').write_text('{"x":2}')
    with pytest.raises(EvidenceVerificationError,match="digest_mismatch"): verify_bundle(out)

def test_evidence_path_traversal_rejected(tmp_path):
    with pytest.raises(ValueError,match="unsafe"): build_bundle(tmp_path/'e',{"../x":{}})

def test_missing_manifest_rejected(tmp_path):
    with pytest.raises(EvidenceVerificationError, match="manifest_missing"):
        verify_bundle(tmp_path / "missing")


def test_unsafe_manifest_entry_rejected(tmp_path):
    out = tmp_path / "e"
    out.mkdir()
    (out / "manifest.json").write_text('{"artifacts":[{"name":"../x","sha256":"0"}]}')
    with pytest.raises(EvidenceVerificationError, match="unsafe_path"):
        verify_bundle(out)
