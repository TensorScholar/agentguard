from decisionlock.adapters.crypto import Ed25519Verifier
from decisionlock.adapters.evidence import verify_bundle
from decisionlock.demo import create_demo


def test_demo_builds_all_artifacts(tmp_path):
    out = tmp_path / "demo"
    create_demo(out)
    assert (out / "receipt.json").is_file() and (out / "grant.json").is_file()
    assert verify_bundle(
        out / "evidence",
        verifier=Ed25519Verifier.from_public_file(out / "public.pem"),
        require_signature=True,
    )[0]
