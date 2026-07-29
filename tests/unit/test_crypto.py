from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier, encode_signature, decode_signature


def test_key_file_round_trip(tmp_path):
    signer = Ed25519Signer.generate("k1")
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    signer.save_private(private)
    signer.save_public(public)
    loaded = Ed25519Signer.load_private(private, "k1")
    verifier = Ed25519Verifier.from_public_file(public, "k1")
    payload = b"payload"
    assert verifier.verify("k1", payload, loaded.sign(payload))
    assert oct(private.stat().st_mode & 0o777) == "0o600"


def test_unknown_key_is_false(signer):
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    assert verifier.verify("unknown", b"x", signer.sign(b"x")) is False


def test_bad_signature_is_false(signer):
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    assert verifier.verify(signer.key_id, b"x", signer.sign(b"y")) is False


def test_signature_encoding_round_trip():
    value = b"\x00\x01\xff"
    assert decode_signature(encode_signature(value)) == value
