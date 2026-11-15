from collections.abc import Callable
from pathlib import Path

import pytest

import decisionlock.adapters.crypto.ed25519 as ed25519_module
from decisionlock.adapters.crypto import (
    Ed25519Signer,
    Ed25519Verifier,
    decode_signature,
    encode_signature,
)


def test_key_file_round_trip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    assert_private_file: Callable[[Path], bytes],
) -> None:
    secure_writer_calls: list[tuple[Path, int]] = []
    original_secure_writer = ed25519_module.secure_atomic_write

    def tracked_secure_writer(path: Path, data: bytes, *, mode: int = 0o600) -> None:
        secure_writer_calls.append((path, mode))
        original_secure_writer(path, data, mode=mode)

    monkeypatch.setattr(ed25519_module, "secure_atomic_write", tracked_secure_writer)
    signer = Ed25519Signer.generate("k1")
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    signer.save_private(private)
    signer.save_public(public)
    loaded = Ed25519Signer.load_private(private, "k1")
    verifier = Ed25519Verifier.from_public_file(public, "k1")
    payload = b"payload"
    assert verifier.verify("k1", payload, loaded.sign(payload))
    assert (private, 0o600) in secure_writer_calls
    assert b"PRIVATE KEY" in assert_private_file(private)


def test_unknown_key_is_false(signer):
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    assert verifier.verify("unknown", b"x", signer.sign(b"x")) is False


def test_bad_signature_is_false(signer):
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    assert verifier.verify(signer.key_id, b"x", signer.sign(b"y")) is False


def test_signature_encoding_round_trip():
    value = b"\x00\x01\xff"
    assert decode_signature(encode_signature(value)) == value
