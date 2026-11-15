from __future__ import annotations

import base64
import binascii
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from decisionlock.security.files import read_regular_file, secure_atomic_write


class Ed25519Signer:
    def __init__(self, private_key: Ed25519PrivateKey, key_id: str = "local-ed25519") -> None:
        self._private_key = private_key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(payload)

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    @classmethod
    def generate(cls, key_id: str = "local-ed25519") -> Ed25519Signer:
        return cls(Ed25519PrivateKey.generate(), key_id)

    def save_private(self, path: Path) -> None:
        secure_atomic_write(
            path,
            self._private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            mode=0o600,
        )

    def save_public(self, path: Path) -> None:
        secure_atomic_write(
            path,
            self.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            mode=0o644,
        )

    @classmethod
    def load_private(cls, path: Path, key_id: str = "local-ed25519") -> Ed25519Signer:
        key = serialization.load_pem_private_key(read_regular_file(path), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("not an Ed25519 private key")
        return cls(key, key_id)


class Ed25519Verifier:
    def __init__(self, keys: dict[str, Ed25519PublicKey]):
        self._keys = keys

    def verify(self, key_id: str, payload: bytes, signature: bytes) -> bool:
        key = self._keys.get(key_id)
        if key is None:
            return False
        try:
            key.verify(signature, payload)
            return True
        except InvalidSignature:
            return False

    @classmethod
    def from_public_file(cls, path: Path, key_id: str = "local-ed25519") -> Ed25519Verifier:
        key = serialization.load_pem_public_key(read_regular_file(path))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("not an Ed25519 public key")
        return cls({key_id: key})


class Ed25519BrokerGrantVerifier:
    """Explicit trust store for provider-neutral broker grant attestations."""

    def __init__(self, keys: dict[tuple[str, str], Ed25519PublicKey]) -> None:
        self._keys = keys

    def verify(
        self,
        broker_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        key = self._keys.get((broker_id, key_id))
        if key is None:
            return False
        try:
            key.verify(signature, payload)
            return True
        except InvalidSignature:
            return False

    @classmethod
    def from_public_file(
        cls,
        path: Path,
        *,
        broker_id: str,
        key_id: str = "mock-broker-ed25519",
    ) -> Ed25519BrokerGrantVerifier:
        key = serialization.load_pem_public_key(read_regular_file(path))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("not an Ed25519 public key")
        return cls({(broker_id, key_id): key})


def encode_signature(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_signature(value: str) -> bytes:
    try:
        return base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid signature encoding") from exc
