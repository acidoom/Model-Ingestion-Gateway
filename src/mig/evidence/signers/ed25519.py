"""ed25519 asymmetric signer/verifier — opt-in (``mig[signing]``).

Publicly verifiable, promotion-grade signatures over the SAME DSSE PAE bytes the
HMAC default signs. ``cryptography`` is imported **lazily inside functions** (via
:func:`_require_cryptography`, mirroring ``sources/huggingface._require_hub``), so
importing this module does not pull in a third-party dependency — the core stays
stdlib-only at import time (I10), and an absent extra yields an actionable error.
"""

from __future__ import annotations

import hashlib
from typing import Any

from mig.evidence.signing import SigningError

#: Scheme tag carried in the DSSE signature.
ED25519_SCHEME = "ed25519"


def _require_cryptography() -> Any:
    """Lazy-import the ed25519 primitives, or raise an install-hint error."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # the extra is not installed
        raise SigningError(
            "ed25519 signing needs the 'cryptography' library — install mig[signing]"
        ) from exc
    return ed25519


def _load_private(data: bytes) -> Any:
    ed25519 = _require_cryptography()
    if len(data) == 32:  # a raw private seed
        return ed25519.Ed25519PrivateKey.from_private_bytes(data)
    from cryptography.hazmat.primitives import serialization

    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise SigningError(
            "could not load ed25519 private key (expected raw 32-byte seed or PEM)"
        ) from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SigningError("provided key is not an ed25519 private key")
    return key


def _load_public(data: bytes) -> Any:
    ed25519 = _require_cryptography()
    if len(data) == 32:  # a raw public key
        return ed25519.Ed25519PublicKey.from_public_bytes(data)
    from cryptography.hazmat.primitives import serialization

    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise SigningError(
            "could not load ed25519 public key (expected raw 32-byte key or PEM)"
        ) from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise SigningError("provided key is not an ed25519 public key")
    return key


def _key_id(public_key: Any) -> str:
    """keyid = first 16 hex of sha256(SubjectPublicKeyInfo DER)."""
    from cryptography.hazmat.primitives import serialization

    der: bytes = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


class Ed25519Signer:
    """Signs the DSSE PAE bytes with an ed25519 private key."""

    scheme = ED25519_SCHEME

    def __init__(self, private_key_bytes: bytes) -> None:
        self._sk = _load_private(private_key_bytes)
        self.key_id = _key_id(self._sk.public_key())

    def sign(self, message: bytes) -> bytes:
        signature: bytes = self._sk.sign(message)
        return signature


class Ed25519Verifier:
    """Verifies an ed25519 signature over the DSSE PAE bytes."""

    scheme = ED25519_SCHEME

    def __init__(self, public_key_bytes: bytes) -> None:
        self._pk = _load_public(public_key_bytes)
        self.key_id = _key_id(self._pk)

    def verify(self, message: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            self._pk.verify(signature, message)
        except (InvalidSignature, ValueError):  # fail-closed on any bad signature
            return False
        return True
