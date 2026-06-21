"""The signing seam: Signer/Verifier protocols, the stdlib HMAC default, and the
sign/verify orchestration over the shared DSSE PAE bytes.

The default :class:`HMACSigner` is stdlib-only (``hmac`` + ``hashlib``) so MIG
signs offline/airgapped with zero non-stdlib deps (I10). HMAC is *integrity +
shared-secret possession*, NOT third-party non-repudiation — :mod:`mig.evidence.verify`
emits a loud banner for the ``hmac-sha256`` scheme and the ed25519/cosign
backends (opt-in extras) are the promotion-grade, publicly-verifiable paths.

A verifier is always chosen by the **operator** (``--signer``/``--key``); it is
NEVER selected from the envelope-supplied ``keyid``/``scheme`` (DSSE does not
authenticate the keyid), which closes the attacker-controlled-keyid hole.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from mig.evidence.canonical import canonical_bytes
from mig.evidence.dsse import (
    PAYLOAD_TYPE,
    Envelope,
    Signature,
    b64,
    extract_payload_bytes,
    pae,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

#: Scheme tag for the stdlib HMAC default.
HMAC_SCHEME = "hmac-sha256"
#: Minimum HMAC key length — a short shared secret is brute-forceable.
MIN_HMAC_KEY_BYTES = 32


class SigningError(RuntimeError):
    """Raised when signing cannot proceed (bad key, missing extra, unknown signer)."""


class VerificationError(RuntimeError):
    """Raised when a signature does not verify (tamper, wrong key, no matching sig)."""


@runtime_checkable
class Signer(Protocol):
    """Signs the DSSE PAE bytes. ``scheme``/``key_id`` describe the signature."""

    scheme: str
    key_id: str

    def sign(self, message: bytes) -> bytes: ...


@runtime_checkable
class Verifier(Protocol):
    """Verifies a signature over the DSSE PAE bytes."""

    scheme: str
    key_id: str

    def verify(self, message: bytes, signature: bytes) -> bool: ...


def hmac_key_id(key: bytes) -> str:
    """A deterministic, domain-separated keyid for an HMAC secret.

    ``sha256(b"mig-keyid-v1" + key)`` rather than a bare ``sha256(key)`` so the
    keyid is not a published commitment to (oracle on) the secret itself.
    """
    return hashlib.sha256(b"mig-keyid-v1" + key).hexdigest()[:16]


def _check_key_len(key: bytes) -> bytes:
    if len(key) < MIN_HMAC_KEY_BYTES:
        raise SigningError(
            f"HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes "
            f"(got {len(key)}); use a high-entropy secret"
        )
    return key


class HMACSigner:
    """Stdlib HMAC-SHA256 signer — the zero-dependency default (I10)."""

    scheme = HMAC_SCHEME

    def __init__(self, key: bytes) -> None:
        self._key = _check_key_len(key)
        self.key_id = hmac_key_id(key)

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self._key, message, hashlib.sha256).digest()


class HMACVerifier:
    """Stdlib HMAC-SHA256 verifier — constant-time compare."""

    scheme = HMAC_SCHEME

    def __init__(self, key: bytes) -> None:
        self._key = _check_key_len(key)
        self.key_id = hmac_key_id(key)

    def verify(self, message: bytes, signature: bytes) -> bool:
        expected = hmac.new(self._key, message, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


def sign_statement(statement: Mapping[str, Any], signer: Signer) -> Envelope:
    """Canonicalise ``statement``, build the PAE, and sign it into a DSSE Envelope."""
    payload = canonical_bytes(statement)
    message = pae(PAYLOAD_TYPE.encode("utf-8"), payload)
    raw_sig = signer.sign(message)
    return Envelope(
        payload_type=PAYLOAD_TYPE,
        payload=b64(payload),
        signatures=[
            Signature(keyid=signer.key_id, sig=b64(raw_sig), scheme=signer.scheme)
        ],
    )


def verify_envelope(env: Envelope, verifier: Verifier) -> dict[str, Any]:
    """Verify ``env`` with the operator-chosen ``verifier``; return the Statement.

    Only signatures whose ``scheme`` matches the verifier are considered (the
    verifier is never picked from the envelope). A malformed (non-base64) payload
    or signature is treated as a verification failure — never a crash or a
    misclassified operator error. Raises :class:`VerificationError` if no matching
    signature verifies.
    """
    try:
        payload = extract_payload_bytes(env)
    except ValueError as exc:  # non-base64 payload — can't be the signed bytes
        raise VerificationError("malformed envelope payload (invalid base64)") from exc
    message = pae(env.payload_type.encode("utf-8"), payload)
    candidates = [s for s in env.signatures if s.scheme == verifier.scheme]
    if not candidates:
        raise VerificationError(
            f"envelope carries no {verifier.scheme!r} signature to verify"
        )
    verified = False
    for sig in candidates:
        try:
            raw = base64.b64decode(sig.sig, validate=True)
        except ValueError:
            continue  # a non-base64 signature simply cannot verify
        if verifier.verify(message, raw):
            verified = True
            break
    if not verified:
        raise VerificationError("signature verification failed")
    statement: Any = json.loads(payload)
    if not isinstance(statement, dict):
        raise VerificationError("signed payload is not a JSON object")
    return statement


def make_signer(
    name: str,
    *,
    key_bytes: bytes | None = None,
    key_ref: str | None = None,
    cosign_bin: str = "cosign",
) -> Signer:
    """Construct a signer by name. ed25519/cosign are lazy-imported (opt-in extras)."""
    if name == "hmac":
        if key_bytes is None:
            raise SigningError("hmac signer needs a key (--key FILE or MIG_SIGNING_KEY)")
        return HMACSigner(key_bytes)
    if name == "ed25519":
        from mig.evidence.signers.ed25519 import Ed25519Signer

        if key_bytes is None:
            raise SigningError("ed25519 signer needs a private key (--key FILE)")
        return Ed25519Signer(key_bytes)
    if name == "cosign":
        from mig.evidence.signers.cosign import CosignSigner

        if not key_ref:
            raise SigningError("cosign signer needs a key reference (--key)")
        return CosignSigner(key_ref, cosign_bin=cosign_bin)
    raise SigningError(f"unknown signer {name!r} (use: hmac, ed25519, cosign)")


def make_verifier(
    name: str,
    *,
    key_bytes: bytes | None = None,
    key_ref: str | None = None,
    cosign_bin: str = "cosign",
) -> Verifier:
    """Construct a verifier by name. ed25519/cosign are lazy-imported (opt-in extras)."""
    if name == "hmac":
        if key_bytes is None:
            raise SigningError(
                "hmac verifier needs a key (--key FILE or MIG_SIGNING_KEY)"
            )
        return HMACVerifier(key_bytes)
    if name == "ed25519":
        from mig.evidence.signers.ed25519 import Ed25519Verifier

        if key_bytes is None:
            raise SigningError("ed25519 verifier needs a public key (--key FILE)")
        return Ed25519Verifier(key_bytes)
    if name == "cosign":
        from mig.evidence.signers.cosign import CosignVerifier

        if not key_ref:
            raise SigningError("cosign verifier needs a public key reference (--key)")
        return CosignVerifier(key_ref, cosign_bin=cosign_bin)
    raise SigningError(f"unknown verifier {name!r} (use: hmac, ed25519, cosign)")
