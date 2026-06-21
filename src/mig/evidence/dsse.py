"""DSSE (Dead Simple Signing Envelope) primitives — stdlib only.

This module frames bytes; it never signs. It defines the **signed-bytes
contract** every signer shares: the Pre-Authentication Encoding (PAE) over a
canonical-JSON in-toto Statement. Because all backends (HMAC, ed25519, cosign)
sign the *identical* PAE bytes, a signature made by one verifies under the same
contract — and the artifact digest, which lives inside the Statement, is inside
the signed bytes (I3).

PAE (per the DSSE spec)::

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body

where ``LEN`` is the ASCII-decimal count of the operand's **raw bytes** (not its
base64 form) and ``SP`` is a single 0x20 space. The envelope's ``signatures[]``
sit *outside* the PAE, so a signature can never appear inside the signed payload.
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

#: The in-toto Statement payload type carried by the envelope.
PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(payload_type: bytes, payload: bytes) -> bytes:
    """The DSSE Pre-Authentication Encoding — the exact bytes that get signed."""
    return b" ".join(
        [
            b"DSSEv1",
            str(len(payload_type)).encode("ascii"),
            payload_type,
            str(len(payload)).encode("ascii"),
            payload,
        ]
    )


@dataclass(frozen=True)
class Signature:
    """One DSSE signature: standard-base64 ``sig`` over the PAE, plus metadata.

    ``scheme``/``keyid`` are advisory for display and triage — a verifier MUST
    NOT select its key from them (DSSE does not authenticate the keyid).
    """

    keyid: str
    sig: str  # standard base64 (padded) of the raw signature bytes
    scheme: str


@dataclass(frozen=True)
class Envelope:
    """A DSSE envelope: the base64 payload plus one or more signatures."""

    payload_type: str
    payload: str  # standard base64 (padded) of canonical_bytes(statement)
    signatures: Sequence[Signature]

    def __post_init__(self) -> None:
        object.__setattr__(self, "signatures", tuple(self.signatures))


def signed_bytes(env: Envelope) -> bytes:
    """The PAE bytes a verifier must recompute and check the signature against."""
    return pae(env.payload_type.encode("utf-8"), extract_payload_bytes(env))


def extract_payload_bytes(env: Envelope) -> bytes:
    """Decode the base64 payload to the raw canonical Statement bytes.

    ``validate=True`` so a payload carrying non-alphabet characters raises rather
    than being silently 'repaired' (envelope byte-canonicality; DSSE compliance).
    Raises ``binascii.Error`` (a ``ValueError``) on malformed base64.
    """
    return base64.b64decode(env.payload, validate=True)


def encode_envelope(env: Envelope) -> dict[str, Any]:
    """The on-disk DSSE JSON shape ``{payloadType, payload, signatures[]}``."""
    return {
        "payloadType": env.payload_type,
        "payload": env.payload,
        "signatures": [
            {"keyid": s.keyid, "sig": s.sig, "scheme": s.scheme} for s in env.signatures
        ],
    }


def b64(raw: bytes) -> str:
    """Standard (padded, non-urlsafe) base64 — pinned for cross-tool interop."""
    return base64.b64encode(raw).decode("ascii")
