"""Evidence bundle + attestation seam (PR1 contract, PR7 signing).

The :class:`Attestation` contract ships in PR1. PR7 adds the build → sign →
verify pipeline over a real in-toto Statement v1 + DSSE envelope, with a
stdlib-only HMAC default (I10) and ed25519/cosign as opt-in backends.
"""

from __future__ import annotations

from mig.evidence.attestation import Attestation
from mig.evidence.builder import build_attestation
from mig.evidence.bundle import (
    BUNDLE_SCHEMA,
    build_bundle,
    load_bundle,
    write_bundle,
)
from mig.evidence.canonical import canonical_bytes, canonical_json
from mig.evidence.dsse import Envelope, Signature, encode_envelope, pae
from mig.evidence.signing import (
    HMACSigner,
    HMACVerifier,
    Signer,
    SigningError,
    VerificationError,
    Verifier,
    make_signer,
    make_verifier,
    sign_statement,
    verify_envelope,
)
from mig.evidence.statement import (
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    attestation_from_statement,
    statement_from_attestation,
)
from mig.evidence.verify import VerifyResult, verify_attestation

__all__ = [
    "Attestation",
    # build
    "build_attestation",
    # canonical bytes
    "canonical_bytes",
    "canonical_json",
    # in-toto statement
    "STATEMENT_TYPE",
    "PREDICATE_TYPE",
    "statement_from_attestation",
    "attestation_from_statement",
    # DSSE
    "Envelope",
    "Signature",
    "encode_envelope",
    "pae",
    # signing
    "Signer",
    "Verifier",
    "HMACSigner",
    "HMACVerifier",
    "SigningError",
    "VerificationError",
    "make_signer",
    "make_verifier",
    "sign_statement",
    "verify_envelope",
    # verify
    "verify_attestation",
    "VerifyResult",
    # bundle
    "BUNDLE_SCHEMA",
    "build_bundle",
    "write_bundle",
    "load_bundle",
]
