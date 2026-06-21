"""Projection between :class:`Attestation` and an in-toto Statement v1.

The signed payload is a real in-toto Statement v1 carrying a MIG *vetting*
predicate, so the result is interoperable with cosign / OPA / Harbor ("compose,
don't reimplement"). The artifact content digest is the Statement *subject*, so
it sits inside the signed bytes and is re-bound at verify time (I3).

Pure mapping — no crypto, no I/O. The ``signature`` field is **dropped** from the
projected predicate: a signature lives only in the DSSE envelope, never inside
the bytes it signs.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from mig.core.hashing import normalize_digest
from mig.core.serde import attestation_from_dict
from mig.evidence.canonical import canonicalize

if TYPE_CHECKING:
    from mig.core.artifact import ArtifactRef
    from mig.evidence.attestation import Attestation

#: in-toto Statement type URI (v1).
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
#: MIG's vetting predicate type URI — the predicate is the projected Attestation.
PREDICATE_TYPE = "https://mig.dev/attestation/vetting/v1"


def subject_name(ref: ArtifactRef) -> str:
    """The in-toto subject name for an artifact ref (``scheme://locator[@rev]``)."""
    name = f"{ref.scheme}://{ref.locator}"
    if ref.revision:
        name = f"{name}@{ref.revision}"
    return name


def _bare_sha256_hex(digest: str) -> str:
    """The bare lowercase hex of a sha256 digest (in-toto subjects carry no algo
    prefix). Raises on a non-sha256 digest — the only algorithm MIG emits."""
    algo, _, hexpart = normalize_digest(digest).partition(":")
    if algo != "sha256" or not hexpart:
        raise ValueError(f"expected a sha256 digest, got {digest!r}")
    return hexpart


def statement_from_attestation(att: Attestation) -> dict[str, Any]:
    """Project an :class:`Attestation` into an in-toto Statement v1 dict.

    The predicate is the canonicalised Attestation with ``signature`` removed
    (the signature belongs to the envelope, not the signed payload). Projecting
    via :func:`canonicalize` — not ``to_jsonable`` — means non-string metadata
    keys are REJECTED here rather than silently str-coerced into a collision.
    """
    predicate = canonicalize(att)
    predicate.pop("signature", None)
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": subject_name(att.ref),
                "digest": {"sha256": _bare_sha256_hex(att.digest)},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def subject_digest(statement: Mapping[str, Any]) -> str:
    """The bare-hex sha256 subject digest from a Statement (for the I3 re-bind)."""
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise ValueError("statement has no subject")
    digest = subjects[0].get("digest", {})
    sha = digest.get("sha256")
    if not isinstance(sha, str) or not sha:
        raise ValueError("statement subject has no sha256 digest")
    return sha


def attestation_from_statement(statement: Mapping[str, Any]) -> Attestation:
    """Reconstruct the :class:`Attestation` carried by a Statement's predicate."""
    actual = statement.get("predicateType")
    if actual != PREDICATE_TYPE:
        raise ValueError(f"not a MIG vetting statement: predicateType={actual!r}")
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        raise ValueError("statement predicate is missing or not an object")
    return attestation_from_dict(predicate)
