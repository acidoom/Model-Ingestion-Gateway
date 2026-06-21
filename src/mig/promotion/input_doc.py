"""The canonical promotion input document — what BOTH the embedded floor and OPA
evaluate.

Built from the VERIFIED signed attestation only (never an unsigned verdict
mirror) via :func:`mig.evidence.canonical.canonicalize`, so it is deterministic,
str-keyed, and reproducible. Every floor-relevant field is guaranteed present and
typed; the gates read with ``.get(...) is True`` so a missing field fails closed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mig.core.artifact import EXECUTABLE_ARTIFACT_TYPES
from mig.core.hashing import normalize_digest
from mig.evidence.canonical import canonicalize
from mig.evidence.statement import PREDICATE_TYPE, subject_name

if TYPE_CHECKING:
    from mig.core.artifact import ArtifactRef
    from mig.evidence.attestation import Attestation
    from mig.evidence.verify import VerifyResult


def _bare_hex(digest: str) -> str:
    return normalize_digest(digest).split(":", 1)[1]


def build_promotion_input(
    result: VerifyResult, attestation: Attestation, ref: ArtifactRef
) -> dict[str, Any]:
    """The deterministic input doc the promotion gate(s) decide over."""
    doc: dict[str, Any] = {
        "subject": {
            "name": subject_name(ref),
            "digest": {"sha256": _bare_hex(attestation.digest)},
        },
        "predicate_type": attestation.predicate_type or PREDICATE_TYPE,
        "decision": attestation.decision.value,
        "artifact_type": attestation.artifact_type.value,
        "overall_rigor": attestation.overall_rigor.value,
        "confinement_level": attestation.confinement_level,
        "is_executable_type": attestation.artifact_type in EXECUTABLE_ARTIFACT_TYPES,
        "gate_summary": [
            {
                "gate_id": g.gate_id,
                "status": g.status.value,
                "rigor": g.rigor.value,
                "scanner_name": g.scanner_name,
                "scanner_version": g.scanner_version,
            }
            for g in attestation.gate_summary
        ],
        "verification": {
            "ok": result.ok,
            "scheme": result.scheme,
            "keyid": result.keyid,
            "checks": dict(result.checks),
        },
        "policy": {"id": attestation.policy_id, "version": attestation.policy_version},
        "mig_version": attestation.mig_version,
        "created_at": attestation.created_at,
    }
    # canonicalize validates (str keys, no NaN/binary) and returns a plain graph.
    projected: dict[str, Any] = canonicalize(doc)
    return projected
