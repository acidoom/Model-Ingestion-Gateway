"""Build a signable :class:`Attestation` from a vetting :class:`Verdict`.

This is the I5 fail-closed gate: :func:`build_attestation` calls
:meth:`Attestation.assert_attributed` before returning, so MIG cannot project —
let alone sign — under-attributed vetting as if it were complete. It also refuses
an unpinned artifact (I3: no digest, no attestation). No signing, no store writes
(I6) — that is the caller's separate, gated concern.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from mig.evidence.attestation import Attestation
from mig.evidence.statement import PREDICATE_TYPE

if TYPE_CHECKING:
    from mig.core.artifact import Artifact
    from mig.core.verdict import Verdict
    from mig.policy.schema import Policy


def build_attestation(
    verdict: Verdict,
    artifact: Artifact,
    *,
    policy: Policy,
    mig_version: str,
    confinement_level: str,
    created_at: str,
    metadata: Mapping[str, object] | None = None,
) -> Attestation:
    """Project ``verdict`` + ``artifact`` into a fully-attributed Attestation.

    ``created_at`` is caller-stamped (ISO-8601 UTC) so a run is byte-reproducible
    — never stamped at import time. Raises ``ValueError`` if the artifact is
    unpinned (I3) or any executed gate is unattributed (I5).
    """
    if not artifact.digest:
        raise ValueError("cannot attest an unpinned artifact (no digest — I3)")
    if verdict.ref != artifact.ref:
        raise ValueError("verdict/artifact ref mismatch — refusing to attest")

    attestation = Attestation(
        ref=artifact.ref,
        digest=artifact.digest,
        artifact_type=artifact.artifact_type,
        decision=verdict.decision,
        gate_summary=verdict.gate_results,
        overall_rigor=verdict.rigor_summary(),
        confinement_level=confinement_level,
        policy_id=policy.id,
        policy_version=policy.version,
        mig_version=mig_version,
        created_at=created_at,
        predicate_type=PREDICATE_TYPE,
        metadata=dict(metadata or {}),
    )
    # I5: refuse to attest vetting whose executed gates aren't named + versioned.
    attestation.assert_attributed()
    return attestation
