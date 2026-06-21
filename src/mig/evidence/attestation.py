"""The :class:`Attestation` — the integration seam OPA/Harbor consume.

Per invariant I5, an attestation MUST honestly encode, *per gate*: status,
rigor, scanner name + version; plus the overall confinement level and rigor.
Signing incomplete vetting as if complete is a defect — so the type makes the
rigor/confinement fields **required**, not optional, and exposes
:meth:`Attestation.attribution_problems` / :meth:`Attestation.assert_attributed`
so the (PR7) builder can fail closed if any *executed* gate is unattributed.

This dataclass is a **superset** of the PRD §5 field list: ``predicate_type``
and ``metadata`` are intentional, additive, defaulted extensions pre-provisioned
for PR7 signing (SLSA/in-toto). All §5-required fields are present and ordered.

Signing (sigstore/cosign, in-toto/SLSA predicate) lands in **PR7**; the
``signature`` field stays ``None`` until then.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mig.core.verdict import EXECUTED_STATUSES

if TYPE_CHECKING:
    from mig.core.artifact import ArtifactRef, ArtifactType
    from mig.core.verdict import Decision, GateResult, RigorLevel


@dataclass
class Attestation:
    """A portable, signable record of a vetting decision.

    ``gate_summary`` carries per-gate status + rigor + scanner versions (I5).
    ``overall_rigor`` and ``confinement_level`` make the *depth* of vetting
    legible to an external evaluator — so an attestation can never silently
    present static-only vetting as if it were behavioral.
    """

    ref: ArtifactRef
    digest: str
    artifact_type: ArtifactType
    decision: Decision
    gate_summary: Sequence[GateResult]  # status + rigor + scanner versions (I5)
    overall_rigor: RigorLevel  # STATIC vs BEHAVIORAL
    confinement_level: str  # "noop" | "docker" | "gvisor"
    policy_id: str
    policy_version: str
    mig_version: str
    created_at: str  # ISO-8601 UTC; stamped by the caller, not at import time
    signature: str | None = None  # sigstore/cosign; in-toto/SLSA — PR7
    predicate_type: str | None = None  # e.g. SLSA predicate URI — PR7 (extension)
    metadata: dict[str, object] = field(default_factory=dict)  # extension

    def __post_init__(self) -> None:
        # Canonicalise collections so serialise → deserialise is a total round-trip.
        self.gate_summary = list(self.gate_summary)
        self.metadata = dict(self.metadata)

    def attribution_problems(self) -> list[str]:
        """I5 check: executed gates that lack scanner name/version.

        A gate that actually executed (``PASS``/``WARN``/``FAIL``) must be
        attributable to a named, versioned scanner. ``SKIPPED``/``ERROR`` gates
        legitimately carry no attribution (e.g. :class:`NoopSandbox`), so they
        are exempt. Returns a list of human-readable problems (empty == clean).
        """
        problems: list[str] = []
        for result in self.gate_summary:
            if result.status not in EXECUTED_STATUSES:
                continue
            if not result.scanner_name:
                problems.append(
                    f"gate {result.gate_id!r} executed "
                    f"({result.status.value}) without scanner_name (I5)"
                )
            if not result.scanner_version:
                problems.append(
                    f"gate {result.gate_id!r} executed "
                    f"({result.status.value}) without scanner_version (I5)"
                )
        return problems

    def assert_attributed(self) -> None:
        """Raise ``ValueError`` if any executed gate is unattributed (I5).

        The PR7 attestation builder calls this before signing so MIG cannot sign
        under-attributed vetting as if it were complete.
        """
        problems = self.attribution_problems()
        if problems:
            raise ValueError(
                "refusing to attest under-attributed vetting (I5): " + "; ".join(problems)
            )
