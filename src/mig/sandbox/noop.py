"""The default sandbox: :class:`NoopSandbox` — a *loud* no-op (invariant I7).

ADR-001 makes the behavioral sandbox load-bearing: static analysis cannot vet
executable artifact types, so the verdict must be honest about whether dynamic
analysis actually happened. The default sandbox runs nothing and says so
loudly:

* ``rigor`` is ``NONE``;
* every detonation returns ``status=SKIPPED``;
* the result carries a HIGH-severity finding spelling out that **no** behavioral
  analysis occurred.

Combined with I8 (policy refuses APPROVE for executable types at static-only
rigor) this prevents the failure mode in risk R1 — adopters trusting an
APPROVE that was never behaviorally vetted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mig.core.verdict import Finding, GateStatus, RigorLevel, Severity
from mig.sandbox.base import BEHAVIORAL_GATE_ID
from mig.sandbox.spec import SandboxObservation

if TYPE_CHECKING:
    from mig.core.artifact import Artifact
    from mig.core.context import ScanContext
    from mig.sandbox.spec import SandboxSpec

#: Stable machine code for the "behavioral analysis did not run" finding.
BEHAVIORAL_SKIPPED_CODE = "behavioral_analysis_skipped"


class NoopSandbox:
    """A sandbox that detonates nothing and reports a loud SKIPPED (I7)."""

    #: This sandbox never achieves behavioral rigor.
    rigor: RigorLevel = RigorLevel.NONE

    #: How this confinement level identifies itself in an attestation (I5).
    confinement_level: str = "noop"

    def detonate(
        self,
        artifact: Artifact,
        spec: SandboxSpec,
        ctx: ScanContext,
    ) -> SandboxObservation:
        finding = Finding(
            gate_id=BEHAVIORAL_GATE_ID,
            severity=Severity.HIGH,
            code=BEHAVIORAL_SKIPPED_CODE,
            message=(
                "Behavioral analysis was SKIPPED: the configured sandbox is "
                "NoopSandbox, which performs no dynamic detonation. This "
                "artifact was NOT loaded or executed under confinement. Do not "
                "treat any APPROVE as behaviorally vetted (see invariants I7/I8)."
            ),
            metadata={
                "sandbox": "noop",
                "requested_spec": {
                    "image": spec.image,
                    "network": spec.network,
                    "read_only": spec.read_only,
                    "timeout_s": spec.timeout_s,
                },
            },
        )
        return SandboxObservation(
            rigor=RigorLevel.NONE,
            status=GateStatus.SKIPPED,
            findings=[finding],
        )
