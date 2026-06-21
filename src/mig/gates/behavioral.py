"""Behavioral gate (expensive) — delegates to the configured sandbox.

This is the one gate that *runs* the artifact, and it never does so in-process:
it hands the artifact to ``ctx.sandbox`` for confined detonation. With the
default :class:`~mig.sandbox.noop.NoopSandbox` the observation is a loud
``SKIPPED`` at ``NONE`` rigor (I7), which surfaces in the verdict and — via the
policy — blocks APPROVE for executable types (I8).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mig import __version__
from mig.core.artifact import Artifact, ArtifactType
from mig.core.verdict import GateCost, GateResult
from mig.sandbox.base import observation_to_result
from mig.sandbox.spec import SandboxSpec

if TYPE_CHECKING:
    from mig.core.context import ScanContext

GATE_ID = "behavioral"


class BehavioralGate:
    """Drive ``ctx.sandbox`` to detonate the artifact under confinement."""

    id = GATE_ID
    cost = GateCost.EXPENSIVE
    applies_to = frozenset(ArtifactType)

    def evaluate(self, artifact: Artifact, ctx: ScanContext) -> GateResult:
        spec = SandboxSpec()  # deny-by-default confinement (no egress, read-only)
        observation = ctx.sandbox.detonate(artifact, spec, ctx)
        confinement = getattr(
            ctx.sandbox, "confinement_level", type(ctx.sandbox).__name__
        )
        return observation_to_result(
            observation,
            scanner_name=f"sandbox:{confinement}",
            scanner_version=__version__,
        )
