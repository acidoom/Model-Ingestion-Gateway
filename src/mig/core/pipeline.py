"""The gate pipeline runner.

Runner semantics (PRD §4, §7):

* **Ordering.** Execute gates by cost: CHEAP → MEDIUM → EXPENSIVE.
* **Applicability.** A gate runs only if ``artifact.artifact_type`` is in its
  ``applies_to`` set. Non-applicable gates are *omitted* (not ``SKIPPED``).
* **Short-circuit expensive, collect cheap.** A ``FAIL`` from a cheap/medium
  gate skips the EXPENSIVE stages (no point detonating something already known
  bad), but the runner still runs every already-eligible cheap/medium gate so
  an analyst sees everything wrong, not just the first thing.
* **Resilience.** A gate that raises does not crash the run; it becomes an
  ``ERROR`` :class:`~mig.core.verdict.GateResult` (vetting is incomplete, which
  the policy treats accordingly).
* **Decision-only.** The runner stops at the :class:`~mig.core.verdict.Verdict`.
  Promotion is a separate, gated call (I6, PR8) and is unreachable here.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import TYPE_CHECKING

from mig.core.verdict import (
    Finding,
    GateCost,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
    Verdict,
)

if TYPE_CHECKING:
    from mig.core.artifact import Artifact
    from mig.core.context import ScanContext
    from mig.core.protocols import Gate

#: The canonical execution order for gate cost classes.
COST_ORDER: tuple[GateCost, ...] = (GateCost.CHEAP, GateCost.MEDIUM, GateCost.EXPENSIVE)


def order_gates(gates: Sequence[Gate]) -> list[Gate]:
    """Stable-sort gates into CHEAP → MEDIUM → EXPENSIVE order."""
    rank = {cost: index for index, cost in enumerate(COST_ORDER)}
    return sorted(gates, key=lambda gate: rank[gate.cost])


def _run_gate(gate: Gate, artifact: Artifact, ctx: ScanContext) -> GateResult:
    """Run one gate, converting any exception into a resilient ERROR result."""
    start = time.perf_counter()
    try:
        result = gate.evaluate(artifact, ctx)
    except Exception as exc:  # a single gate must never crash the pipeline
        ctx.logger.exception("gate %r raised during evaluation", gate.id)
        return GateResult(
            gate_id=gate.id,
            status=GateStatus.ERROR,
            rigor=RigorLevel.NONE,
            findings=[
                Finding(
                    gate_id=gate.id,
                    severity=Severity.MEDIUM,
                    code="gate_error",
                    message=f"gate raised {type(exc).__name__}: {exc}",
                )
            ],
            duration_ms=int((time.perf_counter() - start) * 1000),
        )
    if result.duration_ms is None:
        result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result


def run_pipeline(
    artifact: Artifact,
    gates: Sequence[Gate],
    ctx: ScanContext,
) -> Verdict:
    """Run the gate pipeline and return a categorical :class:`Verdict`."""
    # Imported lazily so the core pipeline does not depend on the policy layer
    # at import time (keeps the module graph acyclic and the layering clean).
    from mig.policy.engine import evaluate

    applicable = [
        gate for gate in order_gates(gates) if artifact.artifact_type in gate.applies_to
    ]

    results: list[GateResult] = []
    short_circuit_expensive = False
    for gate in applicable:
        if short_circuit_expensive and gate.cost is GateCost.EXPENSIVE:
            # A cheap/medium gate already FAILed — skip expensive detonation,
            # but we have still collected every cheap/medium result above.
            continue
        result = _run_gate(gate, artifact, ctx)
        results.append(result)
        if result.status is GateStatus.FAIL and gate.cost is not GateCost.EXPENSIVE:
            short_circuit_expensive = True

    decision = evaluate(ctx.policy, artifact, results)
    return Verdict(
        ref=artifact.ref,
        artifact_type=artifact.artifact_type,
        gate_results=results,
        decision=decision,
    )
