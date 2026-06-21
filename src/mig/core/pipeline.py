"""The gate pipeline runner.

.. note::
   **Scaffolding stub — the runner is implemented in PR2.**

   PR1 fixes the *contract* the runner must honour; the executable
   implementation (ordering, short-circuit/collect semantics, JSON report) is
   PR2's deliverable. This module documents that contract and exposes the
   signature so callers and tests can compile against it.

Runner semantics the PR2 implementation MUST satisfy (PRD §4, §7):

* **Ordering.** Execute gates by cost: CHEAP → MEDIUM → EXPENSIVE.
* **Applicability.** A gate runs only if ``artifact.artifact_type`` is in its
  ``applies_to`` set. Non-applicable gates are *omitted* (not ``SKIPPED``).
* **Short-circuit expensive, collect cheap.** A ``FAIL`` from a cheap gate
  skips the EXPENSIVE stages, but the runner still collects findings from all
  already-eligible cheap/medium gates — an analyst sees everything wrong, not
  just the first thing.
* **Decision-only.** The runner stops at the :class:`~mig.core.verdict.Verdict`.
  Promotion is a separate, gated call (I6, PR8) and MUST NOT be reachable here.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from mig.core.verdict import GateCost

if TYPE_CHECKING:
    from mig.core.artifact import Artifact
    from mig.core.context import ScanContext
    from mig.core.protocols import Gate
    from mig.core.verdict import Verdict

#: The canonical execution order for gate cost classes.
COST_ORDER: tuple[GateCost, ...] = (GateCost.CHEAP, GateCost.MEDIUM, GateCost.EXPENSIVE)


def order_gates(gates: Sequence[Gate]) -> list[Gate]:
    """Stable-sort gates into CHEAP → MEDIUM → EXPENSIVE order.

    Implemented in PR1 because it is pure and useful to test early; the full
    runner that consumes this ordering lands in PR2.
    """
    rank = {cost: i for i, cost in enumerate(COST_ORDER)}
    return sorted(gates, key=lambda gate: rank[gate.cost])


def run_pipeline(
    artifact: Artifact,
    gates: Sequence[Gate],
    ctx: ScanContext,
) -> Verdict:
    """Run the gate pipeline and return a categorical :class:`Verdict`.

    Implemented in **PR2**. See module docstring for the semantics this must
    satisfy.
    """
    raise NotImplementedError(
        "run_pipeline is implemented in PR2 (pipeline runner + walking skeleton)"
    )
