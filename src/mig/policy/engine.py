"""The embedded decision engine.

PR2 ships the **built-in default policy** — a small, categorical reducer that
turns gate results into a :class:`Decision`. It is deliberately *not* a numeric
threshold (I4); it keys on gate status plus the load-bearing rules:

* a ``FAIL`` rejects;
* an ``ERROR`` (a gate that could not complete) requires review — never approve
  on incomplete vetting;
* an **executable** artifact type without behavioral rigor can never be
  approved at static-only rigor (I8 / ADR-001);
* a ``WARN`` (e.g. prompt-injection, I9) asks for human review rather than
  auto-rejecting.

The declarative YAML policy engine (PRD §8) replaces/augments this in **PR5**;
``evaluate`` is the seam the runner calls, so PR5 can dispatch on
``policy.rules`` without touching the pipeline.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from mig.core.artifact import Artifact
from mig.core.verdict import (
    EXECUTED_STATUSES,
    Decision,
    GateResult,
    GateStatus,
    RigorLevel,
)

if TYPE_CHECKING:
    from mig.policy.schema import Policy


def _behavioral_ran(gate_results: Sequence[GateResult]) -> bool:
    return any(
        result.rigor is RigorLevel.BEHAVIORAL and result.status in EXECUTED_STATUSES
        for result in gate_results
    )


def default_decision(artifact: Artifact, gate_results: Sequence[GateResult]) -> Decision:
    """The built-in categorical decision (I4). See module docstring."""
    statuses = {result.status for result in gate_results}

    if GateStatus.FAIL in statuses:
        return Decision.REJECT
    if GateStatus.ERROR in statuses:
        return Decision.REVIEW_REQUIRED
    # I8 / ADR-001: executable types cannot be approved without behavioral rigor.
    if artifact.is_executable_type and not _behavioral_ran(gate_results):
        return Decision.REVIEW_REQUIRED
    if GateStatus.WARN in statuses:
        return Decision.REVIEW_REQUIRED  # I9: warn → review, never auto-reject
    return Decision.APPROVE


def evaluate(
    policy: Policy, artifact: Artifact, gate_results: Sequence[GateResult]
) -> Decision:
    """Evaluate a policy over gate results to a categorical decision.

    PR2: the embedded engine is the built-in default. PR5 evaluates the
    declarative ``policy.rules``; the signature is fixed now so the runner does
    not change.
    """
    return default_decision(artifact, gate_results)
