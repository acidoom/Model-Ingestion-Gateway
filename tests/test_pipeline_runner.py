"""run_pipeline: ordering, applicability, short-circuit/collect, resilience."""

from __future__ import annotations

from dataclasses import dataclass, field

from conftest import make_artifact
from mig.core.artifact import Artifact, ArtifactType
from mig.core.context import DefaultScanContext
from mig.core.pipeline import run_pipeline
from mig.core.protocols import Gate
from mig.core.verdict import (
    Decision,
    GateCost,
    GateResult,
    GateStatus,
    RigorLevel,
)


@dataclass
class StubGate:
    """A configurable gate that logs when it runs."""

    id: str
    cost: GateCost
    log: list[str]
    status: GateStatus = GateStatus.PASS
    applies_to: frozenset[ArtifactType] = field(
        default_factory=lambda: frozenset(ArtifactType)
    )

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        self.log.append(self.id)
        return GateResult(
            gate_id=self.id,
            status=self.status,
            rigor=RigorLevel.STATIC,
            scanner_name="stub",
            scanner_version="1",
        )


@dataclass
class BoomGate:
    id: str = "boom"
    cost: GateCost = GateCost.CHEAP
    applies_to: frozenset[ArtifactType] = field(
        default_factory=lambda: frozenset(ArtifactType)
    )

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        raise RuntimeError("kaboom")


def test_runs_in_cost_order(ctx: DefaultScanContext) -> None:
    log: list[str] = []
    gates = [
        StubGate("exp", GateCost.EXPENSIVE, log),
        StubGate("cheap", GateCost.CHEAP, log),
        StubGate("med", GateCost.MEDIUM, log),
    ]
    run_pipeline(make_artifact(ArtifactType.MODEL), gates, ctx)
    assert log == ["cheap", "med", "exp"]


def test_non_applicable_gates_are_omitted(ctx: DefaultScanContext) -> None:
    log: list[str] = []
    applies = StubGate("applies", GateCost.CHEAP, log)
    skips = StubGate(
        "skips", GateCost.CHEAP, log, applies_to=frozenset({ArtifactType.NPM_PACKAGE})
    )
    verdict = run_pipeline(make_artifact(ArtifactType.MODEL), [applies, skips], ctx)
    assert log == ["applies"]  # the non-applicable gate never ran
    assert [r.gate_id for r in verdict.gate_results] == ["applies"]  # and is omitted


def test_cheap_fail_short_circuits_expensive_but_collects_cheap(
    ctx: DefaultScanContext,
) -> None:
    log: list[str] = []
    gates = [
        StubGate("cheap1", GateCost.CHEAP, log, status=GateStatus.FAIL),
        StubGate("cheap2", GateCost.CHEAP, log, status=GateStatus.PASS),
        StubGate("expensive", GateCost.EXPENSIVE, log),
    ]
    verdict = run_pipeline(make_artifact(ArtifactType.MODEL), gates, ctx)
    # Both cheap gates ran (collect everything wrong); expensive was skipped.
    assert log == ["cheap1", "cheap2"]
    assert [r.gate_id for r in verdict.gate_results] == ["cheap1", "cheap2"]
    assert verdict.decision is Decision.REJECT


def test_gate_exception_becomes_error_and_does_not_crash(
    ctx: DefaultScanContext,
) -> None:
    log: list[str] = []
    gates: list[Gate] = [BoomGate(), StubGate("after", GateCost.CHEAP, log)]
    verdict = run_pipeline(make_artifact(ArtifactType.MODEL), gates, ctx)
    boom = next(r for r in verdict.gate_results if r.gate_id == "boom")
    assert boom.status is GateStatus.ERROR
    assert any(f.code == "gate_error" for f in boom.findings)
    assert "after" in log  # the pipeline continued past the failing gate


def test_clean_run_approves_and_times_gates(ctx: DefaultScanContext) -> None:
    log: list[str] = []
    verdict = run_pipeline(
        make_artifact(ArtifactType.MODEL),
        [StubGate("cheap", GateCost.CHEAP, log)],
        ctx,
    )
    assert verdict.decision is Decision.APPROVE
    assert verdict.gate_results[0].duration_ms is not None
