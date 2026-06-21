"""Gate ordering helpers (the runner itself is covered in test_pipeline_runner)."""

from __future__ import annotations

from conftest import NoopGate
from mig.core.pipeline import COST_ORDER, order_gates
from mig.core.verdict import GateCost


def test_cost_order_is_cheap_medium_expensive() -> None:
    assert COST_ORDER == (GateCost.CHEAP, GateCost.MEDIUM, GateCost.EXPENSIVE)


def test_order_gates_sorts_by_cost() -> None:
    gates = [
        NoopGate(id="e", cost=GateCost.EXPENSIVE),
        NoopGate(id="c", cost=GateCost.CHEAP),
        NoopGate(id="m", cost=GateCost.MEDIUM),
    ]
    assert [g.id for g in order_gates(gates)] == ["c", "m", "e"]


def test_order_gates_is_stable_within_a_cost_class() -> None:
    gates = [
        NoopGate(id="a", cost=GateCost.CHEAP),
        NoopGate(id="b", cost=GateCost.CHEAP),
    ]
    assert [g.id for g in order_gates(gates)] == ["a", "b"]
