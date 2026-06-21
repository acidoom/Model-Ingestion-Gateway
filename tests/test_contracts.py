"""PR1 acceptance: the test doubles compile against the protocol seams.

Static conformance is checked by mypy; this asserts the runtime-checkable
structural conformance too.
"""

from __future__ import annotations

from conftest import NoopGate
from mig.core.context import DefaultScanContext, ScanContext
from mig.core.protocols import Gate, Sandbox, Source, TrustedStore
from mig.sandbox.noop import NoopSandbox
from mig.storage.quarantine import Quarantine


def test_noop_gate_satisfies_gate_protocol(noop_gate: NoopGate) -> None:
    assert isinstance(noop_gate, Gate)


def test_noop_sandbox_satisfies_sandbox_protocol() -> None:
    assert isinstance(NoopSandbox(), Sandbox)


def test_default_context_satisfies_scancontext_protocol(
    ctx: DefaultScanContext,
) -> None:
    assert isinstance(ctx, ScanContext)


def test_noop_gate_is_not_a_source_or_store(noop_gate: NoopGate) -> None:
    # Distinct seams must not accidentally collapse into one another.
    assert not isinstance(noop_gate, Source)
    assert not isinstance(noop_gate, TrustedStore)


def test_quarantine_is_not_a_trusted_store() -> None:
    # I6: the quarantine area is not write-capable trusted storage.
    assert not isinstance(Quarantine(root="/tmp/q"), TrustedStore)


def test_noop_gate_evaluate_returns_passing_result(
    noop_gate: NoopGate,
    model_artifact: object,
    ctx: DefaultScanContext,
) -> None:
    from mig.core.artifact import Artifact
    from mig.core.verdict import GateStatus

    assert isinstance(model_artifact, Artifact)
    result = noop_gate.evaluate(model_artifact, ctx)
    assert result.status is GateStatus.PASS
    assert result.scanner_name == "noop-gate"
