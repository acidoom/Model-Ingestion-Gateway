"""I7: the default sandbox is a *loud* no-op."""

from __future__ import annotations

from conftest import make_artifact
from mig.core.context import DefaultScanContext
from mig.core.verdict import GateStatus, RigorLevel, Severity
from mig.sandbox.base import observation_to_result
from mig.sandbox.noop import BEHAVIORAL_SKIPPED_CODE, NoopSandbox
from mig.sandbox.spec import SandboxSpec


def test_noop_sandbox_rigor_is_none() -> None:
    assert NoopSandbox().rigor is RigorLevel.NONE


def test_noop_detonate_is_loud_skipped(ctx: DefaultScanContext) -> None:
    observation = NoopSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    assert observation.status is GateStatus.SKIPPED
    assert observation.rigor is RigorLevel.NONE
    # "Loud": at least one HIGH-or-greater finding explaining the skip.
    assert observation.findings, "NoopSandbox must emit a finding, not silence"
    skip = observation.findings[0]
    assert skip.code == BEHAVIORAL_SKIPPED_CODE
    assert skip.severity is Severity.HIGH
    assert "SKIPPED" in skip.message


def test_noop_observation_cannot_be_laundered_into_a_behavioral_pass(
    ctx: DefaultScanContext,
) -> None:
    observation = NoopSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    result = observation_to_result(observation, scanner_name="noop")
    # The folded gate result preserves SKIPPED/NONE — no behavioral rigor.
    assert result.status is GateStatus.SKIPPED
    assert result.rigor is RigorLevel.NONE


def test_default_context_uses_noop_sandbox(ctx: DefaultScanContext) -> None:
    assert isinstance(ctx.sandbox, NoopSandbox)


def test_noop_confinement_level_is_noop() -> None:
    # I5/I7: the noop confinement identifies itself honestly, so an attestation
    # can never present it as "docker"/"gvisor".
    assert NoopSandbox().confinement_level == "noop"


def test_default_context_exposes_config_mapping(ctx: DefaultScanContext) -> None:
    # §5 seam: a gate can read run-level config off the context.
    from collections.abc import Mapping

    assert isinstance(ctx.config, Mapping)
