"""Verdict summary helpers carry no decision logic — they only summarise."""

from __future__ import annotations

from conftest import make_ref
from mig.core.artifact import ArtifactType
from mig.core.verdict import (
    Decision,
    Finding,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
    Verdict,
    rigor_rank,
)


def _verdict(
    *results: GateResult, decision: Decision = Decision.REVIEW_REQUIRED
) -> Verdict:
    return Verdict(
        ref=make_ref(),
        artifact_type=ArtifactType.MODEL,
        gate_results=list(results),
        decision=decision,
    )


def _result(
    status: GateStatus,
    rigor: RigorLevel,
    *findings: Finding,
    gate_id: str = "g",
) -> GateResult:
    return GateResult(
        gate_id=gate_id, status=status, rigor=rigor, findings=list(findings)
    )


def test_rigor_rank_total_order() -> None:
    assert rigor_rank(RigorLevel.NONE) < rigor_rank(RigorLevel.STATIC)
    assert rigor_rank(RigorLevel.STATIC) < rigor_rank(RigorLevel.BEHAVIORAL)


def test_highest_severity_none_when_clean() -> None:
    verdict = _verdict(_result(GateStatus.PASS, RigorLevel.STATIC))
    assert verdict.highest_severity() is None


def test_highest_severity_picks_max() -> None:
    verdict = _verdict(
        _result(
            GateStatus.WARN,
            RigorLevel.STATIC,
            Finding("g", Severity.LOW, "a", "a"),
            Finding("g", Severity.HIGH, "b", "b"),
        ),
        _result(
            GateStatus.FAIL,
            RigorLevel.STATIC,
            Finding("g", Severity.MEDIUM, "c", "c"),
        ),
    )
    assert verdict.highest_severity() is Severity.HIGH


def test_rigor_summary_ignores_skipped() -> None:
    # A run that only reached NoopSandbox (SKIPPED/NONE) summarises as STATIC,
    # never BEHAVIORAL — honest attestation (I5).
    verdict = _verdict(
        _result(GateStatus.PASS, RigorLevel.STATIC),
        _result(GateStatus.SKIPPED, RigorLevel.NONE, gate_id="behavioral"),
    )
    assert verdict.rigor_summary() is RigorLevel.STATIC
    assert verdict.behavioral_ran() is False


def test_rigor_summary_none_when_nothing_executed() -> None:
    verdict = _verdict(_result(GateStatus.SKIPPED, RigorLevel.NONE))
    assert verdict.rigor_summary() is RigorLevel.NONE


def test_behavioral_ran_true_only_when_executed_behaviorally() -> None:
    verdict = _verdict(
        _result(GateStatus.PASS, RigorLevel.BEHAVIORAL, gate_id="behavioral"),
    )
    assert verdict.behavioral_ran() is True
    assert verdict.rigor_summary() is RigorLevel.BEHAVIORAL


def test_gates_by_status_groups() -> None:
    pass_result = _result(GateStatus.PASS, RigorLevel.STATIC, gate_id="a")
    fail_result = _result(GateStatus.FAIL, RigorLevel.STATIC, gate_id="b")
    verdict = _verdict(pass_result, fail_result)
    grouped = verdict.gates_by_status()
    assert grouped[GateStatus.PASS] == [pass_result]
    assert grouped[GateStatus.FAIL] == [fail_result]
