"""The built-in default decision is categorical and enforces I8/I9."""

from __future__ import annotations

from conftest import make_artifact
from mig.core.artifact import ArtifactType
from mig.core.verdict import Decision, GateResult, GateStatus, RigorLevel
from mig.policy.engine import default_decision


def _result(
    status: GateStatus,
    rigor: RigorLevel = RigorLevel.STATIC,
    gate_id: str = "g",
) -> GateResult:
    return GateResult(
        gate_id=gate_id,
        status=status,
        rigor=rigor,
        scanner_name="s",
        scanner_version="1",
    )


def _skipped_behavioral() -> GateResult:
    return GateResult(
        gate_id="behavioral", status=GateStatus.SKIPPED, rigor=RigorLevel.NONE
    )


def test_clean_model_approves() -> None:
    artifact = make_artifact(ArtifactType.MODEL)
    results = [_result(GateStatus.PASS), _skipped_behavioral()]
    assert default_decision(artifact, results) is Decision.APPROVE


def test_any_fail_rejects() -> None:
    artifact = make_artifact(ArtifactType.MODEL)
    assert default_decision(artifact, [_result(GateStatus.FAIL)]) is Decision.REJECT


def test_warn_requires_review() -> None:  # I9: warn → review, never auto-reject
    artifact = make_artifact(ArtifactType.MODEL)
    assert (
        default_decision(artifact, [_result(GateStatus.WARN)]) is Decision.REVIEW_REQUIRED
    )


def test_error_requires_review() -> None:
    artifact = make_artifact(ArtifactType.MODEL)
    assert (
        default_decision(artifact, [_result(GateStatus.ERROR, RigorLevel.NONE)])
        is Decision.REVIEW_REQUIRED
    )


def test_executable_type_never_approves_static_only() -> None:  # I8 / QS-2
    artifact = make_artifact(ArtifactType.MCP_SERVER)
    results = [_result(GateStatus.PASS), _skipped_behavioral()]
    assert default_decision(artifact, results) is Decision.REVIEW_REQUIRED


def test_executable_type_can_approve_with_behavioral_rigor() -> None:
    artifact = make_artifact(ArtifactType.MCP_SERVER)
    results = [
        _result(GateStatus.PASS),
        _result(GateStatus.PASS, RigorLevel.BEHAVIORAL, "behavioral"),
    ]
    assert default_decision(artifact, results) is Decision.APPROVE
