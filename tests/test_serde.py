"""PR1 acceptance: the contract models serialize round-trip."""

from __future__ import annotations

import json

from conftest import make_ref
from mig.core.artifact import Artifact, ArtifactType
from mig.core.serde import (
    artifact_from_dict,
    attestation_from_dict,
    finding_from_dict,
    gate_result_from_dict,
    to_json,
    to_jsonable,
    verdict_from_dict,
    verdict_from_json,
)
from mig.core.verdict import (
    Decision,
    Finding,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
    Verdict,
)
from mig.evidence.attestation import Attestation


def _sample_verdict() -> Verdict:
    finding = Finding(
        gate_id="serialization_safety",
        severity=Severity.CRITICAL,
        code="unsafe_pickle_opcode",
        message="GLOBAL opcode references os.system",
        location="weights.bin:128",
        metadata={"opcode": "GLOBAL"},
    )
    behavioral = GateResult(
        gate_id="behavioral",
        status=GateStatus.SKIPPED,
        rigor=RigorLevel.NONE,
        findings=[
            Finding(
                gate_id="behavioral",
                severity=Severity.HIGH,
                code="behavioral_analysis_skipped",
                message="NoopSandbox: no dynamic analysis performed",
            )
        ],
        scanner_name="noop",
    )
    serialization = GateResult(
        gate_id="serialization_safety",
        status=GateStatus.FAIL,
        rigor=RigorLevel.STATIC,
        findings=[finding],
        scanner_name="picklescan",
        scanner_version="0.0.0",
        duration_ms=12,
        evidence={"opcodes_scanned": 4096},
    )
    return Verdict(
        ref=make_ref(),
        artifact_type=ArtifactType.MODEL,
        gate_results=[serialization, behavioral],
        decision=Decision.REJECT,
        advisory_score=10,
    )


def test_verdict_round_trips_through_dict() -> None:
    original = _sample_verdict()
    restored = verdict_from_dict(to_jsonable(original))
    assert restored == original


def test_verdict_round_trips_through_json() -> None:
    original = _sample_verdict()
    restored = verdict_from_json(to_json(original))
    assert restored == original


def test_to_jsonable_is_pure_json_primitives() -> None:
    blob = to_jsonable(_sample_verdict())
    # Must encode to JSON without a custom encoder (enums became their values).
    text = json.dumps(blob)
    assert '"decision": "reject"' in text
    assert '"severity": 4' in text  # Severity.CRITICAL.value


def test_attestation_round_trips() -> None:
    verdict = _sample_verdict()
    attestation = Attestation(
        ref=verdict.ref,
        digest="sha256:abc",
        artifact_type=ArtifactType.MODEL,
        decision=verdict.decision,
        gate_summary=list(verdict.gate_results),
        overall_rigor=RigorLevel.STATIC,
        confinement_level="noop",
        policy_id="model-ingestion",
        policy_version="1",
        mig_version="0.1.0.dev0",
        created_at="2026-06-21T00:00:00Z",
    )
    restored = attestation_from_dict(to_jsonable(attestation))
    assert restored == attestation
    # I5: the attestation must carry rigor + per-gate scanner versions.
    assert restored.overall_rigor is RigorLevel.STATIC
    assert any(g.scanner_name == "picklescan" for g in restored.gate_summary)


# --------------------------------------------------------------------------- #
# Per-type round trips (the acceptance bar is "models serialize round-trip")
# --------------------------------------------------------------------------- #


def test_artifact_round_trips() -> None:
    artifact = Artifact(
        ref=make_ref(),
        artifact_type=ArtifactType.MODEL,
        quarantine_path="/q/model",
        files=["model.safetensors", "config.json"],
        metadata={"library": "transformers", "params": 7_000_000_000},
        digest="sha256:abc",
    )
    assert artifact_from_dict(to_jsonable(artifact)) == artifact


def test_artifact_round_trips_with_no_digest_and_empty_collections() -> None:
    artifact = Artifact(
        ref=make_ref(revision=None, expected_digest=None),
        artifact_type=ArtifactType.DATASET,
        quarantine_path="/q/ds",
    )
    assert artifact_from_dict(to_jsonable(artifact)) == artifact


def test_finding_round_trips_with_and_without_optionals() -> None:
    rich = Finding(
        gate_id="secrets",
        severity=Severity.HIGH,
        code="aws_access_key",
        message="found an AWS key",
        location="train.py:10",
        metadata={"entropy": 4.2},
    )
    bare = Finding(gate_id="x", severity=Severity.INFO, code="c", message="m")
    assert finding_from_dict(to_jsonable(rich)) == rich
    assert finding_from_dict(to_jsonable(bare)) == bare


def test_gate_result_round_trips_including_all_none_optionals() -> None:
    result = GateResult(
        gate_id="serialization_safety",
        status=GateStatus.WARN,
        rigor=RigorLevel.STATIC,
        findings=[Finding("g", Severity.LOW, "c", "m")],
        scanner_name="modelscan",
        scanner_version="0.8.0",
        duration_ms=7,
        evidence={"files": 3},
    )
    minimal = GateResult(gate_id="g", status=GateStatus.SKIPPED, rigor=RigorLevel.NONE)
    assert gate_result_from_dict(to_jsonable(result)) == result
    assert gate_result_from_dict(to_jsonable(minimal)) == minimal


def test_round_trip_is_total_for_tuple_inputs() -> None:
    # Sequence fields may be built with tuples; round-trip must still be equal
    # because construction normalises to a canonical concrete type (list).
    artifact = Artifact(
        ref=make_ref(),
        artifact_type=ArtifactType.MODEL,
        quarantine_path="/q",
        files=("a.safetensors", "b.json"),
    )
    assert artifact_from_dict(to_jsonable(artifact)) == artifact

    verdict = Verdict(
        ref=make_ref(),
        artifact_type=ArtifactType.MODEL,
        gate_results=(
            GateResult("g", GateStatus.PASS, RigorLevel.STATIC, scanner_name="s"),
        ),
        decision=Decision.APPROVE,
    )
    assert verdict_from_dict(to_jsonable(verdict)) == verdict
