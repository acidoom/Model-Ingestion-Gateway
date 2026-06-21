"""(De)serialisation for the core contract types.

The generic :func:`to_jsonable` encoder turns any dataclass/enum graph into
JSON-safe primitives. Decoding is *typed* — explicit ``*_from_dict`` builders
reconstruct each contract type — because round-tripping a security artifact
should reconstruct the exact declared shape, not best-guess from untyped data.

This underpins the PR1 acceptance criterion ("models serialize round-trip") and
the JSON report emitted by ``mig scan`` (PR2).
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping
from enum import Enum
from typing import Any

from mig.core.artifact import Artifact, ArtifactRef, ArtifactType
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

# --------------------------------------------------------------------------- #
# Encoding
# --------------------------------------------------------------------------- #


def to_jsonable(obj: Any) -> Any:
    """Recursively convert a dataclass/enum graph into JSON-safe primitives.

    Enums become their ``.value``; dataclasses become dicts; mappings and
    (non-str) sequences recurse; primitives pass through unchanged.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {
            f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)
        }
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Mapping):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


def to_json(obj: Any, *, indent: int | None = 2) -> str:
    """Encode ``obj`` to a JSON string via :func:`to_jsonable`."""
    return json.dumps(to_jsonable(obj), indent=indent, sort_keys=False)


# --------------------------------------------------------------------------- #
# Decoding (typed)
# --------------------------------------------------------------------------- #


def artifact_ref_from_dict(data: Mapping[str, Any]) -> ArtifactRef:
    return ArtifactRef(
        scheme=data["scheme"],
        locator=data["locator"],
        revision=data.get("revision"),
        expected_digest=data.get("expected_digest"),
    )


def artifact_from_dict(data: Mapping[str, Any]) -> Artifact:
    return Artifact(
        ref=artifact_ref_from_dict(data["ref"]),
        artifact_type=ArtifactType(data["artifact_type"]),
        quarantine_path=data["quarantine_path"],
        files=list(data.get("files", [])),
        metadata=dict(data.get("metadata", {})),
        digest=data.get("digest"),
    )


def finding_from_dict(data: Mapping[str, Any]) -> Finding:
    return Finding(
        gate_id=data["gate_id"],
        severity=Severity(data["severity"]),
        code=data["code"],
        message=data["message"],
        location=data.get("location"),
        metadata=dict(data.get("metadata", {})),
    )


def gate_result_from_dict(data: Mapping[str, Any]) -> GateResult:
    return GateResult(
        gate_id=data["gate_id"],
        status=GateStatus(data["status"]),
        rigor=RigorLevel(data["rigor"]),
        findings=[finding_from_dict(f) for f in data.get("findings", [])],
        scanner_name=data.get("scanner_name"),
        scanner_version=data.get("scanner_version"),
        duration_ms=data.get("duration_ms"),
        evidence=dict(data.get("evidence", {})),
    )


def verdict_from_dict(data: Mapping[str, Any]) -> Verdict:
    return Verdict(
        ref=artifact_ref_from_dict(data["ref"]),
        artifact_type=ArtifactType(data["artifact_type"]),
        gate_results=[gate_result_from_dict(g) for g in data.get("gate_results", [])],
        decision=Decision(data["decision"]),
        advisory_score=data.get("advisory_score"),
    )


def attestation_from_dict(data: Mapping[str, Any]) -> Attestation:
    return Attestation(
        ref=artifact_ref_from_dict(data["ref"]),
        digest=data["digest"],
        artifact_type=ArtifactType(data["artifact_type"]),
        decision=Decision(data["decision"]),
        gate_summary=[gate_result_from_dict(g) for g in data.get("gate_summary", [])],
        overall_rigor=RigorLevel(data["overall_rigor"]),
        confinement_level=data["confinement_level"],
        policy_id=data["policy_id"],
        policy_version=data["policy_version"],
        mig_version=data["mig_version"],
        created_at=data["created_at"],
        signature=data.get("signature"),
        predicate_type=data.get("predicate_type"),
        metadata=dict(data.get("metadata", {})),
    )


def verdict_from_json(text: str) -> Verdict:
    """Parse a JSON string produced by ``to_json(verdict)`` back into a Verdict."""
    parsed: Any = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("expected a JSON object for a Verdict")
    return verdict_from_dict(parsed)
