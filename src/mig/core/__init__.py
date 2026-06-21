"""Core domain model and seams (PRD §5/§6).

Pure types + protocols + minimal orchestration helpers. No artifact is ever
imported, exec'd or deserialized here (invariant I1) — this package only
*describes* and *classifies*.
"""

from __future__ import annotations

from mig.core.artifact import (
    EXECUTABLE_ARTIFACT_TYPES,
    Artifact,
    ArtifactRef,
    ArtifactType,
)
from mig.core.context import DefaultScanContext, ScanContext, make_context
from mig.core.pipeline import COST_ORDER, order_gates, run_pipeline
from mig.core.protocols import Gate, Sandbox, Source, TrustedStore
from mig.core.verdict import (
    Decision,
    Finding,
    GateCost,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
    Verdict,
    rigor_rank,
)

__all__ = [
    "Artifact",
    "ArtifactRef",
    "ArtifactType",
    "EXECUTABLE_ARTIFACT_TYPES",
    "Verdict",
    "GateResult",
    "Finding",
    "Severity",
    "GateStatus",
    "RigorLevel",
    "GateCost",
    "Decision",
    "rigor_rank",
    "Gate",
    "Source",
    "Sandbox",
    "TrustedStore",
    "ScanContext",
    "DefaultScanContext",
    "make_context",
    "run_pipeline",
    "order_gates",
    "COST_ORDER",
]
