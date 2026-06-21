"""MIG — Model Ingestion Gateway.

A pure-Python, embeddable core that vets AI artifacts **before** they enter
trusted infrastructure. The public surface here is the stable contract from
PRD §5: the domain types, the pluggable seams (protocols), the default
:class:`NoopSandbox`, and the :class:`Attestation`.

The system is *decision-only* — :func:`run_pipeline` computes a categorical
verdict; writing to a trusted store is a separate, deliberately-late, gated
call (invariant I6, PR8).
"""

from __future__ import annotations

#: Single source of truth for the version (read by hatchling at build time).
__version__ = "0.1.0.dev0"

from mig.core.artifact import (
    EXECUTABLE_ARTIFACT_TYPES,
    Artifact,
    ArtifactRef,
    ArtifactType,
)
from mig.core.context import DefaultScanContext, ScanContext, make_context
from mig.core.pipeline import order_gates, run_pipeline
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
)
from mig.evidence.attestation import Attestation
from mig.sandbox.noop import NoopSandbox
from mig.sandbox.spec import SandboxObservation, SandboxSpec

__all__ = [
    "__version__",
    # artifact
    "Artifact",
    "ArtifactRef",
    "ArtifactType",
    "EXECUTABLE_ARTIFACT_TYPES",
    # verdict
    "Verdict",
    "GateResult",
    "Finding",
    "Severity",
    "GateStatus",
    "RigorLevel",
    "GateCost",
    "Decision",
    # seams
    "Gate",
    "Source",
    "Sandbox",
    "TrustedStore",
    "ScanContext",
    "DefaultScanContext",
    "make_context",
    # sandbox
    "NoopSandbox",
    "SandboxSpec",
    "SandboxObservation",
    # pipeline
    "run_pipeline",
    "order_gates",
    # evidence
    "Attestation",
]
