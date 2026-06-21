"""Shared test fixtures and the protocol test-doubles.

``NoopGate`` exists to satisfy the PR1 acceptance criterion: a no-op
:class:`~mig.core.protocols.Gate` that compiles against the protocol (statically
via mypy and structurally via ``isinstance``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

import pytest

from mig.core.artifact import Artifact, ArtifactRef, ArtifactType
from mig.core.context import DefaultScanContext, make_context
from mig.core.verdict import (
    GateCost,
    GateResult,
    GateStatus,
    RigorLevel,
)
from mig.policy.schema import Policy
from mig.storage.quarantine import Quarantine


@dataclass
class NoopGate:
    """A minimal :class:`~mig.core.protocols.Gate` test double — always PASS."""

    id: str = "noop"
    cost: GateCost = GateCost.CHEAP
    applies_to: frozenset[ArtifactType] = field(
        default_factory=lambda: frozenset(ArtifactType)
    )

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        return GateResult(
            gate_id=self.id,
            status=GateStatus.PASS,
            rigor=RigorLevel.STATIC,
            scanner_name="noop-gate",
            scanner_version="0",
        )


def make_ref(
    scheme: str = "local",
    locator: str = "/tmp/fixtures/model",
    revision: str | None = "deadbeef",
    expected_digest: str | None = "sha256:00",
) -> ArtifactRef:
    return ArtifactRef(
        scheme=scheme,
        locator=locator,
        revision=revision,
        expected_digest=expected_digest,
    )


def make_artifact(
    artifact_type: ArtifactType = ArtifactType.MODEL,
    *,
    files: list[str] | None = None,
    metadata: Mapping[str, object] | None = None,
) -> Artifact:
    return Artifact(
        ref=make_ref(),
        artifact_type=artifact_type,
        quarantine_path="/tmp/quarantine/model",
        files=list(files or ["model.safetensors", "config.json"]),
        metadata=dict(metadata or {}),
        digest="sha256:00",
    )


@pytest.fixture
def noop_gate() -> NoopGate:
    return NoopGate()


@pytest.fixture
def ref() -> ArtifactRef:
    return make_ref()


@pytest.fixture
def model_artifact() -> Artifact:
    return make_artifact(ArtifactType.MODEL)


@pytest.fixture
def mcp_artifact() -> Artifact:
    return make_artifact(ArtifactType.MCP_SERVER)


@pytest.fixture
def ctx() -> DefaultScanContext:
    return make_context(
        policy=Policy(id="test-policy", version="1"),
        quarantine=Quarantine(root="/tmp/quarantine"),
    )
