"""The structural seams MIG composes around (PRD §5).

Everything pluggable — sources, gates, sandboxes, trusted stores — is a
:class:`typing.Protocol`. Implementations live in adapter packages and need not
inherit from anything; they only have to match the shape. The protocols are
``runtime_checkable`` so tests (and the registry) can assert conformance, but
static conformance via a type checker is the primary guarantee.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from mig.core.artifact import Artifact, ArtifactRef, ArtifactType
from mig.core.verdict import GateCost, GateResult, RigorLevel

if TYPE_CHECKING:
    from mig.core.context import ScanContext
    from mig.evidence.attestation import Attestation
    from mig.sandbox.spec import SandboxObservation, SandboxSpec
    from mig.storage.quarantine import Quarantine


@runtime_checkable
class Gate(Protocol):
    """A single pipeline stage producing a :class:`GateResult`.

    ``cost`` drives ordering (CHEAP → MEDIUM → EXPENSIVE); ``applies_to`` gates
    applicability — a gate runs only when ``artifact.artifact_type`` is in the
    set. Static gates MUST NOT import/exec/deserialize the artifact (I1).
    """

    id: str
    cost: GateCost
    applies_to: frozenset[ArtifactType]

    def evaluate(self, artifact: Artifact, ctx: ScanContext) -> GateResult: ...


@runtime_checkable
class Source(Protocol):
    """Fetches an artifact reference into quarantine.

    Implementations MUST pin and verify the expected digest / commit SHA at
    fetch time and land bytes in quarantine, never a shared temp dir (I3).
    """

    scheme: str

    def fetch(self, ref: ArtifactRef, quarantine: Quarantine) -> Artifact: ...


@runtime_checkable
class Sandbox(Protocol):
    """Detonates an artifact under confinement and reports what it observed.

    The default implementation is :class:`~mig.sandbox.noop.NoopSandbox`, whose
    ``rigor`` is ``NONE`` and which yields a loud ``SKIPPED`` result (I7).
    """

    rigor: RigorLevel

    def detonate(
        self,
        artifact: Artifact,
        spec: SandboxSpec,
        ctx: ScanContext,
    ) -> SandboxObservation: ...


@runtime_checkable
class TrustedStore(Protocol):
    """Write access to the trusted store — used ONLY by ``promote()`` (I6).

    This protocol is intentionally never referenced from the ``ingest()`` path.
    Promotion is a separate, gated call introduced in PR8.
    """

    def promote(self, artifact: Artifact, attestation: Attestation) -> str: ...
