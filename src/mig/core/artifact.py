"""Artifact identity and in-flight representation.

These types describe *what* is being vetted. They carry no decision logic —
that lives in :mod:`mig.policy`. See PRD §5.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum


class ArtifactType(Enum):
    """The kind of artifact under inspection.

    The distinction matters because vetting is *type-aware* (invariant I4):
    a ``MODEL`` and an ``MCP_SERVER`` carry incompatible risk profiles and
    must never receive a uniform "approved" stamp.
    """

    MODEL = "model"
    ADAPTER = "adapter"
    DATASET = "dataset"
    TOKENIZER = "tokenizer"
    EMBEDDING_MODEL = "embedding_model"
    AGENT_SKILL = "agent_skill"
    MCP_SERVER = "mcp_server"
    PYTHON_PACKAGE = "python_package"
    NPM_PACKAGE = "npm_package"
    CONTAINER_IMAGE = "container_image"
    NOTEBOOK = "notebook"
    PROMPT_TEMPLATE = "prompt_template"
    EVAL_SET = "eval_set"


#: Artifact types that execute code when loaded/run. Per invariant I8 these
#: MUST NOT receive an ``APPROVE`` decision at static-only rigor — policy must
#: require behavioral rigor or return ``REVIEW_REQUIRED``. Single source of
#: truth, consumed by the policy engine (PR5).
EXECUTABLE_ARTIFACT_TYPES: frozenset[ArtifactType] = frozenset(
    {
        ArtifactType.MCP_SERVER,
        ArtifactType.PYTHON_PACKAGE,
        ArtifactType.NPM_PACKAGE,
        ArtifactType.NOTEBOOK,
        ArtifactType.CONTAINER_IMAGE,
    }
)


@dataclass(frozen=True)
class ArtifactRef:
    """A pinned, content-addressable reference to an artifact.

    ``revision`` and ``expected_digest`` are how invariant I3 is honoured:
    a :class:`~mig.core.protocols.Source` MUST verify the expected digest /
    commit SHA *at fetch time*.
    """

    scheme: str  # "huggingface", "local", "github", ...
    locator: str  # repo id / path
    revision: str | None = None  # commit SHA / tag — pinned at fetch
    expected_digest: str | None = None


@dataclass
class Artifact:
    """An artifact-in-flight: bytes that have landed in quarantine.

    Construction of this object means the bytes are already isolated in a
    quarantine area (I3) — never a shared temp dir.
    """

    ref: ArtifactRef
    artifact_type: ArtifactType
    quarantine_path: str
    files: Sequence[str] = field(default_factory=list)
    metadata: Mapping[str, object] = field(default_factory=dict)
    digest: str | None = None  # computed via streaming/chunked hashing (I3, QS-4)

    def __post_init__(self) -> None:
        # Normalise collection fields to canonical concrete types so that
        # serialise → deserialise is a *total* round-trip: a caller may pass any
        # Sequence (incl. a tuple) or non-dict Mapping, but the stored form — and
        # therefore equality after a round-trip — is always list/dict.
        self.files = list(self.files)
        self.metadata = dict(self.metadata)

    @property
    def is_executable_type(self) -> bool:
        """True if loading/running this artifact executes code (I8)."""
        return self.artifact_type in EXECUTABLE_ARTIFACT_TYPES
