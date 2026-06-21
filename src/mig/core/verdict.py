"""Verdict, gate results, findings and the enums that classify them.

The decision model is *categorical and type-aware* (invariant I4): the verdict
is a :class:`Decision` enum derived by policy, never a bare boolean and never a
numeric-score threshold. ``advisory_score`` exists only as a UX field.

The helper methods on :class:`Verdict` summarise gate results; they contain **no
decision logic** — deriving a :class:`Decision` is the sole job of the policy
engine (PR5).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .artifact import ArtifactRef, ArtifactType


class Severity(Enum):
    """How serious an individual :class:`Finding` is.

    Integer values give a natural ordering for *summarising* findings (e.g.
    ``highest_severity``); they are deliberately **not** a decision basis (I4).
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class GateStatus(Enum):
    """Outcome of a single gate.

    ``SKIPPED`` is load-bearing: the default :class:`~mig.sandbox.noop.NoopSandbox`
    emits a *loud* SKIPPED behavioral result (I7) so callers cannot mistake
    "not run" for "passed".
    """

    PASS = "pass"  # noqa: S105 — gate status, not a password (bandit false positive)
    WARN = "warn"
    FAIL = "fail"
    SKIPPED = "skipped"
    ERROR = "error"


class RigorLevel(Enum):
    """How deep inspection went for a gate, or overall."""

    NONE = "none"
    STATIC = "static"
    BEHAVIORAL = "behavioral"


class GateCost(Enum):
    """Relative cost class — the pipeline runs CHEAP → MEDIUM → EXPENSIVE."""

    CHEAP = "cheap"
    MEDIUM = "medium"
    EXPENSIVE = "expensive"


class Decision(Enum):
    """The categorical verdict (I4). Derived by policy, never a bare bool."""

    APPROVE = "approve"
    REJECT = "reject"
    REVIEW_REQUIRED = "review_required"


#: Statuses that mean a gate *actually executed* (as opposed to being skipped
#: or erroring out). Used when summarising achieved rigor and when checking
#: per-gate attribution for an attestation (I5).
EXECUTED_STATUSES: frozenset[GateStatus] = frozenset(
    {GateStatus.PASS, GateStatus.WARN, GateStatus.FAIL}
)
#: Backwards-compatible private alias.
_EXECUTED_STATUSES = EXECUTED_STATUSES

#: Total order over rigor levels, for ``max``-style summaries.
_RIGOR_RANK: Mapping[RigorLevel, int] = {
    RigorLevel.NONE: 0,
    RigorLevel.STATIC: 1,
    RigorLevel.BEHAVIORAL: 2,
}


def rigor_rank(rigor: RigorLevel) -> int:
    """Ordinal rank of a rigor level (``NONE`` < ``STATIC`` < ``BEHAVIORAL``)."""
    return _RIGOR_RANK[rigor]


@dataclass(frozen=True)
class Finding:
    """A single observation produced by a gate.

    ``code`` is a *stable machine code* (e.g. ``"unsafe_pickle_opcode"``) — the
    contract downstream tooling matches on. ``message`` is human-facing.

    Note: ``Finding`` is frozen for value-equality but is **intentionally not
    hashable** — its ``metadata`` is a mutable mapping, so ``hash(finding)``
    raises. Deduplicate findings by ``(gate_id, code, location)``, not by
    putting ``Finding`` objects in a set.
    """

    gate_id: str
    severity: Severity
    code: str
    message: str
    location: str | None = None  # file[:offset]
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # frozen → object.__setattr__; normalise metadata so round-trips are total.
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass
class GateResult:
    """The result of running one gate against one artifact.

    Records ``scanner_name``/``scanner_version`` so the attestation can encode
    *which scanner at what version* produced each result (I5).
    """

    gate_id: str
    status: GateStatus
    rigor: RigorLevel
    findings: Sequence[Finding] = field(default_factory=list)
    scanner_name: str | None = None
    scanner_version: str | None = None
    duration_ms: int | None = None
    evidence: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Canonicalise collections so serialise → deserialise is total (I5/serde).
        self.findings = list(self.findings)
        self.evidence = dict(self.evidence)


@dataclass
class Verdict:
    """The aggregate outcome for an artifact.

    ``decision`` is categorical and derived by policy (I4). ``advisory_score``
    is **UX only** and MUST NOT be the basis of any decision.

    The helper methods summarise gate results without making decisions.
    """

    ref: ArtifactRef
    artifact_type: ArtifactType
    gate_results: Sequence[GateResult]
    decision: Decision
    advisory_score: int | None = None  # UX ONLY (I4) — never the decision basis

    def __post_init__(self) -> None:
        self.gate_results = list(self.gate_results)

    # -- summaries (no decision logic) -------------------------------------

    def highest_severity(self) -> Severity | None:
        """The most severe finding across all gates, or ``None`` if clean."""
        severities = [
            finding.severity
            for result in self.gate_results
            for finding in result.findings
        ]
        if not severities:
            return None
        return max(severities, key=lambda sev: sev.value)

    def rigor_summary(self) -> RigorLevel:
        """The highest rigor level *actually achieved* by an executed gate.

        Skipped/errored gates do not contribute — a run that only ever reached
        :class:`~mig.sandbox.noop.NoopSandbox` summarises as ``STATIC`` (or
        ``NONE``), never ``BEHAVIORAL`` (supports honest attestation, I5).
        """
        achieved = [
            result.rigor
            for result in self.gate_results
            if result.status in _EXECUTED_STATUSES
        ]
        if not achieved:
            return RigorLevel.NONE
        return max(achieved, key=rigor_rank)

    def behavioral_ran(self) -> bool:
        """True iff a gate actually executed at ``BEHAVIORAL`` rigor.

        ``NoopSandbox`` yields ``SKIPPED`` at ``NONE`` rigor, so this returns
        ``False`` for the default configuration — the signal policy uses to
        enforce I8 (executable types cannot be approved static-only).
        """
        return any(
            result.rigor is RigorLevel.BEHAVIORAL and result.status in _EXECUTED_STATUSES
            for result in self.gate_results
        )

    def gates_by_status(self) -> Mapping[GateStatus, Sequence[GateResult]]:
        """Group gate results by their :class:`GateStatus`."""
        grouped: dict[GateStatus, list[GateResult]] = {}
        for result in self.gate_results:
            grouped.setdefault(result.status, []).append(result)
        return grouped
