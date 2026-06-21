"""The embedded decision engine (PRD §8, ADR-002/003).

Two layers, both **categorical** (I4 — never a numeric score threshold):

1. **Safety baseline** (:func:`default_decision`) — load-bearing and always
   applied: a ``FAIL`` rejects, an ``ERROR`` requires review, an executable type
   without behavioral rigor cannot be approved (I8), a ``WARN`` requires review
   (I9). This is a *floor*: a declarative policy can escalate it but never
   downgrade it (a permissive policy cannot approve a failing artifact).

2. **Declarative rules** (:func:`matched_rules`) — organisation-specific
   categorical rules from a YAML/JSON policy, AND-combined per rule.

:func:`evaluate` returns the most-severe of the two. The embedded engine owns
the *ingest* decision; OPA owns *promotion*-time enforcement over the signed
attestation (ADR-003) — a deferred seam.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass

from mig.core.artifact import Artifact
from mig.core.verdict import (
    EXECUTED_STATUSES,
    Decision,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
    rigor_rank,
)
from mig.policy.schema import Policy, PolicyAction, PolicyError, PolicyRule

#: Total order over decisions, so the baseline acts as a non-downgradable floor.
_DECISION_RANK = {Decision.APPROVE: 0, Decision.REVIEW_REQUIRED: 1, Decision.REJECT: 2}
_SEVERITY_BY_NAME = {sev.name.lower(): sev for sev in Severity}
_RIGOR_BY_NAME = {lvl.value: lvl for lvl in RigorLevel}


def _behavioral_ran(gate_results: Sequence[GateResult]) -> bool:
    return any(
        result.rigor is RigorLevel.BEHAVIORAL and result.status in EXECUTED_STATUSES
        for result in gate_results
    )


def default_decision(artifact: Artifact, gate_results: Sequence[GateResult]) -> Decision:
    """The built-in categorical safety baseline (I4/I8/I9). See module docstring."""
    statuses = {result.status for result in gate_results}

    if GateStatus.FAIL in statuses:
        return Decision.REJECT
    if GateStatus.ERROR in statuses:
        return Decision.REVIEW_REQUIRED
    if artifact.is_executable_type and not _behavioral_ran(gate_results):
        return Decision.REVIEW_REQUIRED  # I8 / ADR-001
    if GateStatus.WARN in statuses:
        return Decision.REVIEW_REQUIRED  # I9: warn → review, never auto-reject
    return Decision.APPROVE


# --------------------------------------------------------------------------- #
# Declarative rule matching
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _MatchContext:
    artifact_type: str
    extensions: frozenset[str]
    formats: frozenset[str]
    finding_codes: frozenset[str]
    max_severity: Severity | None
    rigor: RigorLevel
    failed_gates: frozenset[str]


def _build_context(
    artifact: Artifact, gate_results: Sequence[GateResult]
) -> _MatchContext:
    extensions = {os.path.splitext(f)[1].lower() for f in artifact.files}
    findings = [fnd for result in gate_results for fnd in result.findings]
    severities = [fnd.severity for fnd in findings]
    executed = [r.rigor for r in gate_results if r.status in EXECUTED_STATUSES]
    return _MatchContext(
        artifact_type=artifact.artifact_type.value,
        extensions=frozenset(extensions),
        formats=frozenset(ext.lstrip(".") for ext in extensions),
        finding_codes=frozenset(fnd.code for fnd in findings),
        max_severity=max(severities, key=lambda s: s.value) if severities else None,
        rigor=max(executed, key=rigor_rank) if executed else RigorLevel.NONE,
        failed_gates=frozenset(
            r.gate_id for r in gate_results if r.status is GateStatus.FAIL
        ),
    )


def _as_list(value: object, key: str) -> list[object]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise PolicyError(f"condition {key!r} expects a list")
    return list(value)


def _as_str_list(value: object, key: str) -> list[str]:
    return [str(item).lower() for item in _as_list(value, key)]


def _predicate_matches(key: str, value: object, ctx: _MatchContext) -> bool:
    # Value predicates (type/format/ext/rigor/severity names) are matched
    # case-insensitively; identifier predicates (finding codes, gate ids) are
    # stable machine codes matched verbatim.
    if key == "artifact.type":
        return ctx.artifact_type == str(value).lower()
    if key == "artifact.type_in":
        return ctx.artifact_type in _as_str_list(value, key)
    if key == "artifact.file_ext_in":
        wanted = {e if e.startswith(".") else f".{e}" for e in _as_str_list(value, key)}
        return bool(ctx.extensions & wanted)
    if key == "artifact.format_not_in":
        return not (ctx.formats & set(_as_str_list(value, key)))
    if key == "rigor_below":
        rigor_target = _RIGOR_BY_NAME.get(str(value).lower())
        if rigor_target is None:
            raise PolicyError(f"condition 'rigor_below': unknown rigor {value!r}")
        return rigor_rank(ctx.rigor) < rigor_rank(rigor_target)
    if key == "finding.code":
        return str(value) in ctx.finding_codes
    if key == "finding.code_in":
        return bool(ctx.finding_codes & {str(item) for item in _as_list(value, key)})
    if key == "finding.severity_at_least":
        sev_target = _SEVERITY_BY_NAME.get(str(value).lower())
        if sev_target is None:
            raise PolicyError(f"condition 'finding.severity_at_least': bad {value!r}")
        return ctx.max_severity is not None and ctx.max_severity.value >= sev_target.value
    if key == "gate_failed":
        return str(value) in ctx.failed_gates
    raise PolicyError(f"unknown policy condition: {key!r}")


def _rule_matches(rule: PolicyRule, ctx: _MatchContext) -> bool:
    if not rule.when:
        return False  # an empty condition never fires (avoids matching everything)
    return all(_predicate_matches(key, value, ctx) for key, value in rule.when.items())


def matched_rules(
    policy: Policy, artifact: Artifact, gate_results: Sequence[GateResult]
) -> list[PolicyRule]:
    """The policy rules whose ``when`` conditions all match the scan results."""
    ctx = _build_context(artifact, gate_results)
    return [rule for rule in policy.rules if _rule_matches(rule, ctx)]


def _decision_from_actions(actions: set[PolicyAction]) -> Decision:
    if PolicyAction.REJECT in actions:
        return Decision.REJECT
    if PolicyAction.REQUIRE_REVIEW in actions:
        return Decision.REVIEW_REQUIRED
    return Decision.APPROVE  # warn-only is advisory


def evaluate(
    policy: Policy, artifact: Artifact, gate_results: Sequence[GateResult]
) -> Decision:
    """Decide categorically: max(safety baseline, declarative policy rules).

    The baseline is a floor — declarative rules can only escalate it, never
    downgrade a failing/reviewable artifact to approve.
    """
    baseline = default_decision(artifact, gate_results)
    rules = matched_rules(policy, artifact, gate_results)
    policy_decision = _decision_from_actions({rule.action for rule in rules})
    if _DECISION_RANK[policy_decision] > _DECISION_RANK[baseline]:
        return policy_decision
    return baseline
