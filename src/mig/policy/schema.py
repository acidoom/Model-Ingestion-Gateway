"""Declarative policy schema (PRD §8).

A policy is a named, versioned set of **categorical** rules (I4 — no numeric
score thresholds). Each rule has a ``when`` condition map (AND-combined), an
``action`` (reject / require_review / warn), and an advisory ``severity``.

The schema is parsed from a plain mapping (loaded from YAML or JSON, see
:mod:`mig.policy.loader`) so the engine never depends on a particular file
format. ``Policy()`` with no rules is the built-in default — the embedded
safety baseline still applies (see :mod:`mig.policy.engine`).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum

from mig.core.verdict import Severity


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


class PolicyAction(Enum):
    """Categorical action a matched rule contributes (I4)."""

    REJECT = "reject"
    REQUIRE_REVIEW = "require_review"
    WARN = "warn"


_SEVERITY_BY_NAME = {sev.name.lower(): sev for sev in Severity}


@dataclass(frozen=True)
class PolicyRule:
    """One categorical rule: if ``when`` matches, contribute ``action``."""

    id: str
    when: Mapping[str, object]
    action: PolicyAction
    severity: Severity = Severity.MEDIUM

    @staticmethod
    def from_mapping(data: Mapping[str, object]) -> PolicyRule:
        rule_id = data.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"rule is missing a string 'id': {data!r}")
        when = data.get("when", {})
        if not isinstance(when, Mapping):
            raise PolicyError(f"rule {rule_id!r}: 'when' must be a mapping")
        action_raw = data.get("action")
        if not isinstance(action_raw, str):
            raise PolicyError(f"rule {rule_id!r}: missing string 'action'")
        try:
            action = PolicyAction(action_raw)
        except ValueError:
            valid = ", ".join(a.value for a in PolicyAction)
            raise PolicyError(
                f"rule {rule_id!r}: unknown action {action_raw!r} (use: {valid})"
            ) from None
        severity = _parse_severity(data.get("severity"), rule_id)
        return PolicyRule(id=rule_id, when=dict(when), action=action, severity=severity)


def _parse_severity(value: object, rule_id: str) -> Severity:
    if value is None:
        return Severity.MEDIUM
    if isinstance(value, str) and value.lower() in _SEVERITY_BY_NAME:
        return _SEVERITY_BY_NAME[value.lower()]
    raise PolicyError(f"rule {rule_id!r}: unknown severity {value!r}")


@dataclass(frozen=True)
class Policy:
    """A named, versioned policy. No rules == the built-in default."""

    id: str
    version: str
    rules: Sequence[PolicyRule] = field(default_factory=tuple)

    @staticmethod
    def from_mapping(data: Mapping[str, object]) -> Policy:
        if not isinstance(data, Mapping):
            raise PolicyError("policy document must be a mapping")
        policy_id = data.get("id")
        if not isinstance(policy_id, str) or not policy_id:
            raise PolicyError("policy is missing a string 'id'")
        version = data.get("version")
        version_str = str(version) if version is not None else "1"
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, Sequence) or isinstance(raw_rules, str):
            raise PolicyError("policy 'rules' must be a list")
        rules = tuple(PolicyRule.from_mapping(_as_mapping(rule)) for rule in raw_rules)
        return Policy(id=policy_id, version=version_str, rules=rules)


def _as_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"each rule must be a mapping, got {type(value).__name__}")
    return value
