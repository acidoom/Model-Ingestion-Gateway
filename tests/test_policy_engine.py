"""PR5 declarative policy engine: categorical rules, safety floor, loader."""

from __future__ import annotations

import dataclasses
import json
import pathlib
from collections.abc import Mapping

import pytest

from conftest import make_artifact
from mig.core.artifact import ArtifactType
from mig.core.verdict import (
    Decision,
    Finding,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
)
from mig.policy.engine import evaluate, matched_rules
from mig.policy.loader import load_policy
from mig.policy.schema import Policy, PolicyAction, PolicyError


def _rule_policy(action: str, when: Mapping[str, object]) -> Policy:
    return Policy.from_mapping(
        {
            "id": "p",
            "version": "1",
            "rules": [{"id": "r", "when": when, "action": action, "severity": "high"}],
        }
    )


def _result(
    status: GateStatus,
    *findings: Finding,
    gate_id: str = "g",
    rigor: RigorLevel = RigorLevel.STATIC,
) -> GateResult:
    return GateResult(
        gate_id=gate_id,
        status=status,
        rigor=rigor,
        findings=list(findings),
        scanner_name="s",
        scanner_version="1",
    )


# --- acceptance: same artifact, different policies → different decisions ----- #


def test_same_artifact_different_policies_yield_different_decisions() -> None:
    artifact = make_artifact(ArtifactType.MODEL)  # clean → baseline APPROVE
    when = {"artifact.type": "model"}
    assert evaluate(_rule_policy("reject", when), artifact, []) is Decision.REJECT
    assert (
        evaluate(_rule_policy("require_review", when), artifact, [])
        is Decision.REVIEW_REQUIRED
    )
    assert evaluate(Policy(id="empty", version="1"), artifact, []) is Decision.APPROVE


# --- safety floor: a policy can escalate but never downgrade ----------------- #


def test_permissive_policy_cannot_downgrade_a_fail() -> None:
    artifact = make_artifact(ArtifactType.MODEL)
    decision = evaluate(
        Policy(id="empty", version="1"), artifact, [_result(GateStatus.FAIL)]
    )
    assert decision is Decision.REJECT  # gate FAIL is a floor


def test_permissive_policy_cannot_approve_executable_static_only() -> None:
    # I8: executable type without behavioral rigor → review, even with no rules.
    artifact = make_artifact(ArtifactType.MCP_SERVER)
    decision = evaluate(
        Policy(id="empty", version="1"),
        artifact,
        [_result(GateStatus.SKIPPED, gate_id="behavioral", rigor=RigorLevel.NONE)],
    )
    assert decision is Decision.REVIEW_REQUIRED


def test_warn_action_is_advisory_only() -> None:
    artifact = make_artifact(ArtifactType.MODEL)
    results = [_result(GateStatus.PASS, Finding("g", Severity.INFO, "note", "m"))]
    policy = _rule_policy("warn", {"finding.code": "note"})
    assert matched_rules(policy, artifact, results)  # the rule fires
    assert evaluate(policy, artifact, results) is Decision.APPROVE  # but warn ≠ decision


# --- condition predicates --------------------------------------------------- #


def test_format_not_in_matches_only_unsafe_format() -> None:
    policy = _rule_policy(
        "require_review",
        {"artifact.type": "model", "artifact.format_not_in": ["safetensors", "gguf"]},
    )
    pickle_model = make_artifact(
        ArtifactType.MODEL, files=["pytorch_model.bin", "config.json"]
    )
    safe_model = make_artifact(
        ArtifactType.MODEL, files=["model.safetensors", "config.json"]
    )
    assert matched_rules(policy, pickle_model, [])
    assert not matched_rules(policy, safe_model, [])


def test_executable_requires_behavioral_rigor_rule() -> None:
    policy = _rule_policy(
        "require_review",
        {"artifact.type_in": ["mcp_server"], "rigor_below": "behavioral"},
    )
    artifact = make_artifact(ArtifactType.MCP_SERVER)
    static_only = [
        _result(GateStatus.SKIPPED, gate_id="behavioral", rigor=RigorLevel.NONE)
    ]
    assert matched_rules(policy, artifact, static_only)


def test_finding_severity_at_least_condition() -> None:
    policy = _rule_policy("reject", {"finding.severity_at_least": "critical"})
    artifact = make_artifact(ArtifactType.MODEL)
    critical = [_result(GateStatus.FAIL, Finding("g", Severity.CRITICAL, "c", "m"))]
    medium = [_result(GateStatus.WARN, Finding("g", Severity.MEDIUM, "c", "m"))]
    assert matched_rules(policy, artifact, critical)
    assert not matched_rules(policy, artifact, medium)


def test_finding_code_in_matches_codes_verbatim() -> None:
    # Finding codes are stable machine identifiers; code_in matches them exactly
    # (no case-folding that would silently miss a mixed-case code).
    policy = _rule_policy("warn", {"finding.code_in": ["CVE-2024-1", "secret_detected"]})
    artifact = make_artifact(ArtifactType.MODEL)
    results = [_result(GateStatus.WARN, Finding("g", Severity.MEDIUM, "CVE-2024-1", "m"))]
    assert matched_rules(policy, artifact, results)


def test_unknown_condition_raises_policy_error() -> None:
    policy = _rule_policy("reject", {"bogus.condition": "x"})
    with pytest.raises(PolicyError):
        evaluate(policy, make_artifact(ArtifactType.MODEL), [])


def test_empty_when_never_fires() -> None:
    policy = _rule_policy("reject", {})
    assert not matched_rules(policy, make_artifact(ArtifactType.MODEL), [])


# --- I4: categorical, no numeric thresholds --------------------------------- #


def test_actions_are_categorical_and_rules_have_no_score() -> None:
    assert {a.value for a in PolicyAction} == {"reject", "require_review", "warn"}
    field_names = {f.name for f in dataclasses.fields(_rule_policy("warn", {}).rules[0])}
    assert "threshold" not in field_names
    assert "score" not in field_names


# --- loader (YAML + JSON) --------------------------------------------------- #


def test_load_yaml_policy(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        "version: 1\n"
        "id: model-ingestion\n"
        "rules:\n"
        "  - id: no_pickle_models\n"
        "    when: {artifact.file_ext_in: ['.pkl', '.bin']}\n"
        "    action: reject\n"
        "    severity: critical\n"
    )
    policy = load_policy(str(path))
    assert policy.id == "model-ingestion"
    assert len(policy.rules) == 1
    assert policy.rules[0].action is PolicyAction.REJECT
    assert policy.rules[0].severity is Severity.CRITICAL


def test_load_json_policy(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "id": "p",
                "version": "1",
                "rules": [
                    {
                        "id": "r",
                        "when": {"artifact.type": "model"},
                        "action": "warn",
                        "severity": "medium",
                    }
                ],
            }
        )
    )
    policy = load_policy(str(path))
    assert policy.rules[0].action is PolicyAction.WARN


def test_bad_policy_action_raises(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"id": "p", "rules": [{"id": "r", "action": "nope"}]}))
    with pytest.raises(PolicyError):
        load_policy(str(path))


def test_policy_missing_id_raises(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "noid.json"
    path.write_text(json.dumps({"version": "1", "rules": []}))
    with pytest.raises(PolicyError):
        load_policy(str(path))
