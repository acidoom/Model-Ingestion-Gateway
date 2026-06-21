"""Invariants from PRD §3, encoded as tests.

These are the rules that keep MIG honest. They are deliberately structural —
they assert properties of the *source* and the *contract*, so a future PR cannot
quietly relax them. They guard not just PR1's own code but the surface later PRs
will extend (a real static gate, a real attestation builder).
"""

from __future__ import annotations

import ast
import pathlib
import tomllib
from dataclasses import fields

import pytest

from conftest import make_ref
from mig.core.artifact import EXECUTABLE_ARTIFACT_TYPES, ArtifactType
from mig.core.verdict import Decision, GateResult, GateStatus, RigorLevel, Verdict
from mig.evidence.attestation import Attestation

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "mig"

# --- I1: no in-process deserialize / exec / shell-out ----------------------- #

#: Imports never legitimate anywhere in MIG's own source (I1/I10).
FORBIDDEN_IMPORT_TOPS = {"pickle", "cpickle", "marshal", "dill", "shelve", "cloudpickle"}
#: Bare builtins that execute arbitrary code — never legitimate anywhere.
FORBIDDEN_BUILTIN_CALLS = {"exec", "eval", "compile", "__import__"}
#: Shell-exec sinks — never legitimate anywhere (pass argv lists, not a shell).
FORBIDDEN_DOTTED_ANYWHERE = {"os.system", "os.popen"}
#: Deserialiser roots whose ``.load``/``.loads`` must not appear on the static
#: surface. ``json``/``tomllib`` are deliberately absent — they are safe.
UNSAFE_LOADER_ROOTS = {
    "pickle",
    "marshal",
    "dill",
    "cloudpickle",
    "yaml",
    "torch",
    "numpy",
    "np",
    "joblib",
    "pandas",
    "pd",
}
#: Dynamic-import / out-of-process sinks banned on the static surface only. The
#: behavioral sandbox (sandbox/) and fetchers (sources/) legitimately run
#: out-of-process or fetch bytes, so they are NOT part of the static surface.
FORBIDDEN_DOTTED_STATIC = {"importlib.import_module"}
FORBIDDEN_ROOTS_STATIC = {"subprocess", "runpy"}

#: The static-analysis + orchestration surface that must never load an artifact
#: in-host (I1). Confinement/fetch packages are intentionally excluded.
STATIC_SURFACE_DIRS = {"core", "gates"}


def _source_modules() -> list[pathlib.Path]:
    return sorted(SRC.rglob("*.py"))


def _is_static_surface(path: pathlib.Path) -> bool:
    return any(part in STATIC_SURFACE_DIRS for part in path.parts)


def _dotted_call_name(func: ast.expr) -> str | None:
    """Return the dotted name of a call target (``a.b.c``), or None if complex."""
    parts: list[str] = []
    cur: ast.expr = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def test_static_code_never_deserializes_or_execs() -> None:
    """I1: MIG's own code never deserializes untrusted bytes, executes arbitrary
    code, or shells out.

    Banned EVERYWHERE: pickle/marshal/dill imports; bare exec/eval/compile/
    __import__; os.system/os.popen. Banned on the static surface (core/, gates/):
    unsafe ``.load``/``.loads`` deserialisers, importlib.import_module, runpy,
    subprocess — the constructs a real static gate would otherwise reach for.
    The behavioral sandbox is exempt by design (it *confines*, out of process).
    Best-effort: obfuscated reflection (e.g. getattr-based) is out of scope.
    """
    offenders: list[str] = []
    for path in _source_modules():
        static = _is_static_surface(path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in FORBIDDEN_IMPORT_TOPS:
                        offenders.append(f"{path.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] in FORBIDDEN_IMPORT_TOPS:
                    offenders.append(f"{path.name}: from {node.module} import")
            elif isinstance(node, ast.Call):
                dotted = _dotted_call_name(node.func)
                if dotted is None:
                    continue
                root, name = dotted.split(".")[0], dotted.split(".")[-1]
                if "." not in dotted and dotted in FORBIDDEN_BUILTIN_CALLS:
                    offenders.append(f"{path.name}: {dotted}() executes code")
                elif dotted in FORBIDDEN_DOTTED_ANYWHERE:
                    offenders.append(f"{path.name}: {dotted}() shells out")
                elif static and name in {"load", "loads"} and root in UNSAFE_LOADER_ROOTS:
                    offenders.append(f"{path.name}: {dotted}() deserialises")
                elif static and (
                    dotted in FORBIDDEN_DOTTED_STATIC or root in FORBIDDEN_ROOTS_STATIC
                ):
                    offenders.append(f"{path.name}: {dotted}() runs/loads out of band")
    assert not offenders, f"I1 violation — unsafe constructs: {offenders}"


# --- I4: categorical, type-aware verdict ------------------------------------ #


def test_decision_is_categorical() -> None:
    """I4: the decision is a small categorical enum, not a score."""
    assert {d.name for d in Decision} == {"APPROVE", "REJECT", "REVIEW_REQUIRED"}


def test_verdict_score_is_advisory_only() -> None:
    """I4: any numeric score is advisory/UX only — never `score`/`risk_score`."""
    names = {f.name for f in fields(Verdict)}
    assert "advisory_score" in names
    assert "score" not in names
    assert "risk_score" not in names


# --- I5: honest, fully-attributed attestation ------------------------------- #


def _attestation(gate_summary: list[GateResult]) -> Attestation:
    return Attestation(
        ref=make_ref(),
        digest="sha256:0",
        artifact_type=ArtifactType.MCP_SERVER,
        decision=Decision.REVIEW_REQUIRED,
        gate_summary=gate_summary,
        overall_rigor=RigorLevel.STATIC,
        confinement_level="noop",
        policy_id="p",
        policy_version="1",
        mig_version="0",
        created_at="2026-01-01T00:00:00Z",
    )


def test_attestation_flags_executed_gate_without_scanner_version() -> None:
    """I5: an executed gate missing scanner name/version is a flagged defect."""
    executed_unattributed = GateResult(
        "static_code", GateStatus.FAIL, RigorLevel.STATIC, scanner_name="x"
    )  # scanner_version is None
    skipped = GateResult("behavioral", GateStatus.SKIPPED, RigorLevel.NONE)  # exempt
    problems = _attestation([executed_unattributed, skipped]).attribution_problems()
    assert any("scanner_version" in p for p in problems)
    with pytest.raises(ValueError):
        _attestation([executed_unattributed]).assert_attributed()


def test_attestation_passes_when_executed_gates_are_attributed() -> None:
    """I5: a SKIPPED gate legitimately has no scanner; executed gates are named."""
    attributed = GateResult(
        "static_code",
        GateStatus.PASS,
        RigorLevel.STATIC,
        scanner_name="ast",
        scanner_version="1",
    )
    skipped = GateResult("behavioral", GateStatus.SKIPPED, RigorLevel.NONE)
    clean = _attestation([attributed, skipped])
    assert clean.attribution_problems() == []
    clean.assert_attributed()  # must not raise


# --- I6: no trusted-store write access on the ingest path ------------------- #


def test_ingest_orchestration_has_no_trusted_store_write() -> None:
    """I6: the pipeline runner never references promotion/write access."""
    pipeline_src = (SRC / "core" / "pipeline.py").read_text(encoding="utf-8")
    assert "promote(" not in pipeline_src
    assert "TrustedStore" not in pipeline_src


def test_no_core_module_exercises_trusted_store_write() -> None:
    """I6: no module under core imports a concrete trusted store or *calls*
    ``promote()``. Re-exporting the TrustedStore *protocol type* is allowed —
    defining the seam is fine; exercising write access during ingest is not.
    """
    for path in (SRC / "core").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "trusted_store" not in node.module, (
                    f"{path.name} imports a trusted store on the ingest path (I6)"
                )
            if isinstance(node, ast.Call):
                dotted = _dotted_call_name(node.func)
                assert not (dotted and dotted.split(".")[-1] == "promote"), (
                    f"{path.name} calls promote() on the ingest path (I6)"
                )


# --- I8: executable types need behavioral rigor ----------------------------- #


def test_executable_artifact_types_match_spec() -> None:
    """I8: the executable-types set is exactly the spec's five."""
    assert (
        frozenset(
            {
                ArtifactType.MCP_SERVER,
                ArtifactType.PYTHON_PACKAGE,
                ArtifactType.NPM_PACKAGE,
                ArtifactType.NOTEBOOK,
                ArtifactType.CONTAINER_IMAGE,
            }
        )
        == EXECUTABLE_ARTIFACT_TYPES
    )


# --- I10: minimal, pinned, hash-checked own dependencies -------------------- #


def test_core_runtime_dependencies_are_empty() -> None:
    """I10: the core has zero (pinned, audited) runtime dependencies."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["dependencies"] == []


def test_locked_dependencies_are_hash_pinned() -> None:
    """I10: every registry-sourced package in uv.lock carries an integrity hash.

    Fail-closed: a future edit that introduces a hashless source (a direct URL
    or git dependency) drops hash coverage, and this test catches it — turning
    the README's "hash-checked" claim into an enforced gate, not a side effect.
    """
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    unhashed: list[str] = []
    for package in lock.get("package", []):
        if "registry" not in package.get("source", {}):
            continue  # the local project / non-registry sources carry no hash
        sdist_hash = bool(package.get("sdist", {}).get("hash"))
        wheel_hash = any(w.get("hash") for w in package.get("wheels", []))
        if not (sdist_hash or wheel_hash):
            unhashed.append(str(package.get("name", "?")))
    assert unhashed == [], f"I10: registry packages without an integrity hash: {unhashed}"
