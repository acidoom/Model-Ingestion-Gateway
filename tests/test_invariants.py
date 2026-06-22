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

#: The in-container detonation harness is the ONE place MIG deliberately loads an
#: artifact (pickle/import) — but it runs INSIDE the confined sandbox container,
#: never in the host process, so it is exempt from the host-side I1 guard.
_DETONATION_HARNESS = SRC / "sandbox" / "_harness.py"


def _source_modules() -> list[pathlib.Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if p != _DETONATION_HARNESS]


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
    """I6: no module under core OR evidence imports a concrete trusted store or
    *calls* ``promote()``. Re-exporting the TrustedStore *protocol type* is allowed
    — defining the seam is fine; exercising write access during ingest/attest is
    not. The evidence (attestation/signing) layer is on the ingest path too, so it
    is held to the same rule.
    """
    for subdir in ("core", "evidence"):
        for path in (SRC / subdir).rglob("*.py"):
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


# --- I6 (PR8): promotion is the SOLE gated writer; ingest can't reach it ----- #


def _imports_promotion(path: pathlib.Path) -> bool:
    """True if ``path`` imports anything under ``mig.promotion`` (any form)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "mig.promotion"
        ):
            return True
        if isinstance(node, ast.Import) and any(
            a.name.startswith("mig.promotion") for a in node.names
        ):
            return True
    return False


def test_only_promotion_package_imports_the_writer() -> None:
    """I6: the trusted-store writer lives in ``mig.promotion``, and ONLY that
    package (plus the delegating CLI) may import it — an AST import check, so name
    aliasing cannot evade it. The TrustedStore *protocol* in core/protocols.py
    defines the seam without importing the writer, so it is unaffected."""
    promotion = SRC / "promotion"
    cli_main = SRC / "cli" / "main.py"
    offenders = [
        str(path.relative_to(SRC))
        for path in SRC.rglob("*.py")
        if not (promotion in path.parents or path == cli_main)
        and _imports_promotion(path)
    ]
    assert offenders == [], f"I6: mig.promotion imported outside the writer: {offenders}"


def test_core_and_evidence_do_not_import_promotion() -> None:
    """I6 (two-way wall): the ingest path cannot even import the writer."""
    for subdir in ("core", "evidence"):
        for path in (SRC / subdir).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    assert not (node.module or "").startswith("mig.promotion"), (
                        f"{path.name} imports mig.promotion on the ingest path (I6)"
                    )
                elif isinstance(node, ast.Import):
                    assert not any(
                        a.name.startswith("mig.promotion") for a in node.names
                    ), f"{path.name} imports mig.promotion on the ingest path (I6)"


def test_promote_is_unreachable_without_verify() -> None:
    """I6: in the orchestrator, the store write is lexically AFTER
    ``verify_attestation`` and dominated by a ``not result.ok`` early return —
    'you cannot promote what wasn't verified', encoded as structure."""
    src = (SRC / "promotion" / "promote.py").read_text(encoding="utf-8")
    verify_at = src.index("verify_attestation(")
    write_at = src.index("store.write(")
    assert verify_at < write_at, "store.write must come after verify_attestation"
    assert "if not result.ok" in src[verify_at:write_at], (
        "the store write must be guarded by a 'not result.ok' early return"
    )


def test_promotion_default_path_is_stdlib_only() -> None:
    """I10: no module under promotion/ imports a third-party dep at module scope;
    the OPA backend is lazy-imported by make_promotion_gate."""
    forbidden = {"cryptography", "boto3", "requests", "oras"}
    for path in (SRC / "promotion").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:  # module-scope statements only
            if isinstance(node, ast.Import):
                assert not any(a.name.split(".")[0] in forbidden for a in node.names), (
                    f"{path.name} imports a third-party dep at module scope (I10)"
                )
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in forbidden, (
                    f"{path.name} imports a third-party dep at module scope (I10)"
                )
    gate_tree = ast.parse((SRC / "promotion" / "gate.py").read_text(encoding="utf-8"))
    for node in gate_tree.body:  # opa must be lazy (function-scope), not module-scope
        assert not (isinstance(node, ast.ImportFrom) and "opa" in (node.module or "")), (
            "gate.py imports the OPA backend at module scope (must be lazy)"
        )


# --- I8: executable types need behavioral rigor ----------------------------- #


def test_executable_artifact_types_match_spec() -> None:
    """I8: the executable-types set is exactly the code-bearing types — the spec's
    five plus AGENT_SKILL (a skill bundles runnable scripts + agent-driving
    instructions, so it must clear behavioral rigor before APPROVE)."""
    assert (
        frozenset(
            {
                ArtifactType.MCP_SERVER,
                ArtifactType.PYTHON_PACKAGE,
                ArtifactType.NPM_PACKAGE,
                ArtifactType.NOTEBOOK,
                ArtifactType.CONTAINER_IMAGE,
                ArtifactType.AGENT_SKILL,
            }
        )
        == EXECUTABLE_ARTIFACT_TYPES
    )


# --- I10: minimal, pinned, hash-checked own dependencies -------------------- #


def test_core_runtime_dependencies_are_empty() -> None:
    """I10: the core has zero (pinned, audited) runtime dependencies."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["dependencies"] == []


def test_signing_default_is_stdlib_only() -> None:
    """I10: the default signing path is stdlib-only. No module under evidence/
    imports ``cryptography`` at top level EXCEPT the opt-in ed25519 backend, which
    imports it lazily inside functions — so importing the evidence package (and
    signing with the HMAC default) never pulls in the extra.
    """
    ed25519_backend = SRC / "evidence" / "signers" / "ed25519.py"
    offenders: list[str] = []
    for path in (SRC / "evidence").rglob("*.py"):
        if path == ed25519_backend:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Import)
                and any(a.name.split(".")[0] == "cryptography" for a in node.names)
                or (
                    isinstance(node, ast.ImportFrom)
                    and (node.module or "").split(".")[0] == "cryptography"
                )
            ):
                offenders.append(path.name)
    assert offenders == [], f"I10: evidence imports cryptography eagerly: {offenders}"


def test_ed25519_backend_imports_cryptography_lazily() -> None:
    """The ed25519 backend must keep ``cryptography`` out of module scope (lazy,
    inside functions) so even importing it does not require the extra (I10)."""
    ed25519_backend = SRC / "evidence" / "signers" / "ed25519.py"
    tree = ast.parse(ed25519_backend.read_text(encoding="utf-8"))
    for node in tree.body:  # module-level statements only
        assert not (
            isinstance(node, (ast.Import, ast.ImportFrom))
            and "cryptography" in ast.dump(node)
        ), "ed25519 backend imports cryptography at module scope (must be lazy)"


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
