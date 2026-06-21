"""Static-code gate — AST inspection of bundled Python (I1-safe).

Parses each ``.py`` file an artifact ships (custom ``modeling_*.py``, hooks,
package code) with the stdlib :mod:`ast` and flags dangerous call sites —
arbitrary-code execution, shell-out, unsafe deserialization, dynamic import,
network capability. Parsing **does not execute** the code (I1); the artifact is
inspected as bytes/AST only.

This gate complements the format-allowlist gate, which only *flags the presence*
of executable companions — here we look at what that code actually does.
"""

from __future__ import annotations

import ast
import os
from typing import TYPE_CHECKING

from mig import __version__
from mig.core.artifact import ArtifactType
from mig.core.verdict import (
    Finding,
    GateCost,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
)
from mig.storage.quarantine import safe_join

if TYPE_CHECKING:
    from mig.core.artifact import Artifact

GATE_ID = "static_code"

#: Don't read absurd source files into memory.
_MAX_SOURCE_BYTES = 5 * 1024 * 1024

_BARE_EXEC_CALLS = {"exec", "eval", "compile", "__import__"}
_OS_EXEC_NAMES = {
    "system",
    "popen",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnv",
    "spawnve",
    "posix_spawn",
}
_UNSAFE_LOADER_ROOTS = {"pickle", "marshal", "dill", "cloudpickle", "shelve"}
#: Dual-use capability roots — flagged for review, not auto-reject.
_CAPABILITY_ROOTS = {
    "subprocess",
    "socket",
    "ctypes",
    "runpy",
    "requests",
    "urllib",
    "http",
    "ftplib",
    "telnetlib",
    "smtplib",
    "paramiko",
    "pty",
    "fcntl",
}


def _dotted_call_name(func: ast.expr) -> str | None:
    parts: list[str] = []
    cur: ast.expr = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _build_import_map(tree: ast.Module) -> dict[str, str]:
    """Map each in-scope name to the module/symbol it refers to.

    So ``import os as o`` → ``{"o": "os"}`` and ``from os import system`` →
    ``{"system": "os.system"}``. Lets the classifier see through the common
    ``from os import system; system()`` and aliased-import evasions.
    """
    mapping: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    mapping[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    mapping[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                mapping[local] = f"{node.module}.{alias.name}"
    return mapping


def _resolve(dotted: str, import_map: dict[str, str]) -> str:
    parts = dotted.split(".")
    if parts[0] in import_map:
        return ".".join([import_map[parts[0]], *parts[1:]])
    return dotted


def _classify_call(dotted: str) -> tuple[Severity, str] | None:
    parts = dotted.split(".")
    root, name = parts[0], parts[-1]
    if name in _BARE_EXEC_CALLS and root in ("builtins", name):
        return Severity.CRITICAL, "dynamic_code_execution"
    if root == "os" and name in _OS_EXEC_NAMES:
        return Severity.CRITICAL, "shell_execution"
    if name in ("load", "loads") and root in _UNSAFE_LOADER_ROOTS:
        return Severity.CRITICAL, "unsafe_deserialization"
    if dotted == "importlib.import_module":
        return Severity.MEDIUM, "dynamic_import"
    if root in _CAPABILITY_ROOTS:
        return Severity.MEDIUM, "suspicious_capability"
    return None


class StaticCodeGate:
    """Flag dangerous constructs in bundled ``.py`` files via AST (no execution)."""

    id = GATE_ID
    cost = GateCost.MEDIUM
    applies_to = frozenset(ArtifactType)  # any artifact may ship .py code

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        findings: list[Finding] = []
        scanned: list[str] = []
        for rel in artifact.files:
            if not rel.endswith(".py"):
                continue
            scanned.append(rel)
            findings.extend(self._scan_file(artifact.quarantine_path, rel))

        return GateResult(
            gate_id=GATE_ID,
            status=_status_for(findings),
            rigor=RigorLevel.STATIC,
            findings=findings,
            scanner_name="mig.static_code",
            scanner_version=__version__,
            evidence={"scanned_files": scanned},
        )

    def _scan_file(self, quarantine_path: str, rel: str) -> list[Finding]:
        path = safe_join(quarantine_path, rel)
        try:
            if os.path.getsize(path) > _MAX_SOURCE_BYTES:
                return [
                    _finding(
                        Severity.MEDIUM,
                        "source_too_large",
                        rel,
                        None,
                        "source file too large to analyse statically",
                    )
                ]
            with open(path, encoding="utf-8") as handle:
                source = handle.read()
        except (OSError, UnicodeDecodeError):
            return [
                _finding(
                    Severity.MEDIUM,
                    "unreadable_source",
                    rel,
                    None,
                    "could not read source as UTF-8 text",
                )
            ]
        try:
            tree = ast.parse(source, filename=rel)
        except (SyntaxError, ValueError, RecursionError):
            # RecursionError: a deeply-nested but valid file. Treat as one bad
            # file, never let it abort the gate and mask sibling files.
            return [
                _finding(
                    Severity.MEDIUM,
                    "unparseable_python",
                    rel,
                    None,
                    "file does not parse as Python (obfuscated/over-nested?)",
                )
            ]

        import_map = _build_import_map(tree)
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _dotted_call_name(node.func)
            if dotted is None:
                continue
            resolved = _resolve(dotted, import_map)
            classified = _classify_call(resolved)
            if classified is None:
                continue
            severity, code = classified
            findings.append(
                _finding(severity, code, rel, node.lineno, f"calls {resolved}()")
            )
        return findings


def _finding(
    severity: Severity, code: str, rel: str, line: int | None, message: str
) -> Finding:
    return Finding(
        gate_id=GATE_ID,
        severity=severity,
        code=code,
        message=message,
        location=f"{rel}:{line}" if line is not None else rel,
    )


def _status_for(findings: list[Finding]) -> GateStatus:
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities or Severity.HIGH in severities:
        return GateStatus.FAIL
    if findings:
        return GateStatus.WARN
    return GateStatus.PASS
