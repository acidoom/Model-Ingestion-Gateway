"""Agent-skill gate (medium) — skill-aware static checks (I1-safe: reads text only).

An *agent skill* is a directory with a ``SKILL.md`` manifest (markdown body plus a
YAML frontmatter block) and optional bundled helper scripts. Both surfaces are
risky in agent contexts:

* the **frontmatter** can grant the agent powerful tools (a `Bash`/shell or a `*`
  wildcard grant lets the skill run arbitrary commands through the agent);
* the **body** carries instructions that drive the agent (prompt-injection there
  is caught by the prompt-injection gate);
* **bundled scripts** run when the skill executes (their code is also seen by the
  static-code / serialization gates and detonated by the behavioral sandbox).

This gate adds skill-specific *signal*: a missing manifest, dangerous tool grants,
and bundled executables. The findings are WARN-only (advisory / policy-escalatable,
like prompt-injection, I9) — actual malicious code is rejected by the other gates.
It never executes or deserialises anything (I1): it reads files as bounded text
and parses the frontmatter with a small line scanner (no YAML loader).
"""

from __future__ import annotations

import os
import re
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
from mig.gates._common import has_shebang, read_text

if TYPE_CHECKING:
    from mig.core.artifact import Artifact

GATE_ID = "agent_skill"

#: Tool grants that let a skill run arbitrary commands through the agent. Names
#: are matched against the *leading identifier* of each grant (see :func:`_norm`),
#: so ``Bash(rm -rf /)`` and ``bash`` both reduce to ``bash``.
_DANGEROUS_TOOLS = frozenset(
    {
        "bash",
        "shell",
        "sh",
        "zsh",
        "ksh",
        "fish",
        "exec",
        "execute",
        "run",
        "powershell",
        "pwsh",
        "cmd",
        "command",
        "terminal",
        "eval",
        "system",
        "subprocess",
        "ssh",
    }
)
#: Wildcard grants ("everything") are equally dangerous.
_WILDCARD_GRANTS = frozenset({"*", "all", "any"})
#: Extensions that mean a bundled file is runnable code, not a doc/resource.
_EXECUTABLE_EXTS = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".ksh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".rb",
        ".pl",
        ".php",
        ".lua",
        ".go",
        ".rs",
        ".exe",
        ".bin",
        ".command",
        ".scpt",
        ".applescript",
        ".osa",
        ".jar",
        ".war",
        ".wasm",
        ".vbs",
        ".vbe",
        ".so",
        ".dylib",
        ".dll",
    }
)
#: Bundled files that are runnable by basename, regardless of extension.
_EXECUTABLE_NAMES = frozenset(
    {"makefile", "gnumakefile", "dockerfile", "justfile", "rakefile"}
)

_FRONTMATTER_RE = re.compile(r"^\ufeff?---[ \t]*\n(.*?)\n---[ \t]*(?:\n|$)", re.DOTALL)
_TOOLS_KEY_RE = re.compile(r"^(\s*)(allowed[-_]tools|tools)\s*:\s*(.*)$", re.IGNORECASE)
#: A YAML block-scalar indicator (``|``, ``>`` with optional chomp/indent digits)
#: as the value of a tools key; the real list lives on the indented lines below.
_BLOCK_SCALAR_RE = re.compile(r"^[|>][0-9+-]*$")
#: Leading ``- `` list marker on a block-list item.
_LIST_MARKER_RE = re.compile(r"^-\s+")
#: A trailing ``# ...`` YAML comment.
_COMMENT_RE = re.compile(r"\s+#.*$")


def _find_manifest(files: list[str]) -> str | None:
    for rel in files:
        if os.path.basename(rel).lower() == "skill.md":
            return rel
    return None


def _frontmatter(text: str) -> str:
    match = _FRONTMATTER_RE.match(text)
    return match.group(1) if match else ""


def _split_tokens(value: str) -> list[str]:
    """Candidate tool tokens from a value string (no YAML deserialisation, I1).

    Strips a trailing ``# comment`` and ``[]`` flow brackets, then splits on
    commas, whitespace, and ``:`` (so a mapping entry such as ``Bash: {}`` yields
    ``Bash``). Pieces with no word char and no ``*`` (``{}``, ``-``) are dropped.
    """
    value = _COMMENT_RE.sub("", value).strip().strip("[]")
    return [
        piece
        for piece in re.split(r"[,\s:]+", value)
        if piece and (re.search(r"\w", piece) or "*" in piece)
    ]


def _granted_tools(frontmatter: str) -> list[str]:
    """Tool names from an ``allowed-tools`` / ``tools`` key (inline or block).

    A deliberately small, dependency-free scanner: it does NOT deserialise YAML
    (I1). It recognises the inline forms (``tools: A, B`` and ``tools: [A, B]``)
    and the block forms that follow a bare/block-scalar key, namely ``- A`` list
    items, ``A: {}`` mapping entries, and bare scalars under ``|`` / ``>``. Any
    line indented deeper than the key is treated as part of its value.
    """
    tools: list[str] = []
    lines = frontmatter.splitlines()
    i = 0
    while i < len(lines):
        key = _TOOLS_KEY_RE.match(lines[i])
        if not key:
            i += 1
            continue
        indent = len(key.group(1))
        inline = _COMMENT_RE.sub("", key.group(3)).strip()
        if inline and not _BLOCK_SCALAR_RE.match(inline):
            tools += _split_tokens(inline)
            i += 1
            continue
        # Block form (list / mapping / block scalar): consume every line indented
        # deeper than the key, dropping a leading "- " list marker on each.
        i += 1
        while i < len(lines):
            line = lines[i]
            if line.strip() == "":
                i += 1
                continue
            if len(line) - len(line.lstrip()) <= indent:
                break
            tools += _split_tokens(_LIST_MARKER_RE.sub("", line.strip()))
            i += 1
    return [t.strip().strip("\"'") for t in tools if t.strip()]


def _norm(token: str) -> str:
    """Canonical lowercase head of a grant token (defeats argument syntax, I1).

    ``Bash(rm -rf /)`` and ``"Bash"`` both reduce to ``bash`` so the dangerous-set
    membership test sees the tool name, not the (arbitrary) argument string.
    """
    stripped = token.strip().strip("\"'")
    head = re.match(r"[\w.\-]+", stripped)
    return head.group(0).lower() if head else stripped.lower()


def _dangerous(tools: list[str]) -> list[str]:
    flagged: list[str] = []
    for tool in tools:
        head = _norm(tool)
        if head in _DANGEROUS_TOOLS or head in _WILDCARD_GRANTS or "*" in tool:
            flagged.append(tool)
    return flagged


def _bundled_executables(
    files: list[str], manifest: str | None, quarantine_path: str
) -> list[str]:
    """Bundled runnable files: by extension, by well-known basename, or shebang."""
    out: list[str] = []
    for rel in files:
        if rel == manifest:
            continue
        name = os.path.basename(rel).lower()
        if (
            os.path.splitext(rel)[1].lower() in _EXECUTABLE_EXTS
            or name in _EXECUTABLE_NAMES
            or (os.path.splitext(rel)[1] == "" and has_shebang(quarantine_path, rel))
        ):
            out.append(rel)
    return sorted(out)


class SkillGate:
    """Skill-aware static checks for ``agent_skill`` artifacts (WARN-only signal)."""

    id = GATE_ID
    cost = GateCost.MEDIUM
    applies_to = frozenset({ArtifactType.AGENT_SKILL})

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        files = list(artifact.files)
        manifest = _find_manifest(files)
        findings: list[Finding] = []
        tools: list[str] = []

        if manifest is None:
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.MEDIUM,
                    code="skill_missing_manifest",
                    message="agent skill has no SKILL.md manifest",
                )
            )
        else:
            text = read_text(artifact.quarantine_path, manifest) or ""
            tools = _granted_tools(_frontmatter(text))
            dangerous = _dangerous(tools)
            if dangerous:
                findings.append(
                    Finding(
                        gate_id=GATE_ID,
                        severity=Severity.HIGH,
                        code="skill_dangerous_tool_grant",
                        message=(
                            f"skill grants command-execution / wildcard tools: "
                            f"{dangerous}"
                        ),
                        location=manifest,
                        metadata={"tools": dangerous},
                    )
                )

        executables = _bundled_executables(files, manifest, artifact.quarantine_path)
        if executables:
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.MEDIUM,
                    code="skill_bundles_executables",
                    message=f"skill bundles runnable scripts: {executables}",
                    metadata={"files": executables},
                )
            )

        status = GateStatus.WARN if findings else GateStatus.PASS
        return GateResult(
            gate_id=GATE_ID,
            status=status,
            rigor=RigorLevel.STATIC,
            findings=findings,
            scanner_name="mig.agent_skill",
            scanner_version=__version__,
            evidence={
                "has_manifest": manifest is not None,
                "granted_tools": tools,
                "bundled_executables": executables,
            },
        )
