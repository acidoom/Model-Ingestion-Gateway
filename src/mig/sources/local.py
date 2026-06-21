"""The ``local`` source: stage a path on disk into quarantine (I3).

A local artifact is copied — never inspected in place — into an isolated
quarantine subdirectory, then content-hashed with streaming digests. If the
reference pins an ``expected_digest``, it is verified at fetch and a mismatch
aborts before any gate runs (I3). Large-file optimisation (hardlink/reflink)
and the hardened quarantine land in PR3.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Sequence

from mig.core.artifact import Artifact, ArtifactRef, ArtifactType
from mig.core.hashing import hash_tree
from mig.sources.base import DigestMismatchError, SourceError
from mig.storage.quarantine import Quarantine

#: File extensions that identify a weights-bearing model artifact.
_MODEL_HINT_EXTENSIONS = {".safetensors", ".gguf", ".bin", ".pt", ".pth", ".ckpt"}


def _resolve_local_path(locator: str) -> str:
    """Normalise a ``local`` locator (strip an optional scheme prefix)."""
    path = locator
    for prefix in ("local://", "local:", "file://"):
        if path.startswith(prefix):
            path = path[len(prefix) :]
            break
    return os.path.abspath(os.path.expanduser(path))


def _stage(source_path: str, dest_dir: str) -> list[str]:
    """Copy ``source_path`` into ``dest_dir``; return sorted relative file paths."""
    staged: list[str] = []
    if os.path.isfile(source_path):
        name = os.path.basename(source_path)
        shutil.copy2(source_path, os.path.join(dest_dir, name))
        return [name]
    for root, _dirs, files in os.walk(source_path):
        for name in files:
            abs_path = os.path.join(root, name)
            rel = os.path.relpath(abs_path, source_path)
            target = os.path.join(dest_dir, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(abs_path, target)
            staged.append(rel)
    return sorted(staged)


def infer_artifact_type(files: Sequence[str]) -> ArtifactType:
    """Best-effort artifact-type inference for a local path (models-first).

    The caller can always override via an explicit type hint; this is only a
    convenience default for ``mig scan <path>``.
    """
    if any(os.path.splitext(f)[1].lower() in _MODEL_HINT_EXTENSIONS for f in files):
        return ArtifactType.MODEL
    return ArtifactType.MODEL


class LocalSource:
    """Stage a local path into quarantine and content-hash it (I3)."""

    scheme = "local"

    def __init__(self, artifact_type: ArtifactType | None = None) -> None:
        # Optional explicit type (from `mig scan --type`); else inferred.
        self._type_hint = artifact_type

    def fetch(self, ref: ArtifactRef, quarantine: Quarantine) -> Artifact:
        source_path = _resolve_local_path(ref.locator)
        if not os.path.exists(source_path):
            raise SourceError(f"local path not found: {source_path!r}")

        dest = quarantine.allocate(ref)
        files = _stage(source_path, dest)
        if not files:
            raise SourceError(f"local path contains no files: {source_path!r}")

        digest = hash_tree(dest, files)
        if ref.expected_digest and digest != ref.expected_digest:
            # I3: verify the pin at fetch — a mismatch must not reach the gates.
            raise DigestMismatchError(
                expected=ref.expected_digest, actual=digest, locator=ref.locator
            )

        artifact_type = self._type_hint or infer_artifact_type(files)
        return Artifact(
            ref=ref,
            artifact_type=artifact_type,
            quarantine_path=dest,
            files=files,
            metadata={"source": "local", "origin": source_path},
            digest=digest,
        )
