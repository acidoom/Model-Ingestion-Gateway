"""The ``local`` source: stage a path on disk into quarantine (I3).

A local artifact is copied — never inspected in place — into an isolated
quarantine subdirectory, then content-hashed with streaming digests. If the
reference pins an ``expected_digest``, it is verified at fetch and a mismatch
aborts before any gate runs (I3). Large-file optimisation (hardlink/reflink)
and the hardened quarantine land in PR3.
"""

from __future__ import annotations

import os
from collections.abc import Sequence

from mig.core.artifact import Artifact, ArtifactRef, ArtifactType
from mig.core.hashing import digests_match, hash_tree
from mig.sources.base import DigestMismatchError, SourceError
from mig.storage.quarantine import Quarantine, stage_local_tree


def _resolve_local_path(locator: str) -> str:
    """Normalise a ``local`` locator (strip an optional scheme prefix)."""
    path = locator
    for prefix in ("local://", "local:", "file://"):
        if path.startswith(prefix):
            path = path[len(prefix) :]
            break
    return os.path.abspath(os.path.expanduser(path))


def infer_artifact_type(files: Sequence[str]) -> ArtifactType:
    """Default artifact type for a local path (models-first).

    MIG is models-first (R2): without an explicit ``--type`` a local path is
    treated as a model. Richer inference (packages, notebooks) arrives with the
    per-type suites in the follow-on waves.
    """
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
        files = stage_local_tree(source_path, dest, quarantine.limits)
        if not files:
            raise SourceError(f"local path contains no files: {source_path!r}")

        digest = hash_tree(dest, files)
        if ref.expected_digest and not digests_match(digest, ref.expected_digest):
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
