"""Quarantine — isolated landing area for untrusted bytes (I3).

The invariant this type upholds (I3): fetched bytes MUST land in a dedicated
quarantine area, **never** a shared temp dir. PR2 adds materialisation
(:meth:`Quarantine.allocate`); the full hardening — decompression-bomb guards,
restrictive permissions, eviction — lands in **PR3** (PRD §7, QS-4).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from mig.core.artifact import ArtifactRef


@dataclass(frozen=True)
class Quarantine:
    """An isolated root under which untrusted artifacts are staged."""

    root: str

    def path_for(self, ref: ArtifactRef) -> str:
        """A deterministic, filesystem-safe subdirectory path for ``ref``.

        Pure path computation — does not touch the filesystem. Use
        :meth:`allocate` to materialise the directory.
        """
        safe = "".join(
            ch if ch.isalnum() or ch in "-._" else "_"
            for ch in f"{ref.scheme}__{ref.locator}__{ref.revision or 'unpinned'}"
        )
        return os.path.join(self.root, safe)

    def allocate(self, ref: ArtifactRef) -> str:
        """Create and return an isolated quarantine subdirectory for ``ref``.

        PR2 ensures the directory exists under the quarantine root; PR3 hardens
        it (0700 perms, freshness, capacity/bomb guards).
        """
        path = self.path_for(ref)
        os.makedirs(path, exist_ok=True)
        return path
