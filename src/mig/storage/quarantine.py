"""Quarantine — isolated landing area for untrusted bytes (I3).

Scaffolding stub. The hardened implementation (digest-pinned fetch landing
zone, decompression-bomb guards, streaming/chunked hashing for multi-GB
artifacts) lands in **PR3** (PRD §7, QS-4).

The invariant this type exists to uphold (I3): fetched bytes MUST land in a
dedicated quarantine area, **never** a shared temp dir. For PR1 we model only
the identity — a rooted area that hands out per-run subdirectories.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from mig.core.artifact import ArtifactRef


@dataclass(frozen=True)
class Quarantine:
    """An isolated root under which untrusted artifacts are staged.

    PR3 hardens fetch + hashing; PR1 only needs a stable place-for path so the
    :class:`~mig.core.protocols.Source` and :class:`~mig.core.context.ScanContext`
    contracts have something concrete to reference.
    """

    root: str

    def path_for(self, ref: ArtifactRef) -> str:
        """A deterministic, filesystem-safe subdirectory for ``ref``.

        Note: PR1 does not create the directory or fetch anything — quarantine
        *materialisation* is PR3's job. This is path computation only.
        """
        safe = "".join(
            ch if ch.isalnum() or ch in "-._" else "_"
            for ch in f"{ref.scheme}__{ref.locator}__{ref.revision or 'unpinned'}"
        )
        return os.path.join(self.root, safe)
