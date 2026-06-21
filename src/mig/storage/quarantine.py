"""Quarantine — isolated landing area for untrusted bytes (I3).

Upholds I3: fetched bytes MUST land in a dedicated, isolated quarantine area,
never a shared temp dir or the source in place. This module also provides the
guards every source relies on:

* **bomb/resource guards** (:class:`QuarantineLimits`) — reject artifacts whose
  declared or on-disk size/count exceeds sane caps, *before* exhausting disk;
* **traversal guard** (:func:`safe_join`) — a fetched filename can never escape
  the quarantine root (zip-slip);
* **restrictive permissions** — allocated directories are created ``0o700``.
"""

from __future__ import annotations

import contextlib
import os
import shutil
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from mig.core.artifact import ArtifactRef

_KIB = 1024
_MIB = 1024 * _KIB
_GIB = 1024 * _MIB


class QuarantineError(Exception):
    """Raised when staging into quarantine would be unsafe (traversal/limits)."""


@dataclass(frozen=True)
class QuarantineLimits:
    """Resource caps applied to anything staged into quarantine.

    Defaults are generous enough for real multi-GB models (QS-4) while still
    fencing an adversarial source that declares or serves absurd sizes.
    """

    max_file_bytes: int = 64 * _GIB
    max_total_bytes: int = 128 * _GIB
    max_files: int = 100_000


DEFAULT_LIMITS = QuarantineLimits()


def safe_join(root: str, rel: str) -> str:
    """Join ``rel`` under ``root``, rejecting absolute paths and ``..`` escapes.

    Returns the absolute target path. Raises :class:`QuarantineError` if ``rel``
    is absolute or would resolve outside ``root`` (zip-slip protection).
    """
    if os.path.isabs(rel) or rel.startswith(("/", "\\")):
        raise QuarantineError(f"unsafe absolute path in artifact: {rel!r}")
    root_abs = os.path.abspath(root)
    target_abs = os.path.abspath(os.path.join(root_abs, rel))
    if target_abs != root_abs and not target_abs.startswith(root_abs + os.sep):
        raise QuarantineError(f"path traversal blocked: {rel!r}")
    return target_abs


@dataclass(frozen=True)
class Quarantine:
    """An isolated root under which untrusted artifacts are staged."""

    root: str
    limits: QuarantineLimits = DEFAULT_LIMITS

    def path_for(self, ref: ArtifactRef) -> str:
        """A deterministic, filesystem-safe subdirectory path for ``ref``.

        Pure path computation — does not touch the filesystem.
        """
        safe = "".join(
            ch if ch.isalnum() or ch in "-._" else "_"
            for ch in f"{ref.scheme}__{ref.locator}__{ref.revision or 'unpinned'}"
        )
        return os.path.join(self.root, safe)

    def allocate(self, ref: ArtifactRef) -> str:
        """Create and return an isolated ``0o700`` quarantine subdirectory."""
        path = self.path_for(ref)
        os.makedirs(path, mode=0o700, exist_ok=True)
        with contextlib.suppress(OSError):  # best-effort on non-POSIX platforms
            os.chmod(path, 0o700)
        return path

    def check_declared_sizes(self, sizes: Sequence[int]) -> None:
        """Bomb guard: reject *before* download if declared sizes exceed limits."""
        if len(sizes) > self.limits.max_files:
            raise QuarantineError(
                f"artifact declares {len(sizes)} files (> {self.limits.max_files})"
            )
        for size in sizes:
            if size > self.limits.max_file_bytes:
                raise QuarantineError(
                    f"declared file size {size} exceeds cap {self.limits.max_file_bytes}"
                )
        if sum(sizes) > self.limits.max_total_bytes:
            raise QuarantineError(
                f"declared total size {sum(sizes)} exceeds cap "
                f"{self.limits.max_total_bytes}"
            )

    def enforce(self, root: str, files: Iterable[str]) -> None:
        """Enforce on-disk size/count limits over staged ``files`` under ``root``."""
        rels = list(files)
        if len(rels) > self.limits.max_files:
            raise QuarantineError(f"staged {len(rels)} files (> {self.limits.max_files})")
        total = 0
        for rel in rels:
            size = os.path.getsize(safe_join(root, rel))
            if size > self.limits.max_file_bytes:
                raise QuarantineError(
                    f"staged file {rel!r} size {size} exceeds cap "
                    f"{self.limits.max_file_bytes}"
                )
            total += size
        if total > self.limits.max_total_bytes:
            raise QuarantineError(
                f"staged total size {total} exceeds cap {self.limits.max_total_bytes}"
            )


def stage_local_tree(src: str, dest: str, limits: QuarantineLimits) -> list[str]:
    """Copy a local file/dir into ``dest`` with symlink + traversal + size guards.

    Returns the sorted list of staged paths relative to ``dest``. Copies file
    *content* only (not metadata/permissions), so nothing about the source's
    mode survives into quarantine.

    **Symlinks are rejected** (I3): following a symlink would dereference a file
    *outside* the declared artifact tree into quarantine and into the content
    digest — and a link to a special file (e.g. ``/dev/zero``) would defeat the
    size guard and read unboundedly. An artifact that contains symlinks is
    anomalous and fails closed.
    """
    staged: list[str] = []
    total = 0

    def _place(abs_src: str, rel: str) -> None:
        nonlocal total
        if os.path.islink(abs_src):
            raise QuarantineError(
                f"symlink not allowed in artifact (out-of-tree deref): {rel!r}"
            )
        if len(staged) + 1 > limits.max_files:
            raise QuarantineError(f"more than {limits.max_files} files in artifact")
        size = os.path.getsize(abs_src)
        if size > limits.max_file_bytes:
            raise QuarantineError(
                f"file {rel!r} size {size} exceeds cap {limits.max_file_bytes}"
            )
        total += size
        if total > limits.max_total_bytes:
            raise QuarantineError(
                f"total size {total} exceeds cap {limits.max_total_bytes}"
            )
        target = safe_join(dest, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(abs_src, target)
        staged.append(rel)

    if os.path.isfile(src):
        _place(src, os.path.basename(src))
    else:
        for walk_root, dirs, files in os.walk(src):
            for name in dirs:
                # os.walk(followlinks=False) won't descend a symlinked dir, but
                # reject it loudly rather than silently skipping it.
                abs_dir = os.path.join(walk_root, name)
                if os.path.islink(abs_dir):
                    raise QuarantineError(
                        f"symlink not allowed in artifact (dir): "
                        f"{os.path.relpath(abs_dir, src)!r}"
                    )
            for name in files:
                abs_src = os.path.join(walk_root, name)
                _place(abs_src, os.path.relpath(abs_src, src))
    return sorted(staged)
