"""Quarantine hardening: permissions, traversal guard, bomb/size limits (I3)."""

from __future__ import annotations

import os
import pathlib
import stat
import sys

import pytest

from mig.core.artifact import ArtifactRef
from mig.storage.quarantine import (
    Quarantine,
    QuarantineError,
    QuarantineLimits,
    safe_join,
    stage_local_tree,
)


def _ref() -> ArtifactRef:
    return ArtifactRef(scheme="local", locator="org/model", revision="abc")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_allocate_creates_private_directory(tmp_path: pathlib.Path) -> None:
    path = Quarantine(root=str(tmp_path / "q")).allocate(_ref())
    assert os.path.isdir(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o700


def test_safe_join_rejects_absolute_paths(tmp_path: pathlib.Path) -> None:
    with pytest.raises(QuarantineError):
        safe_join(str(tmp_path), "/etc/passwd")


def test_safe_join_rejects_traversal(tmp_path: pathlib.Path) -> None:
    with pytest.raises(QuarantineError):
        safe_join(str(tmp_path), "../../etc/passwd")


def test_safe_join_allows_nested_relative_paths(tmp_path: pathlib.Path) -> None:
    target = safe_join(str(tmp_path), "sub/dir/file.bin")
    assert target.startswith(os.path.abspath(str(tmp_path)) + os.sep)


def test_check_declared_sizes_enforces_caps() -> None:
    quarantine = Quarantine(
        root="/tmp/q",
        limits=QuarantineLimits(max_file_bytes=10, max_total_bytes=15, max_files=2),
    )
    quarantine.check_declared_sizes([5, 5])  # ok
    with pytest.raises(QuarantineError):
        quarantine.check_declared_sizes([11])  # single file too big
    with pytest.raises(QuarantineError):
        quarantine.check_declared_sizes([8, 8])  # total too big
    with pytest.raises(QuarantineError):
        quarantine.check_declared_sizes([1, 1, 1])  # too many files


def test_stage_local_tree_copies_and_enforces(tmp_path: pathlib.Path) -> None:
    src = tmp_path / "src"
    (src / "nested").mkdir(parents=True)
    (src / "a.txt").write_bytes(b"hello")
    (src / "nested" / "b.bin").write_bytes(b"world!!")
    dest = tmp_path / "dest"
    dest.mkdir()

    files = stage_local_tree(str(src), str(dest), QuarantineLimits())
    assert files == ["a.txt", "nested/b.bin"]
    assert (dest / "a.txt").read_bytes() == b"hello"
    assert (dest / "nested" / "b.bin").read_bytes() == b"world!!"


def test_stage_local_tree_rejects_oversized_file(tmp_path: pathlib.Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "big.bin").write_bytes(b"x" * 50)
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(QuarantineError):
        stage_local_tree(str(src), str(dest), QuarantineLimits(max_file_bytes=10))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_stage_local_tree_rejects_symlinks(tmp_path: pathlib.Path) -> None:
    # I3: an in-tree symlink to an outside file must not deref host bytes into
    # quarantine (or poison the digest) — staging fails closed.
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"OUTSIDE-TREE-SECRET")
    src = tmp_path / "src"
    src.mkdir()
    (src / "innocent.txt").symlink_to(outside)
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(QuarantineError):
        stage_local_tree(str(src), str(dest), QuarantineLimits())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_stage_local_tree_rejects_symlinked_directory(tmp_path: pathlib.Path) -> None:
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "leak.txt").write_bytes(b"leak")
    src = tmp_path / "src"
    src.mkdir()
    (src / "real.txt").write_bytes(b"ok")
    (src / "linkdir").symlink_to(outside_dir, target_is_directory=True)
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(QuarantineError):
        stage_local_tree(str(src), str(dest), QuarantineLimits())
