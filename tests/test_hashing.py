"""Streaming hashing + digest normalisation."""

from __future__ import annotations

import pathlib

from mig.core.hashing import digests_match, hash_file, hash_tree, normalize_digest


def test_hash_file_is_prefixed_sha256(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "f.bin"
    path.write_bytes(b"hello world")
    digest = hash_file(str(path))
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64


def test_hash_tree_is_order_independent(tmp_path: pathlib.Path) -> None:
    root = tmp_path
    (root / "a.txt").write_bytes(b"a")
    (root / "b.txt").write_bytes(b"b")
    assert hash_tree(str(root), ["a.txt", "b.txt"]) == hash_tree(
        str(root), ["b.txt", "a.txt"]
    )


def test_normalize_accepts_bare_hex() -> None:
    bare = "a" * 64
    assert normalize_digest(bare) == f"sha256:{bare}"
    assert normalize_digest(f"SHA256:{'A' * 64}") == f"sha256:{'a' * 64}"


def test_digests_match_across_forms() -> None:
    hexpart = "deadbeef" * 8  # 64 hex chars
    assert digests_match(f"sha256:{hexpart}", hexpart)  # bare vs prefixed
    assert digests_match(f"sha256:{hexpart}", f"sha256:{hexpart.upper()}")  # case
    assert not digests_match(f"sha256:{hexpart}", "sha256:" + "0" * 64)
