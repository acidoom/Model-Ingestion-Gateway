"""HuggingFaceSource: SHA-pin at fetch, bomb guard, digest verify (I3).

All hub calls are monkeypatched, so these tests need neither huggingface_hub nor
the network.
"""

from __future__ import annotations

import pathlib

import pytest

from conftest import install_fake_hf_hub, safetensors_bytes
from mig.core.artifact import ArtifactRef
from mig.sources.base import DigestMismatchError, SourceError
from mig.sources.huggingface import HuggingFaceError, HuggingFaceSource
from mig.storage.quarantine import Quarantine, QuarantineError, QuarantineLimits


def _quarantine(tmp_path: pathlib.Path, **kwargs: object) -> Quarantine:
    return Quarantine(root=str(tmp_path / "q"), **kwargs)  # type: ignore[arg-type]


def _model_files() -> dict[str, bytes]:
    return {
        "model.safetensors": safetensors_bytes(),
        "config.json": b'{"model_type": "demo"}',
    }


def _ref(locator: str = "org/model", revision: str | None = "main") -> ArtifactRef:
    return ArtifactRef(scheme="huggingface", locator=locator, revision=revision)


def test_fetch_pins_commit_sha_and_hashes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    install_fake_hf_hub(monkeypatch, sha="a" * 40, files=_model_files())
    artifact = HuggingFaceSource().fetch(_ref(), _quarantine(tmp_path))

    assert artifact.ref.scheme == "huggingface"
    assert artifact.ref.revision == "a" * 40  # pinned to the immutable SHA (I3)
    assert set(artifact.files) == {"model.safetensors", "config.json"}
    assert artifact.digest is not None
    assert artifact.digest.startswith("sha256:")
    assert artifact.metadata["revision"] == "a" * 40
    assert artifact.metadata["resolved_from"] == "main"
    assert (pathlib.Path(artifact.quarantine_path) / "model.safetensors").is_file()


def test_expected_digest_mismatch_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    install_fake_hf_hub(monkeypatch, sha="a" * 40, files=_model_files())
    ref = ArtifactRef(
        scheme="huggingface",
        locator="org/model",
        revision="main",
        expected_digest="sha256:nope",
    )
    with pytest.raises(DigestMismatchError):
        HuggingFaceSource().fetch(ref, _quarantine(tmp_path))


def test_bomb_guard_rejects_before_download(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    downloads = {"count": 0}

    def fake_resolve(
        repo_id: str, revision: str | None, token: str | None
    ) -> tuple[str, list[tuple[str, int]]]:
        return "a" * 40, [("huge.bin", 10**12)]  # 1 TB declared

    def fake_download(repo_id: str, sha_value: str, dest: str, token: str | None) -> None:
        downloads["count"] += 1

    monkeypatch.setattr("mig.sources.huggingface.resolve_commit", fake_resolve)
    monkeypatch.setattr("mig.sources.huggingface.download_snapshot", fake_download)

    quarantine = _quarantine(tmp_path, limits=QuarantineLimits(max_file_bytes=1024))
    with pytest.raises(QuarantineError):
        HuggingFaceSource().fetch(_ref(), quarantine)
    assert downloads["count"] == 0  # never downloaded the declared bomb


def test_empty_repo_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    install_fake_hf_hub(monkeypatch, sha="a" * 40, files={})
    with pytest.raises(SourceError):
        HuggingFaceSource().fetch(_ref(), _quarantine(tmp_path))


def test_missing_extra_is_a_friendly_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    def boom() -> object:
        raise HuggingFaceError(
            "the 'huggingface' source requires the optional dependency"
        )

    monkeypatch.setattr("mig.sources.huggingface._require_hub", boom)
    with pytest.raises(HuggingFaceError):
        HuggingFaceSource().fetch(_ref(), _quarantine(tmp_path))


def _patch_hub(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sha: str,
    declared: list[tuple[str, int]],
    write: dict[str, bytes],
) -> None:
    """Patch the hub so the API declares ``declared`` but the download writes
    ``write`` — lets tests diverge the declared set from what lands on disk.
    """

    def fake_resolve(
        repo_id: str, revision: str | None, token: str | None
    ) -> tuple[str, list[tuple[str, int]]]:
        return sha, declared

    def fake_download(repo_id: str, sha_value: str, dest: str, token: str | None) -> None:
        for rel, data in write.items():
            target = pathlib.Path(dest) / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

    monkeypatch.setattr("mig.sources.huggingface.resolve_commit", fake_resolve)
    monkeypatch.setattr("mig.sources.huggingface.download_snapshot", fake_download)


def test_hub_cache_dir_is_excluded_from_artifact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    _patch_hub(
        monkeypatch,
        sha="a" * 40,
        declared=[("config.json", 2)],
        write={
            "config.json": b"{}",
            ".cache/huggingface/download/x.lock": b"bookkeeping",
        },
    )
    artifact = HuggingFaceSource().fetch(_ref(), _quarantine(tmp_path))
    assert artifact.files == ["config.json"]  # .cache is not part of the artifact


def test_undeclared_file_in_snapshot_is_still_vetted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    # A file present on disk but not in the API metadata must NOT slip into
    # quarantine un-hashed — the actual landed set is authoritative.
    _patch_hub(
        monkeypatch,
        sha="a" * 40,
        declared=[("config.json", 2)],
        write={"config.json": b"{}", "sneaky.bin": b"\x80\x04pickle"},
    )
    artifact = HuggingFaceSource().fetch(_ref(), _quarantine(tmp_path))
    assert "sneaky.bin" in artifact.files


def test_declared_file_missing_after_download_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    _patch_hub(
        monkeypatch,
        sha="a" * 40,
        declared=[("config.json", 2), ("model.safetensors", 100)],
        write={"config.json": b"{}"},  # model.safetensors never written
    )
    with pytest.raises(HuggingFaceError):
        HuggingFaceSource().fetch(_ref(), _quarantine(tmp_path))


def test_revision_in_locator_is_parsed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    captured: dict[str, object] = {}

    def fake_resolve(
        repo_id: str, revision: str | None, token: str | None
    ) -> tuple[str, list[tuple[str, int]]]:
        captured["repo_id"] = repo_id
        captured["revision"] = revision
        return "b" * 40, [("config.json", 2)]

    def fake_download(repo_id: str, sha_value: str, dest: str, token: str | None) -> None:
        (pathlib.Path(dest) / "config.json").write_bytes(b"{}")

    monkeypatch.setattr("mig.sources.huggingface.resolve_commit", fake_resolve)
    monkeypatch.setattr("mig.sources.huggingface.download_snapshot", fake_download)

    HuggingFaceSource().fetch(_ref(locator="org/model@deadbeef"), _quarantine(tmp_path))
    assert captured["repo_id"] == "org/model"
    assert captured["revision"] == "deadbeef"
