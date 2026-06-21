"""LocalSource: stage into quarantine, hash, verify pins (I3)."""

from __future__ import annotations

import pathlib

import pytest

from conftest import make_model_dir
from mig.core.artifact import ArtifactRef, ArtifactType
from mig.sources.base import DigestMismatchError, SourceError
from mig.sources.local import LocalSource
from mig.storage.quarantine import Quarantine


def _quarantine(tmp_path: pathlib.Path, name: str = "q") -> Quarantine:
    return Quarantine(root=str(tmp_path / name))


def test_fetch_stages_bytes_into_quarantine(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    ref = ArtifactRef(scheme="local", locator=str(model))
    artifact = LocalSource().fetch(ref, _quarantine(tmp_path))

    assert set(artifact.files) == {"model.safetensors", "config.json"}
    assert artifact.digest is not None
    assert artifact.digest.startswith("sha256:")
    assert artifact.artifact_type is ArtifactType.MODEL
    # I3: bytes landed in the isolated quarantine, not inspected in place.
    assert artifact.quarantine_path.startswith(str(tmp_path / "q"))
    assert (pathlib.Path(artifact.quarantine_path) / "model.safetensors").is_file()


def test_fetch_missing_path_raises(tmp_path: pathlib.Path) -> None:
    ref = ArtifactRef(scheme="local", locator=str(tmp_path / "nope"))
    with pytest.raises(SourceError):
        LocalSource().fetch(ref, _quarantine(tmp_path))


def test_fetch_single_file(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    ref = ArtifactRef(scheme="local", locator=str(model / "model.safetensors"))
    artifact = LocalSource().fetch(ref, _quarantine(tmp_path))
    assert artifact.files == ["model.safetensors"]


def test_digest_is_stable_across_fetches(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    ref = ArtifactRef(scheme="local", locator=str(model))
    first = LocalSource().fetch(ref, _quarantine(tmp_path, "q1"))
    second = LocalSource().fetch(ref, _quarantine(tmp_path, "q2"))
    assert first.digest == second.digest


def test_pinned_digest_verified_at_fetch(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    computed = (
        LocalSource()
        .fetch(
            ArtifactRef(scheme="local", locator=str(model)), _quarantine(tmp_path, "q0")
        )
        .digest
    )
    assert computed is not None

    # Correct pin → fetch succeeds.
    LocalSource().fetch(
        ArtifactRef(scheme="local", locator=str(model), expected_digest=computed),
        _quarantine(tmp_path, "q1"),
    )
    # Wrong pin → I3 mismatch aborts before any gate runs.
    with pytest.raises(DigestMismatchError):
        LocalSource().fetch(
            ArtifactRef(scheme="local", locator=str(model), expected_digest="sha256:bad"),
            _quarantine(tmp_path, "q2"),
        )


def test_explicit_type_overrides_inference(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    artifact = LocalSource(artifact_type=ArtifactType.MCP_SERVER).fetch(
        ArtifactRef(scheme="local", locator=str(model)), _quarantine(tmp_path)
    )
    assert artifact.artifact_type is ArtifactType.MCP_SERVER
