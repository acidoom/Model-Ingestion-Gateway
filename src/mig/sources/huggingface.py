"""The ``huggingface`` source — digest/SHA-pinned fetch into quarantine (I3).

Resolves a (possibly mutable) revision to an **immutable commit SHA at fetch
time**, applies the quarantine's bomb guard to the *declared* file sizes before
downloading anything, downloads the repo snapshot into an isolated quarantine
directory, then content-hashes it with streaming digests (QS-4) and verifies a
pinned ``expected_digest`` if one was supplied.

``huggingface_hub`` is an optional dependency (``pip install 'mig[huggingface]'``).
All hub calls go through the module-level wrappers :func:`resolve_commit` and
:func:`download_snapshot`, which tests monkeypatch — so the unit tests need
neither the library nor the network.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from mig.core.artifact import Artifact, ArtifactRef, ArtifactType
from mig.core.hashing import digests_match, hash_tree
from mig.sources.base import DigestMismatchError, SourceError
from mig.storage.quarantine import safe_join

if TYPE_CHECKING:
    from mig.storage.quarantine import Quarantine

#: Environment variables consulted for an access token (private repos / limits).
_TOKEN_ENV_VARS = ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN")


class HuggingFaceError(SourceError):
    """A Hugging Face fetch failure (missing extra, resolution, download)."""


def _require_hub() -> Any:
    try:
        import huggingface_hub
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise HuggingFaceError(
            "the 'huggingface' source requires the optional dependency; "
            "install it with: pip install 'mig[huggingface]'"
        ) from exc
    return huggingface_hub


def _token() -> str | None:
    for name in _TOKEN_ENV_VARS:
        value = os.environ.get(name)
        if value:
            return value
    return None


def resolve_commit(
    repo_id: str, revision: str | None, token: str | None
) -> tuple[str, list[tuple[str, int]]]:
    """Resolve ``revision`` to an immutable commit SHA + ``(path, size)`` files.

    Wraps ``HfApi.repo_info(..., files_metadata=True)``. Monkeypatched in tests.
    """
    hub = _require_hub()
    info = hub.HfApi(token=token).repo_info(
        repo_id=repo_id, revision=revision, files_metadata=True
    )
    sha = info.sha
    if not sha:
        raise HuggingFaceError(f"could not resolve a commit SHA for {repo_id!r}")
    files: list[tuple[str, int]] = [
        (str(sibling.rfilename), int(sibling.size or 0))
        for sibling in (info.siblings or [])
    ]
    return str(sha), files


def download_snapshot(repo_id: str, sha: str, dest: str, token: str | None) -> None:
    """Download the repo snapshot at ``sha`` into ``dest``. Monkeypatched in tests."""
    hub = _require_hub()
    hub.snapshot_download(repo_id=repo_id, revision=sha, local_dir=dest, token=token)


def _list_staged(dest: str) -> list[str]:
    """Sorted relative paths actually present under ``dest``.

    Excludes huggingface_hub's top-level ``.cache`` bookkeeping directory, which
    ``snapshot_download(local_dir=...)`` writes but which is not part of the
    artifact and must not be hashed/vetted.
    """
    staged: list[str] = []
    for walk_root, dirs, names in os.walk(dest):
        if walk_root == dest:
            dirs[:] = [d for d in dirs if d != ".cache"]
        for name in names:
            staged.append(os.path.relpath(os.path.join(walk_root, name), dest))
    return sorted(staged)


def _parse_locator(ref: ArtifactRef) -> tuple[str, str | None]:
    """Split ``org/model[@revision]`` (+ ref.revision) into (repo_id, revision)."""
    locator = ref.locator
    for prefix in ("huggingface://", "hf://"):
        if locator.startswith(prefix):
            locator = locator[len(prefix) :]
            break
    if "@" in locator:
        repo_id, _, rev = locator.partition("@")
        return repo_id, (rev or ref.revision)
    return locator, ref.revision


class HuggingFaceSource:
    """Fetch a Hugging Face repo at a pinned commit SHA into quarantine (I3)."""

    scheme = "huggingface"

    def __init__(self, artifact_type: ArtifactType | None = None) -> None:
        self._type_hint = artifact_type

    def fetch(self, ref: ArtifactRef, quarantine: Quarantine) -> Artifact:
        repo_id, revision = _parse_locator(ref)
        if not repo_id:
            raise HuggingFaceError("missing Hugging Face repo id")
        token = _token()

        # I3: pin to an immutable commit SHA at fetch time.
        sha, declared = resolve_commit(repo_id, revision, token)
        if not declared:
            raise HuggingFaceError(f"repo {repo_id!r}@{sha} declares no files")

        # Bomb guard (best-effort): reject obviously-oversized declared sizes
        # before downloading. Files the API reports with no size are coerced to 0
        # here; the authoritative guard is the post-download on-disk `enforce`.
        quarantine.check_declared_sizes([size for _, size in declared])

        pinned_ref = ArtifactRef(
            scheme="huggingface",
            locator=repo_id,
            revision=sha,
            expected_digest=ref.expected_digest,
        )
        dest = quarantine.allocate(pinned_ref)
        download_snapshot(repo_id, sha, dest, token)

        # Vet exactly what landed on disk, not just what the API declared, so an
        # undeclared file in the snapshot cannot sit in quarantine un-hashed.
        files = _list_staged(dest)
        if not files:
            raise HuggingFaceError(f"no files landed for {repo_id!r}@{sha}")
        missing = sorted({path for path, _ in declared} - set(files))
        if missing:
            raise HuggingFaceError(f"declared files missing after download: {missing}")
        for rel in files:
            safe_join(dest, rel)  # defence-in-depth: confirm each path stays in root
        quarantine.enforce(dest, files)  # authoritative on-disk size/count guard

        digest = hash_tree(dest, files)
        if ref.expected_digest and not digests_match(digest, ref.expected_digest):
            raise DigestMismatchError(
                expected=ref.expected_digest, actual=digest, locator=repo_id
            )

        return Artifact(
            ref=pinned_ref,
            artifact_type=self._type_hint or ArtifactType.MODEL,
            quarantine_path=dest,
            files=files,
            metadata={
                "source": "huggingface",
                "repo_id": repo_id,
                "revision": sha,
                "resolved_from": revision,
            },
            digest=digest,
        )
