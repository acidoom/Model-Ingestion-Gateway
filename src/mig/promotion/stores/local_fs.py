"""The local content-addressed trusted store (Zone 3) — the stdlib default.

This is the ONLY component that writes into trusted infrastructure, and it does
so only via :meth:`LocalTrustedStore.write`, called by the gated promotion
orchestrator AFTER verification + policy allow. Writes are:

* **content-addressed** — keyed by the signed, re-bound sha256 subject digest, so
  bytes can never be filed under a key that doesn't match them;
* **atomic + crash-safe** — staged into a sibling temp dir with a ``.complete``
  marker written last, then ``os.replace``-d into place; a crash leaves only a
  ``.tmp-*`` dir, never a half-populated or marker-less key;
* **idempotent** — re-promoting the same digest is a verified no-op; a key whose
  stored bytes don't re-hash to its own digest is a hard error (no-clobber).

A third I3 re-bind happens here at the store boundary (re-hash the staged tree ==
attested subject) to close any step-3→step-4 TOCTOU.
"""

from __future__ import annotations

import json
import os
import shutil
from typing import TYPE_CHECKING

from mig.core.hashing import digests_match, hash_tree, normalize_digest
from mig.evidence.canonical import canonical_bytes
from mig.evidence.dsse import encode_envelope, extract_payload_bytes
from mig.evidence.statement import subject_digest
from mig.promotion.errors import PromotionError
from mig.storage.quarantine import DEFAULT_LIMITS, stage_local_tree

if TYPE_CHECKING:
    from mig.core.artifact import Artifact
    from mig.evidence.attestation import Attestation
    from mig.evidence.dsse import Envelope

_URI_SCHEME = "mig-trusted"


def _tree_digest(root_dir: str) -> str:
    """Deterministic sha256 over every file under ``root_dir`` (rel-path bound)."""
    files: list[str] = []
    for dirpath, _dirs, names in os.walk(root_dir):
        for name in names:
            files.append(os.path.relpath(os.path.join(dirpath, name), root_dir))
    return hash_tree(root_dir, files)


def _write_blob(path: str, data: bytes) -> None:
    """Create ``path`` (0o600, must not exist) and durably write ``data``."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_tree(root_dir: str) -> None:
    """fsync every file's DATA under ``root_dir`` (shutil.copyfile does not), so a
    crash after commit cannot leave a ``.complete`` key whose artifact bytes never
    reached disk."""
    for dirpath, _dirs, names in os.walk(root_dir):
        for name in names:
            fd = os.open(os.path.join(dirpath, name), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)


class LocalTrustedStore:
    """A filesystem CAS trusted store rooted at ``root``."""

    def __init__(self, root: str) -> None:
        self._root = os.path.abspath(root)

    # -- the real writer ----------------------------------------------------- #

    def write(
        self,
        artifact: Artifact,
        *,
        envelope: Envelope,
        verify_result: object,
        receipt: object,
    ) -> tuple[str, bool]:
        """Persist the verified artifact + signed envelope + receipt; idempotent.

        Returns ``(store_uri, already_present)``. Raises :class:`PromotionError`
        on a digest mismatch, a non-atomic filesystem, or a clobber attempt.
        """
        bare = subject_digest(json.loads(extract_payload_bytes(envelope)))
        digest = normalize_digest(bare)
        key_dir = self._key_dir(bare)
        complete = os.path.join(key_dir, ".complete")
        uri = self.uri_for(bare)
        att_bytes = canonical_bytes(encode_envelope(envelope))

        if os.path.exists(complete):  # idempotent — verify the stored bytes match
            self._assert_stored_matches(key_dir, digest, att_bytes)
            return uri, True

        # I3 re-bind at the store boundary: the quarantine bytes must still match.
        live = hash_tree(artifact.quarantine_path, list(artifact.files))
        if not digests_match(live, digest):
            raise PromotionError("artifact digest changed before store write (TOCTOU)")

        os.makedirs(os.path.dirname(key_dir), mode=0o700, exist_ok=True)
        tmp = os.path.join(os.path.dirname(key_dir), f".tmp-{bare}-{os.urandom(8).hex()}")
        try:
            self._stage(tmp, artifact, att_bytes, receipt, digest)
            try:
                os.replace(tmp, key_dir)
            except OSError as exc:
                if os.path.exists(complete):  # a concurrent writer won the race
                    self._assert_stored_matches(key_dir, digest, att_bytes)
                    return uri, True
                raise PromotionError(
                    f"could not commit trusted-store entry: {exc}"
                ) from exc
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return uri, False

    # -- TrustedStore Protocol shim ----------------------------------------- #

    def promote(self, artifact: Artifact, attestation: Attestation) -> str:
        """Protocol conformance only. The orchestrator calls :meth:`write`, which
        persists the SIGNED envelope an :class:`Attestation` alone cannot carry."""
        raise NotImplementedError(
            "LocalTrustedStore.promote() is the type seam; use write(envelope=...)"
        )

    # -- internals ----------------------------------------------------------- #

    def _key_dir(self, bare_hex: str) -> str:
        return os.path.join(self._root, "cas", "sha256", bare_hex[:2], bare_hex)

    def uri_for(self, bare_hex: str) -> str:
        """The stable ``mig-trusted://`` URI for a content digest."""
        return f"{_URI_SCHEME}://sha256/{bare_hex}"

    def _stage(
        self,
        tmp: str,
        artifact: Artifact,
        att_bytes: bytes,
        receipt: object,
        digest: str,
    ) -> None:
        os.makedirs(tmp, mode=0o700)
        artifact_dir = os.path.join(tmp, "artifact")
        os.makedirs(artifact_dir, mode=0o700)
        # Copy from the verified quarantine with traversal + symlink guards.
        stage_local_tree(artifact.quarantine_path, artifact_dir, DEFAULT_LIMITS)
        staged = _tree_digest(artifact_dir)
        if not digests_match(staged, digest):  # the copy must be faithful
            raise PromotionError("staged trusted-store tree does not match the digest")
        _fsync_tree(artifact_dir)  # the copied DATA must be durable, not just dir entries
        _write_blob(os.path.join(tmp, "attestation.dsse.json"), att_bytes)
        _write_blob(os.path.join(tmp, "receipt.json"), canonical_bytes(receipt))
        _write_blob(os.path.join(tmp, ".complete"), b"")  # the commit marker — LAST
        self._fsync_dir(tmp)

    def _assert_stored_matches(self, key_dir: str, digest: str, att_bytes: bytes) -> None:
        # The artifact tree must still re-hash to the key (content integrity)...
        stored = _tree_digest(os.path.join(key_dir, "artifact"))
        if not digests_match(stored, digest):
            raise PromotionError(
                f"trusted-store entry digest mismatch at {key_dir!r} (corruption?)"
            )
        # ...AND the persisted SIGNED attestation must be the one being promoted
        # (its provenance can't be silently swapped for a different signed envelope).
        att_path = os.path.join(key_dir, "attestation.dsse.json")
        try:
            with open(att_path, "rb") as handle:
                on_disk = handle.read()
        except OSError as exc:
            raise PromotionError(
                f"trusted-store entry missing attestation: {exc}"
            ) from exc
        if on_disk != att_bytes:
            raise PromotionError(
                f"trusted-store attestation mismatch at {key_dir!r} (tampered?)"
            )

    @staticmethod
    def _fsync_dir(path: str) -> None:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)
