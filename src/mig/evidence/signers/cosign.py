"""cosign CLI wrapper — opt-in (``mig[cosign]``, plus the ``cosign`` binary).

Structurally a twin of :mod:`mig.sandbox.docker`: an optional capability that
drives a host CLI through a single injectable seam (:func:`_run_cosign`,
monkeypatched in unit tests so no real binary is needed). It signs/verifies the
**same DSSE PAE bytes** as the HMAC/ed25519 backends — written to a scratch file
and passed to ``cosign sign-blob`` / ``cosign verify-blob`` — so a cosign
signature verifies under the identical PAE contract (no message mismatch).

Keyless (Fulcio/Rekor/OIDC) is an explicit non-goal for PR7's offline default;
only ``--key`` (file / KMS URI) signing is wired. Needs no Python dependency.
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile

from mig.evidence.dsse import b64
from mig.evidence.signing import SigningError

#: Scheme tag carried in the DSSE signature.
COSIGN_SCHEME = "cosign"


class CosignUnavailableError(SigningError):
    """Raised when the cosign CLI cannot be found or run."""


def _run_cosign(
    cosign_bin: str, args: list[str], *, timeout_s: int = 120
) -> tuple[int | None, str, str]:
    """Invoke ``cosign`` and return ``(exit, stdout, stderr)``.

    The single seam every cosign invocation passes through — monkeypatched in
    unit tests so they need no cosign binary.
    """
    try:
        proc = subprocess.run(
            [cosign_bin, *args],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CosignUnavailableError(f"cosign CLI not found: {cosign_bin!r}") from exc
    except subprocess.TimeoutExpired as exc:
        # A hung cosign/KMS must fail closed-cleanly, not escape as an uncaught
        # SubprocessError (which neither verify nor the CLI catches).
        raise CosignUnavailableError(f"cosign timed out after {timeout_s}s") from exc
    except OSError as exc:
        raise CosignUnavailableError(f"cosign could not be run: {exc}") from exc
    return proc.returncode, proc.stdout, proc.stderr


def _scratch(data: bytes, suffix: str) -> str:
    fd, path = tempfile.mkstemp(prefix="mig-cosign-", suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except OSError:  # a write failure must not leave the temp file behind
        os.unlink(path)
        raise
    return path


class CosignSigner:
    """Signs the DSSE PAE bytes via ``cosign sign-blob`` over a scratch file."""

    scheme = COSIGN_SCHEME

    def __init__(self, key_ref: str, *, cosign_bin: str = "cosign") -> None:
        self._key_ref = key_ref
        self._cosign_bin = cosign_bin
        # keyid is advisory only (verify never trusts it) — a stable, non-secret tag.
        self.key_id = hashlib.sha256(key_ref.encode("utf-8")).hexdigest()[:16]

    def sign(self, message: bytes) -> bytes:
        pae_path = _scratch(message, ".pae")
        try:
            exit_code, stdout, stderr = _run_cosign(
                self._cosign_bin,
                [
                    "sign-blob",
                    "--key",
                    self._key_ref,
                    "--tlog-upload=false",
                    "--yes",
                    pae_path,
                ],
            )
        finally:
            os.unlink(pae_path)
        if exit_code != 0:
            raise SigningError(f"cosign sign-blob failed: {stderr.strip()[:200]}")
        token = stdout.strip()
        try:
            # binascii.Error (raised on bad base64) is a subclass of ValueError.
            return base64.b64decode(token, validate=True)
        except ValueError as exc:  # garbage output → fail closed
            raise SigningError("cosign produced no parseable signature") from exc


class CosignVerifier:
    """Verifies a cosign signature over the DSSE PAE bytes via ``verify-blob``."""

    scheme = COSIGN_SCHEME

    def __init__(self, key_ref: str, *, cosign_bin: str = "cosign") -> None:
        self._key_ref = key_ref
        self._cosign_bin = cosign_bin
        self.key_id = hashlib.sha256(key_ref.encode("utf-8")).hexdigest()[:16]

    def verify(self, message: bytes, signature: bytes) -> bool:
        # Create both scratch files INSIDE the try so a failure on the second
        # never leaks the first (the finally unlinks whatever exists).
        pae_path: str | None = None
        sig_path: str | None = None
        try:
            pae_path = _scratch(message, ".pae")
            sig_path = _scratch(b64(signature).encode("ascii"), ".sig")
            exit_code, _stdout, _stderr = _run_cosign(
                self._cosign_bin,
                [
                    "verify-blob",
                    "--key",
                    self._key_ref,
                    "--insecure-ignore-tlog=true",
                    "--signature",
                    sig_path,
                    pae_path,
                ],
            )
        finally:
            for path in (pae_path, sig_path):
                if path is not None:
                    os.unlink(path)
        return exit_code == 0  # any non-zero / error → fail closed


def cosign_available(cosign_bin: str = "cosign") -> bool:
    """True if the cosign CLI is reachable (used to skip integration tests)."""
    try:
        exit_code, _out, _err = _run_cosign(cosign_bin, ["version"], timeout_s=10)
    except CosignUnavailableError:
        return False
    return exit_code == 0
