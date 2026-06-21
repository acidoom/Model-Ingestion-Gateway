"""PR7 — the cosign CLI signer wrapper (injectable seam; no real binary needed).

The seam ``_run_cosign`` is monkeypatched exactly as ``test_docker_sandbox``
patches ``_run_docker``. A realistic fake signs/verifies an HMAC over the PAE
*file contents*, so these tests prove the wrapper operates on the identical PAE
bytes the other backends sign — not a different message.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Callable

import pytest

import mig.evidence.signers.cosign as cosign_mod
from mig.evidence.dsse import encode_envelope
from mig.evidence.signers.cosign import cosign_available
from mig.evidence.signing import (
    SigningError,
    make_signer,
    make_verifier,
    sign_statement,
    verify_envelope,
)

_SECRET = b"cosign-fake-secret-key-0123456789"
_STATEMENT = {"_type": "x", "predicate": {"decision": "approve"}}

RunFn = Callable[..., tuple[int | None, str, str]]


def _faithful_cosign(secret: bytes, captured: list[list[str]]) -> RunFn:
    """A fake cosign that HMACs the PAE *file* on sign and re-checks it on verify."""

    def run(
        cosign_bin: str, args: list[str], *, timeout_s: int = 120
    ) -> tuple[int | None, str, str]:
        captured.append(args)
        sub = args[0]
        pae_path = args[-1]
        with open(pae_path, "rb") as handle:
            data = handle.read()
        if sub == "sign-blob":
            sig = hmac.new(secret, data, hashlib.sha256).digest()
            return 0, base64.b64encode(sig).decode("ascii"), ""
        if sub == "verify-blob":
            sig_path = args[args.index("--signature") + 1]
            with open(sig_path, "rb") as handle:
                provided = base64.b64decode(handle.read())
            expected = hmac.new(secret, data, hashlib.sha256).digest()
            return (0 if hmac.compare_digest(provided, expected) else 1), "", ""
        return 1, "", "unknown subcommand"

    return run


def test_cosign_argv_shape_and_full_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(cosign_mod, "_run_cosign", _faithful_cosign(_SECRET, captured))

    env = sign_statement(_STATEMENT, make_signer("cosign", key_ref="cosign.key"))
    assert env.signatures[0].scheme == "cosign"
    sign_args = captured[0]
    assert sign_args[0] == "sign-blob"
    assert "--tlog-upload=false" in sign_args
    assert sign_args[-1].endswith(".pae")  # signs the PAE scratch file

    statement = verify_envelope(env, make_verifier("cosign", key_ref="cosign.pub"))
    assert statement["predicate"]["decision"] == "approve"
    assert captured[-1][0] == "verify-blob"
    assert "--signature" in captured[-1]


def test_cosign_tamper_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(cosign_mod, "_run_cosign", _faithful_cosign(_SECRET, captured))
    env = sign_statement(_STATEMENT, make_signer("cosign", key_ref="k"))
    # A verifier keyed to a DIFFERENT secret must reject (the fake checks the HMAC).
    monkeypatch.setattr(
        cosign_mod, "_run_cosign", _faithful_cosign(b"other-secret", captured)
    )
    from mig.evidence.signing import VerificationError

    with pytest.raises(VerificationError):
        verify_envelope(env, make_verifier("cosign", key_ref="k"))


def test_cosign_sign_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cosign_mod, "_run_cosign", lambda b, a, *, timeout_s=120: (1, "", "boom")
    )
    with pytest.raises(SigningError):
        make_signer("cosign", key_ref="k").sign(b"pae")


def test_cosign_garbage_signature_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cosign_mod, "_run_cosign", lambda b, a, *, timeout_s=120: (0, "!!!not-b64!!!", "")
    )
    with pytest.raises(SigningError):
        make_signer("cosign", key_ref="k").sign(b"pae")


def test_cosign_unavailable_binary_is_false() -> None:
    assert cosign_available("mig-no-such-cosign-binary-xyz") is False


def test_cosign_timeout_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A hung cosign must become a clean CosignUnavailableError (a SigningError),
    # not an uncaught subprocess.TimeoutExpired escaping verify/the CLI.
    import subprocess

    from mig.evidence.signers.cosign import CosignUnavailableError, _run_cosign

    def boom(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd="cosign", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(CosignUnavailableError):
        _run_cosign("cosign", ["version"])
    assert cosign_available() is False  # times out → unavailable, never raises


def test_cosign_encode_roundtrips(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(cosign_mod, "_run_cosign", _faithful_cosign(_SECRET, captured))
    env = sign_statement(_STATEMENT, make_signer("cosign", key_ref="k"))
    assert encode_envelope(env)["signatures"][0]["scheme"] == "cosign"
