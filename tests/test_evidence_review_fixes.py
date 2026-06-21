"""Regression tests for the PR7 adversarial-review findings.

Each test pins a fail-closed/robustness property that the review found missing:
non-str-key collision resistance on the SIGNED path, binary rejection, malformed
base64/signature handling, and the re-bind-can't-run-is-a-verification-failure rule.
"""

from __future__ import annotations

import pathlib

import pytest

from conftest import make_model_dir
from mig.core.artifact import Artifact, ArtifactRef, ArtifactType
from mig.core.verdict import Decision, GateResult, GateStatus, RigorLevel, Verdict
from mig.evidence.builder import build_attestation
from mig.evidence.canonical import canonical_bytes
from mig.evidence.dsse import encode_envelope
from mig.evidence.signing import HMACSigner, HMACVerifier, sign_statement
from mig.evidence.statement import statement_from_attestation
from mig.evidence.verify import verify_attestation
from mig.policy.schema import Policy
from mig.sources.local import LocalSource
from mig.storage.quarantine import Quarantine

_KEY = b"k" * 32
_CREATED = "2026-01-01T00:00:00Z"


def _artifact(tmp_path: pathlib.Path) -> Artifact:
    model = make_model_dir(tmp_path)
    return LocalSource(artifact_type=ArtifactType.MODEL).fetch(
        ArtifactRef(scheme="local", locator=str(model)),
        Quarantine(root=str(tmp_path / "q")),
    )


def _verdict(artifact: Artifact) -> Verdict:
    return Verdict(
        ref=artifact.ref,
        artifact_type=artifact.artifact_type,
        gate_results=[
            GateResult(
                "static_code",
                GateStatus.PASS,
                RigorLevel.STATIC,
                scanner_name="ast",
                scanner_version="1",
            )
        ],
        decision=Decision.APPROVE,
    )


def _signed_envelope(statement: dict[str, object]) -> dict[str, object]:
    return encode_envelope(sign_statement(statement, HMACSigner(_KEY)))


# --- #1: non-string metadata keys are rejected on the SIGNED path ----------- #


def test_non_str_metadata_key_rejected_on_signed_path(tmp_path: pathlib.Path) -> None:
    artifact = _artifact(tmp_path)
    att = build_attestation(
        _verdict(artifact),
        artifact,
        policy=Policy(id="p", version="1"),
        mig_version="0",
        confinement_level="noop",
        created_at=_CREATED,
        metadata={1: "x"},  # type: ignore[dict-item]  # non-str key must not coerce
    )
    with pytest.raises(ValueError):
        statement_from_attestation(att)  # projects via canonicalize → rejects


# --- #5: canonical encoder rejects all binary buffer types ------------------ #


def test_canonical_rejects_bytearray_and_memoryview() -> None:
    with pytest.raises(ValueError):
        canonical_bytes({"x": bytearray(b"ab")})
    with pytest.raises(ValueError):
        canonical_bytes({"x": memoryview(b"ab")})


# --- #4/#9: a corrupt base64 signature is a verification failure ------------- #


def test_corrupt_base64_signature_is_verification_failure(tmp_path: pathlib.Path) -> None:
    artifact = _artifact(tmp_path)
    att = build_attestation(
        _verdict(artifact),
        artifact,
        policy=Policy(id="p", version="1"),
        mig_version="0",
        confinement_level="noop",
        created_at=_CREATED,
    )
    env = _signed_envelope(statement_from_attestation(att))
    env["signatures"] = [dict(env["signatures"][0])]  # type: ignore[index]
    env["signatures"][0]["sig"] = "not!valid!base64"  # type: ignore[index]
    result = verify_attestation(env, artifact=artifact, verifier=HMACVerifier(_KEY))
    assert result.checks["signature"] is False
    assert not result.ok


# --- #6: signature valid but re-bind can't run → fail closed ---------------- #


def test_signed_statement_without_subject_fails_closed(tmp_path: pathlib.Path) -> None:
    artifact = _artifact(tmp_path)
    att = build_attestation(
        _verdict(artifact),
        artifact,
        policy=Policy(id="p", version="1"),
        mig_version="0",
        confinement_level="noop",
        created_at=_CREATED,
    )
    statement = statement_from_attestation(att)
    statement["subject"] = []  # authenticated payload, but nothing to re-bind to
    env = _signed_envelope(statement)
    result = verify_attestation(env, artifact=artifact, verifier=HMACVerifier(_KEY))
    assert result.checks["signature"] is True  # signature itself is valid...
    assert not result.ok  # ...but the I3 re-bind cannot run → not verified
