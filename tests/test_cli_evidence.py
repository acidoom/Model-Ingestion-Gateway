"""PR7 — CLI: ``mig ingest`` / ``mig verify`` / ``mig evidence`` end-to-end.

Exercises the real fetch → scan → attest → sign → verify path against a local
fixture with the stdlib HMAC default (no extras needed). Verifies the exit-code
contract: 0 ok, 1 below --fail-on, 2 operator error, 3 verification failure.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from conftest import make_model_dir
from mig.cli.main import main
from mig.evidence.dsse import PAYLOAD_TYPE


def _keyfile(tmp_path: pathlib.Path, *, nbytes: int = 32) -> str:
    path = tmp_path / "signing.key"
    path.write_bytes(b"K" * nbytes)
    return str(path)


def test_ingest_emits_valid_dsse_envelope(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    out = tmp_path / "att.dsse.json"
    code = main(["ingest", str(model), "--key", _keyfile(tmp_path), "--out", str(out)])
    assert code == 0
    envelope = json.loads(out.read_text())
    assert envelope["payloadType"] == PAYLOAD_TYPE
    assert envelope["signatures"][0]["scheme"] == "hmac-sha256"


def test_ingest_then_verify_roundtrip(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    key = _keyfile(tmp_path)
    out = tmp_path / "att.dsse.json"
    assert main(["ingest", str(model), "--key", key, "--out", str(out)]) == 0
    code = main(["verify", str(model), "--attestation", str(out), "--key", key])
    assert code == 0  # verified


def test_verify_detects_tampered_artifact(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    key = _keyfile(tmp_path)
    out = tmp_path / "att.dsse.json"
    assert main(["ingest", str(model), "--key", key, "--out", str(out)]) == 0
    # Mutate the artifact AFTER attesting → the re-bind digest no longer matches.
    (model / "config.json").write_text('{"model_type": "tampered"}')
    code = main(["verify", str(model), "--attestation", str(out), "--key", key])
    assert code == 3  # verification failure (distinct from operator error)


def test_verify_wrong_key_is_failure_not_operator_error(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    out = tmp_path / "att.dsse.json"
    assert (
        main(["ingest", str(model), "--key", _keyfile(tmp_path), "--out", str(out)]) == 0
    )
    other = tmp_path / "other.key"
    other.write_bytes(b"D" * 32)
    code = main(["verify", str(model), "--attestation", str(out), "--key", str(other)])
    assert code == 3  # bad signature → verification failure


def test_ingest_refuses_short_key(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    code = main(["ingest", str(model), "--key", _keyfile(tmp_path, nbytes=8)])
    assert code == 2  # operator error (key too short)


def test_verify_missing_attestation_file_is_operator_error(
    tmp_path: pathlib.Path,
) -> None:
    model = make_model_dir(tmp_path)
    code = main(
        [
            "verify",
            str(model),
            "--attestation",
            str(tmp_path / "nope.json"),
            "--key",
            _keyfile(tmp_path),
        ]
    )
    assert code == 2


def test_env_key_and_newline_terminated_file_verify_equivalently(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Sign via MIG_SIGNING_KEY (no newline); verify via a key FILE carrying the
    # same secret + a trailing newline (what `echo`/editors write). The newline is
    # stripped so it is the SAME key — a spurious tamper alarm would be exit 3.
    model = make_model_dir(tmp_path)
    secret = "S" * 40
    monkeypatch.setenv("MIG_SIGNING_KEY", secret)
    out = tmp_path / "att.dsse.json"
    assert main(["ingest", str(model), "--out", str(out)]) == 0
    monkeypatch.delenv("MIG_SIGNING_KEY", raising=False)
    keyfile = tmp_path / "k.key"
    keyfile.write_bytes(secret.encode("utf-8") + b"\n")
    assert (
        main(["verify", str(model), "--attestation", str(out), "--key", str(keyfile)])
        == 0
    )


def test_ingest_bad_output_path_is_operator_error(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    bad = tmp_path / "no" / "such" / "dir" / "att.json"
    code = main(["ingest", str(model), "--key", _keyfile(tmp_path), "--out", str(bad)])
    assert code == 2  # unwritable --out → clean operator error, not a traceback


def test_verify_malformed_signature_object_is_operator_error(
    tmp_path: pathlib.Path,
) -> None:
    model = make_model_dir(tmp_path)
    key = _keyfile(tmp_path)
    out = tmp_path / "att.dsse.json"
    assert main(["ingest", str(model), "--key", key, "--out", str(out)]) == 0
    env = json.loads(out.read_text())
    del env["signatures"][0]["sig"]  # malformed envelope
    out.write_text(json.dumps(env))
    code = main(["verify", str(model), "--attestation", str(out), "--key", key])
    assert code == 2  # malformed input → operator error (not a crash)


def test_verify_corrupt_base64_signature_is_failure_not_operator_error(
    tmp_path: pathlib.Path,
) -> None:
    model = make_model_dir(tmp_path)
    key = _keyfile(tmp_path)
    out = tmp_path / "att.dsse.json"
    assert main(["ingest", str(model), "--key", key, "--out", str(out)]) == 0
    env = json.loads(out.read_text())
    env["signatures"][0]["sig"] = "not!base64!"  # corrupt the signature bytes
    out.write_text(json.dumps(env))
    code = main(["verify", str(model), "--attestation", str(out), "--key", key])
    assert code == 3  # tamper/corruption → verification failure, distinct from 2


def test_evidence_emits_bundle(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    out = tmp_path / "bundle.json"
    code = main(["evidence", str(model), "--key", _keyfile(tmp_path), "--out", str(out)])
    assert code == 0
    bundle = json.loads(out.read_text())
    assert bundle["schema"].endswith("/evidence-bundle/v1")
    assert "envelope" in bundle and "verdict" in bundle and "run" in bundle


def test_ingest_fail_on_review_exit_code(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An MCP_SERVER with the default NoopSandbox is REVIEW_REQUIRED (I8): --fail-on
    # review must make ingest exit 1 while STILL emitting the (honest) attestation.
    model = make_model_dir(tmp_path)
    out = tmp_path / "att.dsse.json"
    code = main(
        [
            "ingest",
            str(model),
            "--type",
            "mcp_server",
            "--key",
            _keyfile(tmp_path),
            "--out",
            str(out),
            "--fail-on",
            "review",
        ]
    )
    assert code == 1
    assert out.exists()  # the attestation is still produced
    envelope = json.loads(out.read_text())
    statement = json.loads(base64.b64decode(envelope["payload"]))
    assert statement["predicate"]["decision"] == "review_required"
