"""Format-allowlist, digest, and behavioral gates."""

from __future__ import annotations

import pathlib

from conftest import (
    make_model_dir,
    make_pickle_model_dir,
    make_trust_remote_code_dir,
    safetensors_bytes,
)
from mig.core.artifact import Artifact, ArtifactRef
from mig.core.context import DefaultScanContext
from mig.core.verdict import GateStatus, RigorLevel, Severity
from mig.gates.behavioral import BehavioralGate
from mig.gates.digest import DigestGate
from mig.gates.format_allowlist import FormatAllowlistGate
from mig.sources.local import LocalSource
from mig.storage.quarantine import Quarantine


def _fetch(tmp_path: pathlib.Path, model_dir: pathlib.Path) -> Artifact:
    ref = ArtifactRef(scheme="local", locator=str(model_dir))
    return LocalSource().fetch(ref, Quarantine(root=str(tmp_path / "q")))


# --- format allowlist ------------------------------------------------------- #


def test_format_gate_passes_safetensors(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = FormatAllowlistGate().evaluate(
        _fetch(tmp_path, make_model_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.PASS
    assert result.scanner_name == "mig.format_allowlist"
    assert result.scanner_version  # I5: executed gate is attributed


def test_format_gate_fails_pickle_weights(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = FormatAllowlistGate().evaluate(
        _fetch(tmp_path, make_pickle_model_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.FAIL
    assert any(f.code == "unsafe_serialization_format" for f in result.findings)


def test_format_gate_warns_on_trust_remote_code(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = FormatAllowlistGate().evaluate(
        _fetch(tmp_path, make_trust_remote_code_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.WARN
    codes = {f.code for f in result.findings}
    assert "trust_remote_code" in codes
    assert "custom_model_code" in codes  # modeling_demo.py companion


def test_format_gate_fails_joblib_and_dill(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    model = tmp_path / "joblib-model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(safetensors_bytes())
    (model / "preprocessor.joblib").write_bytes(b"\x80\x04joblib-pickle")
    result = FormatAllowlistGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "unsafe_serialization_format" for f in result.findings)


def test_format_gate_warns_on_code_on_load_formats(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    model = tmp_path / "npy-model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(safetensors_bytes())
    (model / "array.npy").write_bytes(b"\x93NUMPY-array")
    result = FormatAllowlistGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.WARN
    assert any(f.code == "code_on_load_format" for f in result.findings)


def test_format_gate_catches_compound_pickle_extension(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    # model.pkl.gz must classify as the pickle it is, not be waved through as .gz.
    model = tmp_path / "gz-model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(safetensors_bytes())
    (model / "weights.pkl.gz").write_bytes(b"\x1f\x8bcompressed-pickle")
    result = FormatAllowlistGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "unsafe_serialization_format" for f in result.findings)


def test_format_gate_warns_on_archive(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    model = tmp_path / "tar-model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(safetensors_bytes())
    (model / "extras.tar.gz").write_bytes(b"\x1f\x8barchive")
    result = FormatAllowlistGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.WARN
    assert any(f.code == "archive_format" for f in result.findings)


def test_format_gate_survives_adversarial_nested_config(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    # A deeply-nested config.json makes json.loads raise RecursionError; the gate
    # must NOT error out and discard the CRITICAL pickle finding (REJECT must
    # survive, not downgrade to REVIEW_REQUIRED).
    model = tmp_path / "evil-model"
    model.mkdir()
    (model / "pytorch_model.bin").write_bytes(b"\x80\x04pickle")
    (model / "config.json").write_text("[" * 100_000 + "]" * 100_000)
    result = FormatAllowlistGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.FAIL
    assert any(
        f.code == "unsafe_serialization_format" and f.severity is Severity.CRITICAL
        for f in result.findings
    )


# --- digest / manifest ------------------------------------------------------ #


def test_digest_gate_notes_unpinned_and_records_manifest(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    artifact = _fetch(tmp_path, make_model_dir(tmp_path))
    result = DigestGate().evaluate(artifact, ctx)
    assert result.status is GateStatus.PASS
    assert any(f.code == "unpinned_reference" for f in result.findings)
    assert result.evidence["digest"] == artifact.digest
    assert "safetensors_manifest" in result.evidence


def test_digest_gate_fails_on_malformed_safetensors(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    bad = tmp_path / "bad-model"
    bad.mkdir()
    (bad / "model.safetensors").write_bytes(b"\x00\x00\x00\x00")  # < 8-byte prefix
    result = DigestGate().evaluate(_fetch(tmp_path, bad), ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "malformed_safetensors" for f in result.findings)


def test_digest_gate_fails_on_pinned_mismatch(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    model = make_model_dir(tmp_path)
    # Construct an artifact with a deliberately wrong pin (bypassing the source's
    # own fetch-time check) to exercise the gate's defence-in-depth path.
    artifact = LocalSource().fetch(
        ArtifactRef(scheme="local", locator=str(model)),
        Quarantine(root=str(tmp_path / "q")),
    )
    pinned = Artifact(
        ref=ArtifactRef(
            scheme="local", locator=str(model), expected_digest="sha256:nope"
        ),
        artifact_type=artifact.artifact_type,
        quarantine_path=artifact.quarantine_path,
        files=artifact.files,
        digest=artifact.digest,
    )
    result = DigestGate().evaluate(pinned, ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "digest_mismatch" for f in result.findings)


# --- behavioral ------------------------------------------------------------- #


def test_behavioral_gate_skips_under_noop(
    model_artifact: Artifact, ctx: DefaultScanContext
) -> None:
    result = BehavioralGate().evaluate(model_artifact, ctx)
    assert result.gate_id == "behavioral"
    assert result.status is GateStatus.SKIPPED
    assert result.rigor is RigorLevel.NONE
    assert any(f.code == "behavioral_analysis_skipped" for f in result.findings)
