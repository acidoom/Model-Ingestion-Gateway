"""PR4 static scanner suite: real detection of the known-bad corpus + I9/I5."""

from __future__ import annotations

import pathlib

import pytest

from conftest import (
    make_injection_card_dir,
    make_leaked_secret_dir,
    make_malicious_code_dir,
    make_malicious_pickle_dir,
    make_model_dir,
    safetensors_bytes,
)
from mig.core.artifact import Artifact, ArtifactRef
from mig.core.context import DefaultScanContext
from mig.core.registry import gate_registry
from mig.core.verdict import GateStatus
from mig.gates import default_gates
from mig.gates.license_metadata import LicenseMetadataGate
from mig.gates.prompt_injection import PromptInjectionGate
from mig.gates.secrets import SecretsGate
from mig.gates.serialization_safety import SerializationSafetyGate
from mig.gates.static_code import StaticCodeGate
from mig.sources.local import LocalSource
from mig.storage.quarantine import Quarantine


def _fetch(tmp_path: pathlib.Path, model_dir: pathlib.Path) -> Artifact:
    ref = ArtifactRef(scheme="local", locator=str(model_dir))
    return LocalSource().fetch(ref, Quarantine(root=str(tmp_path / "q")))


# --- serialization safety (wraps picklescan) -------------------------------- #


def test_serialization_gate_detects_malicious_pickle(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = SerializationSafetyGate().evaluate(
        _fetch(tmp_path, make_malicious_pickle_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.FAIL
    assert any(f.code == "unsafe_pickle_global" for f in result.findings)
    # I5 acceptance: scanner name + version recorded in the GateResult.
    assert result.scanner_name == "picklescan"
    assert result.scanner_version


def test_serialization_gate_passes_safetensors(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = SerializationSafetyGate().evaluate(
        _fetch(tmp_path, make_model_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.PASS


# --- static code (AST) ------------------------------------------------------ #


def test_static_code_gate_detects_shell_execution(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = StaticCodeGate().evaluate(
        _fetch(tmp_path, make_malicious_code_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.FAIL
    shell = [f for f in result.findings if f.code == "shell_execution"]
    assert shell
    assert ":" in (shell[0].location or "")  # file:line reported


def test_static_code_gate_passes_benign_python(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    model = tmp_path / "benign-code"
    model.mkdir()
    (model / "model.safetensors").write_bytes(safetensors_bytes())
    (model / "helper.py").write_text("X = 1\n\n\ndef add(y):\n    return X + y\n")
    result = StaticCodeGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.PASS


def _code_dir(tmp_path: pathlib.Path, name: str, source: str) -> pathlib.Path:
    model = tmp_path / name
    model.mkdir()
    (model / "model.safetensors").write_bytes(safetensors_bytes())
    (model / "code.py").write_text(source)
    return model


def test_static_code_sees_through_from_import(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    # `from os import system; system(...)` must not evade the classifier.
    model = _code_dir(tmp_path, "from-import", "from os import system\nsystem('id')\n")
    result = StaticCodeGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "shell_execution" for f in result.findings)


def test_static_code_sees_through_aliased_import(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    model = _code_dir(tmp_path, "alias", "import os as o\no.system('id')\n")
    result = StaticCodeGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "shell_execution" for f in result.findings)


def test_static_code_one_bad_file_does_not_mask_siblings(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    # A file that fails to parse must not abort the gate and hide a sibling.
    model = tmp_path / "masking"
    model.mkdir()
    (model / "model.safetensors").write_bytes(safetensors_bytes())
    (model / "a_unparseable.py").write_text("1" + "+1" * 80000)  # over-nested
    (model / "z_evil.py").write_text("import os\nos.system('id')\n")
    result = StaticCodeGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "shell_execution" for f in result.findings)


# --- serialization gate resilience ------------------------------------------ #


def test_serialization_unscannable_file_does_not_mask_pickle(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    # A .npy (numpy not a dep → scan raises) must not abort the gate and hide a
    # sibling malicious pickle.
    model = make_malicious_pickle_dir(tmp_path)
    (model / "array.npy").write_bytes(b"\x93NUMPY-not-real")
    result = SerializationSafetyGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "unsafe_pickle_global" for f in result.findings)


def test_serialization_unavailable_warns_when_pickle_present(
    tmp_path: pathlib.Path,
    ctx: DefaultScanContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mig.gates.serialization_safety._load_picklescan", lambda: (None, "")
    )
    result = SerializationSafetyGate().evaluate(
        _fetch(tmp_path, make_malicious_pickle_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.WARN  # unscanned pickle → review, not silent
    assert any(f.code == "serialization_scan_unavailable" for f in result.findings)


def test_serialization_unavailable_passes_when_no_pickle(
    tmp_path: pathlib.Path,
    ctx: DefaultScanContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mig.gates.serialization_safety._load_picklescan", lambda: (None, "")
    )
    result = SerializationSafetyGate().evaluate(
        _fetch(tmp_path, make_model_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.PASS  # nothing to scan


# --- secrets ---------------------------------------------------------------- #


def test_secrets_gate_detects_aws_key_as_warn(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = SecretsGate().evaluate(
        _fetch(tmp_path, make_leaked_secret_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.WARN  # review, never auto-reject
    assert any(f.code == "secret_detected" for f in result.findings)


def test_secrets_gate_passes_clean_model(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = SecretsGate().evaluate(_fetch(tmp_path, make_model_dir(tmp_path)), ctx)
    assert result.status is GateStatus.PASS


# --- license / metadata ----------------------------------------------------- #


def test_license_gate_missing_license_is_info_not_review(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = LicenseMetadataGate().evaluate(
        _fetch(tmp_path, make_model_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.PASS  # missing license must not force review
    assert any(f.code == "no_license" for f in result.findings)


def test_license_gate_warns_on_restrictive_license(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    model = make_model_dir(
        tmp_path, config={"model_type": "demo", "license": "cc-by-nc-4.0"}
    )
    result = LicenseMetadataGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.WARN
    assert any(f.code == "restrictive_license" for f in result.findings)


# --- prompt injection (I9: WARN-only) --------------------------------------- #


def test_prompt_injection_is_warn_only(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = PromptInjectionGate().evaluate(
        _fetch(tmp_path, make_injection_card_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.WARN  # I9: NEVER fail/reject
    assert any(f.code == "prompt_injection_suspected" for f in result.findings)


def test_prompt_injection_passes_clean_card(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    result = PromptInjectionGate().evaluate(
        _fetch(tmp_path, make_model_dir(tmp_path)), ctx
    )
    assert result.status is GateStatus.PASS


# --- registry / wiring ------------------------------------------------------ #


def test_registry_discovers_builtin_gate_entry_points() -> None:
    registry = gate_registry()
    registry.discover()
    expected = {
        "format_allowlist",
        "digest",
        "serialization_safety",
        "secrets",
        "license_metadata",
        "static_code",
        "prompt_injection",
        "behavioral",
    }
    assert expected <= set(registry.names())
    gate = registry.create("static_code")
    assert getattr(gate, "id", None) == "static_code"


def test_default_gates_are_all_attributed() -> None:
    # Every gate must declare id/cost/applies_to so results stay traceable (I5).
    for gate in default_gates():
        assert gate.id
        assert gate.cost
        assert gate.applies_to


# --- additional coverage from the PR4 review -------------------------------- #


def test_secrets_detects_json_style_secret(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    model = make_model_dir(
        tmp_path,
        config={"model_type": "demo", "api_key": "sk-abcdef1234567890ABCD"},
    )
    result = SecretsGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.WARN
    assert any(
        f.metadata.get("secret_type") == "generic_secret_assignment"
        for f in result.findings
    )


def test_secrets_detects_encrypted_private_key(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    model = tmp_path / "enc-key"
    model.mkdir()
    (model / "model.safetensors").write_bytes(safetensors_bytes())
    (model / "key.txt").write_text(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n"
    )
    result = SecretsGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.WARN
    assert any(f.metadata.get("secret_type") == "private_key" for f in result.findings)


def test_serialization_scans_dat_extension(
    tmp_path: pathlib.Path, ctx: DefaultScanContext
) -> None:
    import pickle

    from conftest import _PickleBomb

    model = tmp_path / "dat-model"
    model.mkdir()
    (model / "weights.dat").write_bytes(pickle.dumps(_PickleBomb()))
    result = SerializationSafetyGate().evaluate(_fetch(tmp_path, model), ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "unsafe_pickle_global" for f in result.findings)
