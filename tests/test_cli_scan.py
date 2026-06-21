"""PR2 acceptance: `mig scan <local path>` → verdict JSON end to end."""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from conftest import make_model_dir, make_pickle_model_dir
from mig.cli.main import main


def _run(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_scan_model_emits_verdict_json_with_behavioral_skipped(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run(["scan", str(make_model_dir(tmp_path))], capsys)
    assert code == 0
    verdict: dict[str, Any] = json.loads(out)
    assert verdict["decision"] in {"approve", "review_required", "reject"}
    behavioral = [g for g in verdict["gate_results"] if g["gate_id"] == "behavioral"]
    assert behavioral, "behavioral gate result must be present"
    assert behavioral[0]["status"] == "skipped"  # I7 visible end to end
    assert behavioral[0]["rigor"] == "none"


def test_scan_clean_model_approves(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _code, out, _ = _run(["scan", str(make_model_dir(tmp_path))], capsys)
    assert json.loads(out)["decision"] == "approve"


def test_scan_pickle_model_rejects(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _code, out, _ = _run(["scan", str(make_pickle_model_dir(tmp_path))], capsys)
    assert json.loads(out)["decision"] == "reject"


def test_scan_executable_type_never_approves(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # I8 / QS-2: a static-only run on an executable type can never APPROVE.
    _code, out, _ = _run(
        ["scan", str(make_model_dir(tmp_path)), "--type", "mcp_server"], capsys
    )
    assert json.loads(out)["decision"] == "review_required"


def test_scan_missing_path_is_an_error(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _out, err = _run(["scan", str(tmp_path / "nope")], capsys)
    assert code == 2
    assert "not found" in err


def test_scan_rejects_remote_scheme_until_pr3(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, _out, err = _run(["scan", "hf://org/model"], capsys)
    assert code == 2
    assert "PR3" in err


def test_compact_output_is_single_line(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _code, out, _ = _run(["scan", str(make_model_dir(tmp_path)), "--compact"], capsys)
    assert out.strip().count("\n") == 0
    json.loads(out)  # still valid JSON


def test_manifest_lists_files_and_digest(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run(["manifest", str(make_model_dir(tmp_path))], capsys)
    assert code == 0
    manifest: dict[str, Any] = json.loads(out)
    assert set(manifest["files"]) == {"model.safetensors", "config.json"}
    assert manifest["digest"].startswith("sha256:")
    assert manifest["artifact_type"] == "model"
