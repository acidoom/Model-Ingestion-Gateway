"""PR2 acceptance: `mig scan <local path>` → verdict JSON end to end."""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
from typing import Any

import pytest

from conftest import (
    install_fake_hf_hub,
    make_malicious_code_dir,
    make_malicious_pickle_dir,
    make_model_dir,
    make_pickle_model_dir,
    make_trust_remote_code_dir,
    safetensors_bytes,
)
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


def test_scan_malicious_pickle_corpus_rejects(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # End to end: picklescan flags the os.system opcode → REJECT.
    _code, out, _ = _run(["scan", str(make_malicious_pickle_dir(tmp_path))], capsys)
    verdict: dict[str, Any] = json.loads(out)
    assert verdict["decision"] == "reject"
    codes = {f["code"] for g in verdict["gate_results"] for f in g["findings"]}
    assert "unsafe_pickle_global" in codes


def test_scan_malicious_code_corpus_rejects(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # End to end: the AST static-code gate flags os.system in modeling_*.py.
    _code, out, _ = _run(["scan", str(make_malicious_code_dir(tmp_path))], capsys)
    verdict: dict[str, Any] = json.loads(out)
    assert verdict["decision"] == "reject"
    codes = {f["code"] for g in verdict["gate_results"] for f in g["findings"]}
    assert "shell_execution" in codes


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


def test_scan_unsupported_scheme_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, _out, err = _run(["scan", "s3://bucket/model"], capsys)
    assert code == 2
    assert "unsupported scheme" in err


def test_scan_huggingface_ref_end_to_end(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    install_fake_hf_hub(
        monkeypatch,
        sha="a" * 40,
        files={
            "model.safetensors": safetensors_bytes(),
            "config.json": b'{"model_type": "demo"}',
        },
    )
    code, out, _ = _run(["scan", "hf://org/model@main"], capsys)
    assert code == 0
    verdict: dict[str, Any] = json.loads(out)
    assert verdict["ref"]["scheme"] == "huggingface"
    assert verdict["ref"]["revision"] == "a" * 40  # pinned SHA in the verdict
    assert verdict["decision"] == "approve"


def test_scan_hf_missing_repo_id_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, _out, err = _run(["scan", "hf://"], capsys)
    assert code == 2
    assert "repo id" in err


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


def test_scan_with_correct_digest_pin_succeeds(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    model = make_model_dir(tmp_path)
    _code, out, _ = _run(["manifest", str(model)], capsys)
    digest = json.loads(out)["digest"]
    code, _out, _err = _run(["scan", str(model), "--digest", digest], capsys)
    assert code == 0  # I3: a correct pin verifies and the scan proceeds


def test_scan_with_wrong_digest_pin_errors(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _out, err = _run(
        ["scan", str(make_model_dir(tmp_path)), "--digest", "sha256:" + "0" * 64],
        capsys,
    )
    assert code == 2
    assert "mismatch" in err


def test_scan_cleans_up_quarantine(
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[str] = []
    real_mkdtemp = tempfile.mkdtemp

    def spy(
        suffix: str | None = None,
        prefix: str | None = None,
        dir: str | None = None,
    ) -> str:
        path = real_mkdtemp(suffix, prefix, dir)
        created.append(path)
        return path

    monkeypatch.setattr(tempfile, "mkdtemp", spy)
    _run(["scan", str(make_model_dir(tmp_path))], capsys)
    assert created  # the CLI did allocate a quarantine
    assert not os.path.exists(created[0])  # ...and cleaned it up


def test_pickle_scan_short_circuits_behavioral(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _code, out, _ = _run(["scan", str(make_pickle_model_dir(tmp_path))], capsys)
    verdict: dict[str, Any] = json.loads(out)
    gate_ids = [g["gate_id"] for g in verdict["gate_results"]]
    assert "behavioral" not in gate_ids  # expensive gate skipped after cheap FAIL


def test_scan_trust_remote_code_is_review_required(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # I9: a WARN (trust_remote_code) reduces to review at the CLI, not reject.
    _code, out, _ = _run(["scan", str(make_trust_remote_code_dir(tmp_path))], capsys)
    assert json.loads(out)["decision"] == "review_required"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_scan_artifact_with_symlink_errors(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    model = tmp_path / "model"
    model.mkdir()
    (model / "model.safetensors").write_bytes(safetensors_bytes())
    outside = tmp_path / "secret"
    outside.write_bytes(b"secret")
    (model / "link").symlink_to(outside)
    code, _out, err = _run(["scan", str(model)], capsys)
    assert code == 2  # QuarantineError surfaces as a clean failure
    assert "symlink" in err


# --- PR5: --policy / --fail-on / policy test -------------------------------- #


def test_scan_with_policy_changes_decision(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    model = make_model_dir(tmp_path)  # clean → baseline APPROVE
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "id: p\nversion: 1\nrules:\n"
        "  - id: flag_all_models\n"
        "    when: {artifact.type: model}\n"
        "    action: reject\n"
        "    severity: high\n"
    )
    _code, out, _ = _run(["scan", str(model), "--policy", str(policy)], capsys)
    assert json.loads(out)["decision"] == "reject"


def test_fail_on_reject_exit_codes(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad, _o, _e = _run(
        ["scan", str(make_pickle_model_dir(tmp_path)), "--fail-on", "reject"], capsys
    )
    assert bad == 1
    ok, _o2, _e2 = _run(
        ["scan", str(make_model_dir(tmp_path)), "--fail-on", "reject"], capsys
    )
    assert ok == 0


def test_fail_on_review_exit_code(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _o, _e = _run(
        ["scan", str(make_trust_remote_code_dir(tmp_path)), "--fail-on", "review"],
        capsys,
    )
    assert code == 1  # trust_remote_code → review_required → fails the review gate


def test_policy_test_reports_matched_rules(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    model = make_model_dir(tmp_path)
    policy = tmp_path / "p.json"
    policy.write_text(
        json.dumps(
            {
                "id": "p",
                "version": "1",
                "rules": [
                    {
                        "id": "flag_models",
                        "when": {"artifact.type": "model"},
                        "action": "require_review",
                        "severity": "medium",
                    }
                ],
            }
        )
    )
    code, out, _ = _run(["policy", "test", str(model), "--policy", str(policy)], capsys)
    assert code == 0
    report: dict[str, Any] = json.loads(out)
    assert report["decision"] == "review_required"
    assert [r["id"] for r in report["matched_rules"]] == ["flag_models"]


def test_scan_bad_policy_errors(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: p\nrules:\n  - id: r\n    action: nope\n")
    code, _out, err = _run(
        ["scan", str(make_model_dir(tmp_path)), "--policy", str(bad)], capsys
    )
    assert code == 2
    assert "nope" in err or "action" in err


def test_scan_eval_invalid_policy_errors_cleanly(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Schema-valid but references an unknown condition → eval-time PolicyError.
    # Must exit 2 (operator error) with a message, not a traceback / exit 1.
    bad = tmp_path / "evalbad.yaml"
    bad.write_text(
        "id: p\nversion: 1\nrules:\n"
        "  - id: r\n    when: {bogus.cond: x}\n    action: reject\n    severity: high\n"
    )
    code, _out, err = _run(
        ["scan", str(make_model_dir(tmp_path)), "--policy", str(bad)], capsys
    )
    assert code == 2
    assert "bogus" in err or "unknown" in err
