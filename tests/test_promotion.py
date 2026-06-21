"""PR8 — gated trusted-store promotion (the decision boundary).

Covers the load-bearing fail-closed properties: an unverified/tampered/non-APPROVE
artifact can NEVER reach the store; the embedded floor's clauses; OPA deny-
overrides (OPA can only restrict, never loosen); idempotency + no-clobber; and the
trust-only-the-signed-attestation rule.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from conftest import make_model_dir
from mig.cli.main import main
from mig.core.artifact import Artifact, ArtifactRef, ArtifactType
from mig.core.verdict import Decision, GateResult, GateStatus, RigorLevel, Verdict
from mig.evidence.builder import build_attestation
from mig.evidence.dsse import encode_envelope
from mig.evidence.signing import HMACSigner, sign_statement
from mig.evidence.statement import statement_from_attestation
from mig.policy.schema import Policy
from mig.promotion.gate import EmbeddedPromotionGate, make_promotion_gate
from mig.sources.local import LocalSource
from mig.storage.quarantine import Quarantine

_KEY = b"K" * 32


# --------------------------------------------------------------------------- #
# Helpers: build + sign an arbitrary attestation, and write it to disk.
# --------------------------------------------------------------------------- #


def _keyfile(tmp_path: pathlib.Path) -> str:
    p = tmp_path / "k.key"
    p.write_bytes(_KEY)
    return str(p)


def _fetch(
    tmp_path: pathlib.Path, artifact_type: ArtifactType, name: str = "m"
) -> Artifact:
    model = make_model_dir(tmp_path, name=name)
    return LocalSource(artifact_type=artifact_type).fetch(
        ArtifactRef(scheme="local", locator=str(model)),
        Quarantine(root=str(tmp_path / "q")),
    )


def _signed_envelope(
    artifact: Artifact,
    *,
    decision: Decision,
    rigor: RigorLevel = RigorLevel.STATIC,
    confinement: str = "noop",
) -> dict[str, Any]:
    gate = GateResult(
        "static_code", GateStatus.PASS, rigor, scanner_name="ast", scanner_version="1"
    )
    verdict = Verdict(
        ref=artifact.ref,
        artifact_type=artifact.artifact_type,
        gate_results=[gate],
        decision=decision,
    )
    att = build_attestation(
        verdict,
        artifact,
        policy=Policy(id="p", version="1"),
        mig_version="0",
        confinement_level=confinement,
        created_at="2026-01-01T00:00:00Z",
    )
    return encode_envelope(
        sign_statement(statement_from_attestation(att), HMACSigner(_KEY))
    )


def _signed_with_predicate_digest(
    artifact: Artifact, *, predicate_digest: Any
) -> dict[str, Any]:
    """A validly-signed envelope whose predicate.digest is tampered before signing."""
    gate = GateResult(
        "static_code",
        GateStatus.PASS,
        RigorLevel.STATIC,
        scanner_name="ast",
        scanner_version="1",
    )
    verdict = Verdict(
        ref=artifact.ref,
        artifact_type=artifact.artifact_type,
        gate_results=[gate],
        decision=Decision.APPROVE,
    )
    att = build_attestation(
        verdict,
        artifact,
        policy=Policy(id="p", version="1"),
        mig_version="0",
        confinement_level="noop",
        created_at="2026-01-01T00:00:00Z",
    )
    statement = statement_from_attestation(att)
    statement["predicate"]["digest"] = predicate_digest  # tamper the predicate field
    return encode_envelope(sign_statement(statement, HMACSigner(_KEY)))


def _write(path: pathlib.Path, env: dict[str, Any]) -> str:
    path.write_text(json.dumps(env))
    return str(path)


def _cas_count(store_root: pathlib.Path) -> int:
    return len(list((store_root / "cas" / "sha256").glob("*/*/.complete")))


# --------------------------------------------------------------------------- #
# The embedded floor (unit — no I/O)
# --------------------------------------------------------------------------- #


def _ok_input(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "decision": "approve",
        "is_executable_type": False,
        "overall_rigor": "static",
        "confinement_level": "noop",
        "policy": {"id": "p", "version": "1"},
        "verification": {
            "ok": True,
            "scheme": "ed25519",
            "keyid": "abc",
            "checks": {
                "signature": True,
                "digest_rebind": True,
                "attribution": True,
                "keyid": True,
            },
        },
    }
    doc.update(over)
    return doc


def test_embedded_floor_allows_clean_approved_model() -> None:
    assert EmbeddedPromotionGate().evaluate(_ok_input()).allow is True


def test_embedded_floor_denies_non_approve() -> None:
    d = EmbeddedPromotionGate().evaluate(_ok_input(decision="reject"))
    assert d.allow is False
    assert any("approve" in r for r in d.reasons)


@pytest.mark.parametrize("check", ["signature", "digest_rebind", "attribution", "keyid"])
def test_embedded_floor_requires_each_check(check: str) -> None:
    doc = _ok_input()
    doc["verification"]["checks"][check] = False
    assert EmbeddedPromotionGate().evaluate(doc).allow is False


def test_embedded_floor_executable_needs_behavioral_confinement() -> None:
    gate = EmbeddedPromotionGate()
    # executable + static/noop → denied
    assert (
        gate.evaluate(
            _ok_input(
                is_executable_type=True, overall_rigor="static", confinement_level="noop"
            )
        ).allow
        is False
    )
    # executable + behavioral + docker → allowed
    assert (
        gate.evaluate(
            _ok_input(
                is_executable_type=True,
                overall_rigor="behavioral",
                confinement_level="docker",
            )
        ).allow
        is True
    )
    # a bogus confinement string is NOT accepted (allowlist, not blocklist)
    assert (
        gate.evaluate(
            _ok_input(
                is_executable_type=True,
                overall_rigor="behavioral",
                confinement_level="NoopSandbox",
            )
        ).allow
        is False
    )


def test_embedded_floor_fails_closed_on_missing_fields() -> None:
    assert EmbeddedPromotionGate().evaluate({}).allow is False


def test_require_asymmetric_rejects_hmac() -> None:
    doc = _ok_input()
    doc["verification"]["scheme"] = "hmac-sha256"
    assert EmbeddedPromotionGate(require_asymmetric=True).evaluate(doc).allow is False
    assert EmbeddedPromotionGate().evaluate(doc).allow is True  # default allows


def test_require_keyid_allowlist() -> None:
    doc = _ok_input()
    doc["verification"]["keyid"] = "abc"
    assert (
        EmbeddedPromotionGate(required_keyids=frozenset({"xyz"})).evaluate(doc).allow
        is False
    )
    assert (
        EmbeddedPromotionGate(required_keyids=frozenset({"abc"})).evaluate(doc).allow
        is True
    )


# --------------------------------------------------------------------------- #
# OPA deny-overrides (mocked seam — no opa binary)
# --------------------------------------------------------------------------- #


def _opa_eval_returning(allow: bool, reasons: list[str]) -> Any:
    payload = json.dumps(
        {"result": [{"expressions": [{"value": {"allow": allow, "reasons": reasons}}]}]}
    )

    def fake(
        opa_bin: str, args: list[str], *, input_bytes: bytes, timeout_s: int = 30
    ) -> tuple[int, str, str]:
        return 0, payload, ""

    return fake


def test_opa_deny_overrides_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    import mig.promotion.opa.cli as opa_mod

    monkeypatch.setattr(opa_mod, "_run_opa", _opa_eval_returning(False, ["opa says no"]))
    gate = make_promotion_gate(opa="cli", policy_path="policies/promotion.rego")
    d = gate.evaluate(_ok_input())  # embedded would allow
    assert d.allow is False
    assert "opa says no" in d.reasons


def test_opa_cannot_loosen_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    import mig.promotion.opa.cli as opa_mod

    monkeypatch.setattr(opa_mod, "_run_opa", _opa_eval_returning(True, []))
    gate = make_promotion_gate(opa="cli", policy_path="policies/promotion.rego")
    # embedded DENIES (reject); OPA allow=true must NOT loosen it.
    assert gate.evaluate(_ok_input(decision="reject")).allow is False


def test_opa_unreachable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import mig.promotion.opa.cli as opa_mod

    def boom(*a: Any, **k: Any) -> Any:
        raise opa_mod.OpaUnavailableError("opa exploded")

    monkeypatch.setattr(opa_mod, "_run_opa", boom)
    gate = make_promotion_gate(opa="cli", policy_path="policies/promotion.rego")
    assert gate.evaluate(_ok_input()).allow is False  # never fail-open


def test_opa_malformed_output_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import mig.promotion.opa.cli as opa_mod

    monkeypatch.setattr(opa_mod, "_run_opa", lambda *a, **k: (0, "not json at all", ""))
    gate = make_promotion_gate(opa="cli", policy_path="policies/promotion.rego")
    assert gate.evaluate(_ok_input()).allow is False


def test_opa_cli_argv_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    import mig.promotion.opa.cli as opa_mod

    captured: list[list[str]] = []

    def fake(
        opa_bin: str, args: list[str], *, input_bytes: bytes, timeout_s: int = 30
    ) -> tuple[int, str, str]:
        captured.append(args)
        return (
            0,
            json.dumps(
                {"result": [{"expressions": [{"value": {"allow": True, "reasons": []}}]}]}
            ),
            "",
        )

    monkeypatch.setattr(opa_mod, "_run_opa", fake)
    make_promotion_gate(opa="cli", policy_path="P.rego").evaluate(_ok_input())
    args = captured[0]
    assert args[0] == "eval" and "--stdin-input" in args
    assert "data.mig.promotion.decision" in args
    assert "P.rego" in args


# --------------------------------------------------------------------------- #
# End-to-end via the CLI
# --------------------------------------------------------------------------- #


def test_promote_denied_when_decision_not_approve(tmp_path: pathlib.Path) -> None:
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    env = _signed_envelope(artifact, decision=Decision.REJECT)
    att = _write(tmp_path / "att.json", env)
    store = tmp_path / "trusted"
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 1  # verification passes, gate DENIES
    assert _cas_count(store) == 0  # nothing written


def test_promote_denied_executable_static_only(tmp_path: pathlib.Path) -> None:
    # A signed APPROVE for an MCP_SERVER vetted static-only must still be denied (I8).
    artifact = _fetch(tmp_path, ArtifactType.MCP_SERVER)
    env = _signed_envelope(
        artifact, decision=Decision.APPROVE, rigor=RigorLevel.STATIC, confinement="noop"
    )
    att = _write(tmp_path / "att.json", env)
    store = tmp_path / "trusted"
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--type",
            "mcp_server",
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 1
    assert _cas_count(store) == 0


def test_promote_executable_behavioral_is_promotable(tmp_path: pathlib.Path) -> None:
    artifact = _fetch(tmp_path, ArtifactType.MCP_SERVER)
    env = _signed_envelope(
        artifact,
        decision=Decision.APPROVE,
        rigor=RigorLevel.BEHAVIORAL,
        confinement="docker",
    )
    att = _write(tmp_path / "att.json", env)
    store = tmp_path / "trusted"
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--type",
            "mcp_server",
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 0
    assert _cas_count(store) == 1


def test_promote_trusts_only_signed_attestation(tmp_path: pathlib.Path) -> None:
    # A bundle whose UNSIGNED verdict says approve but SIGNED predicate says reject
    # must be denied — promotion reads only the signed envelope.
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    env = _signed_envelope(artifact, decision=Decision.REJECT)
    bundle = {
        "schema": "https://mig.dev/evidence-bundle/v1",
        "verdict": {"decision": "approve"},  # the lie
        "envelope": env,
    }
    att = _write(tmp_path / "bundle.json", bundle)
    store = tmp_path / "trusted"
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 1  # the signed reject wins
    assert _cas_count(store) == 0


def test_promote_no_clobber_on_corrupted_entry(tmp_path: pathlib.Path) -> None:
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    env = _signed_envelope(artifact, decision=Decision.APPROVE)
    att = _write(tmp_path / "att.json", env)
    store = tmp_path / "trusted"
    assert (
        main(
            [
                "promote",
                artifact.ref.locator,
                "--attestation",
                att,
                "--key",
                _keyfile(tmp_path),
                "--store-root",
                str(store),
            ]
        )
        == 0
    )
    # Corrupt the stored artifact, keep .complete → a re-promote must NOT silently
    # accept it as the idempotent no-op.
    entry = next((store / "cas" / "sha256").glob("*/*"))
    (entry / "artifact" / "config.json").write_text('{"model_type":"corrupted"}')
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 2  # PromotionError: store entry digest mismatch


def test_promote_missing_attestation_is_operator_error(tmp_path: pathlib.Path) -> None:
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            str(tmp_path / "nope.json"),
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(tmp_path / "t"),
        ]
    )
    assert code == 2


def test_promote_opa_policy_required(tmp_path: pathlib.Path) -> None:
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    env = _signed_envelope(artifact, decision=Decision.APPROVE)
    att = _write(tmp_path / "att.json", env)
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(tmp_path / "t"),
            "--opa",
            "cli",
        ]  # no --opa-policy
    )
    assert code == 2


# --- review-fix regressions ------------------------------------------------- #


@pytest.mark.parametrize("flag", [None, 1, "yes"])
def test_embedded_floor_executable_flag_fails_closed(flag: Any) -> None:
    # A non-bool / missing is_executable_type must NOT skip the rigor requirement.
    doc = _ok_input(
        is_executable_type=flag, overall_rigor="static", confinement_level="noop"
    )
    assert EmbeddedPromotionGate().evaluate(doc).allow is False


def test_promote_non_string_predicate_digest_is_verification_failure(
    tmp_path: pathlib.Path,
) -> None:
    # Signed, correct subject, but predicate.digest is an int → must NOT crash;
    # it is a verification failure (exit 3), and the attempt is audited.
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    env = _signed_with_predicate_digest(artifact, predicate_digest=12345)
    att = _write(tmp_path / "att.json", env)
    store = tmp_path / "trusted"
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 3
    assert _cas_count(store) == 0
    assert (store / "index" / "promotions.jsonl").exists()  # still audited


def test_promote_divergent_predicate_digest_is_verification_failure(
    tmp_path: pathlib.Path,
) -> None:
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    env = _signed_with_predicate_digest(artifact, predicate_digest="sha256:" + "ff" * 32)
    att = _write(tmp_path / "att.json", env)
    store = tmp_path / "trusted"
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 3
    assert _cas_count(store) == 0


def test_promote_malformed_attestation_is_operator_error(tmp_path: pathlib.Path) -> None:
    # Valid JSON, but not a DSSE envelope/bundle → clean exit 2 (not a traceback).
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    att = _write(tmp_path / "bad.json", {"hello": "world"})
    store = tmp_path / "trusted"
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 2
    assert (store / "index" / "promotions.jsonl").exists()  # audited, not crashed


def test_promote_rejects_poisoned_stored_attestation(tmp_path: pathlib.Path) -> None:
    # Swapping the persisted signed attestation (but keeping artifact/+.complete)
    # must NOT be accepted as an idempotent no-op — the provenance can't be swapped.
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    env = _signed_envelope(artifact, decision=Decision.APPROVE)
    att = _write(tmp_path / "att.json", env)
    store = tmp_path / "trusted"
    assert (
        main(
            [
                "promote",
                artifact.ref.locator,
                "--attestation",
                att,
                "--key",
                _keyfile(tmp_path),
                "--store-root",
                str(store),
            ]
        )
        == 0
    )
    entry = next((store / "cas" / "sha256").glob("*/*"))
    (entry / "attestation.dsse.json").write_text('{"poisoned": true}')
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 2  # PromotionError: stored attestation mismatch


def test_promote_store_error_is_audited_operator_error(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A non-PromotionError raised inside the store write (e.g. OSError) must be a
    # clean, AUDITED operator error — not an uncaught traceback at the boundary.
    import mig.promotion.stores.local_fs as store_mod

    def boom(*a: Any, **k: Any) -> Any:
        raise OSError("disk gone")

    monkeypatch.setattr(store_mod, "stage_local_tree", boom)
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    env = _signed_envelope(artifact, decision=Decision.APPROVE)
    att = _write(tmp_path / "att.json", env)
    store = tmp_path / "trusted"
    code = main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    assert code == 2
    assert _cas_count(store) == 0


def test_promote_audit_records_denial(tmp_path: pathlib.Path) -> None:
    artifact = _fetch(tmp_path, ArtifactType.MODEL)
    env = _signed_envelope(artifact, decision=Decision.REJECT)
    att = _write(tmp_path / "att.json", env)
    store = tmp_path / "trusted"
    main(
        [
            "promote",
            artifact.ref.locator,
            "--attestation",
            att,
            "--key",
            _keyfile(tmp_path),
            "--store-root",
            str(store),
        ]
    )
    # The denial is durably recorded even though no CAS entry was written.
    assert (store / "index" / "promotions.jsonl").exists()
    assert list((store / "index" / "denied").glob("*.json"))
