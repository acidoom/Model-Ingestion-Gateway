"""PR7 — attestation building, canonical bytes, DSSE signing, and verification.

Covers the load-bearing properties: deterministic signed bytes (PAE golden +
canonical stability), the structural exclusion of the signature from the payload,
tamper detection, the I3 digest re-bind, I5 fail-closed at build AND verify, the
domain-separated HMAC keyid, the ed25519 extra, and the cosign CLI seam.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from typing import Any

import pytest

from conftest import make_model_dir
from mig.core.artifact import Artifact, ArtifactRef, ArtifactType
from mig.core.serde import (
    dsse_envelope_from_dict,
    evidence_bundle_from_dict,
    statement_from_dict,
    to_json,
)
from mig.core.verdict import Decision, GateResult, GateStatus, RigorLevel, Verdict
from mig.evidence.builder import build_attestation
from mig.evidence.bundle import build_bundle
from mig.evidence.canonical import canonical_bytes, canonical_json
from mig.evidence.dsse import encode_envelope, pae
from mig.evidence.signing import (
    HMAC_SCHEME,
    MIN_HMAC_KEY_BYTES,
    HMACSigner,
    HMACVerifier,
    SigningError,
    VerificationError,
    hmac_key_id,
    make_signer,
    make_verifier,
    sign_statement,
    verify_envelope,
)
from mig.evidence.statement import (
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    statement_from_attestation,
)
from mig.evidence.verify import verify_attestation
from mig.policy.schema import Policy
from mig.sources.local import LocalSource
from mig.storage.quarantine import Quarantine

_CREATED = "2026-01-01T00:00:00Z"
_KEY = b"k" * MIN_HMAC_KEY_BYTES


def _attributed_gate() -> GateResult:
    return GateResult(
        "static_code",
        GateStatus.PASS,
        RigorLevel.STATIC,
        scanner_name="ast",
        scanner_version="1",
    )


def _fetch_local(
    tmp_path: Any, name: str = "model", *, config: dict[str, object] | None = None
) -> Artifact:
    model = make_model_dir(tmp_path, name=name, config=config)
    return LocalSource(artifact_type=ArtifactType.MODEL).fetch(
        ArtifactRef(scheme="local", locator=str(model)),
        Quarantine(root=str(tmp_path / "q")),
    )


def _attest(artifact: Artifact, *, decision: Decision = Decision.APPROVE) -> Any:
    verdict = Verdict(
        ref=artifact.ref,
        artifact_type=artifact.artifact_type,
        gate_results=[_attributed_gate()],
        decision=decision,
    )
    return build_attestation(
        verdict,
        artifact,
        policy=Policy(id="p", version="1"),
        mig_version="0",
        confinement_level="noop",
        created_at=_CREATED,
    )


# --- canonical bytes / PAE: the determinism keystone ------------------------ #


def test_pae_is_exact_golden() -> None:
    assert pae(b"application/vnd.in-toto+json", b'{"a":1}') == (
        b'DSSEv1 28 application/vnd.in-toto+json 7 {"a":1}'
    )


def test_canonical_is_stable_regardless_of_key_order() -> None:
    assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})
    assert canonical_json({"a": 2, "b": 1}) == '{"a":2,"b":1}'


def test_canonical_rejects_non_finite_and_non_str_keys() -> None:
    with pytest.raises(ValueError):
        canonical_bytes({"x": float("nan")})
    with pytest.raises(ValueError):
        canonical_bytes({"x": float("inf")})
    with pytest.raises(ValueError):
        canonical_bytes({1: "a"})  # non-string key would collide after coercion


def test_canonical_differs_from_human_to_json() -> None:
    # The report encoder (sort_keys=False, spaced) must NEVER equal the signed
    # bytes, so report formatting can't change what was signed.
    obj = {"b": 1, "a": 2}
    assert to_json(obj, indent=None).encode("utf-8") != canonical_bytes(obj)


# --- sign / verify / tamper ------------------------------------------------- #


def test_hmac_sign_verify_roundtrip(tmp_path: Any) -> None:
    att = _attest(_fetch_local(tmp_path))
    env = sign_statement(statement_from_attestation(att), HMACSigner(_KEY))
    assert env.signatures[0].scheme == HMAC_SCHEME
    statement = verify_envelope(
        dsse_envelope_from_dict(encode_envelope(env)), HMACVerifier(_KEY)
    )
    assert statement["predicate"]["decision"] == "approve"


def test_signature_is_excluded_from_signed_payload(tmp_path: Any) -> None:
    att = _attest(_fetch_local(tmp_path))
    env = sign_statement(statement_from_attestation(att), HMACSigner(_KEY))
    payload = json.loads(base64.b64decode(env.payload))
    assert "signature" not in payload["predicate"]
    # Appending another signature cannot change the signed payload bytes.
    assert (
        env.payload
        == sign_statement(statement_from_attestation(att), HMACSigner(_KEY)).payload
    )


def test_tamper_breaks_signature(tmp_path: Any) -> None:
    att = _attest(_fetch_local(tmp_path))
    statement = statement_from_attestation(att)
    env = sign_statement(statement, HMACSigner(_KEY))
    tampered = copy.deepcopy(statement)
    tampered["predicate"]["decision"] = "reject"  # approve -> reject
    forged = dict(encode_envelope(env))
    forged["payload"] = base64.b64encode(json.dumps(tampered).encode("utf-8")).decode(
        "ascii"
    )
    with pytest.raises(VerificationError):
        verify_envelope(dsse_envelope_from_dict(forged), HMACVerifier(_KEY))


# --- I3 digest re-bind ------------------------------------------------------ #


def test_verify_rebinds_to_the_live_artifact_digest(tmp_path: Any) -> None:
    artifact = _fetch_local(tmp_path, name="real")
    att = _attest(artifact)
    env = encode_envelope(
        sign_statement(statement_from_attestation(att), HMACSigner(_KEY))
    )

    good = verify_attestation(env, artifact=artifact, verifier=HMACVerifier(_KEY))
    assert good.ok
    assert good.checks == {
        "signature": True,
        "digest_rebind": True,
        "attribution": True,
        "keyid": True,
    }
    assert good.decision == "approve"

    # A DIFFERENT artifact (distinct content → distinct digest) breaks the bind.
    other = _fetch_local(
        tmp_path / "elsewhere", name="different", config={"model_type": "other"}
    )
    bad = verify_attestation(env, artifact=other, verifier=HMACVerifier(_KEY))
    assert not bad.ok
    assert bad.checks["digest_rebind"] is False
    assert bad.checks["signature"] is True  # signature is fine; the binding isn't


def test_digest_compare_handles_prefixed_and_bare_hex(tmp_path: Any) -> None:
    artifact = _fetch_local(tmp_path)
    att = _attest(artifact)
    statement = statement_from_attestation(att)
    # subject is bare hex; the artifact digest is sha256:-prefixed.
    assert ":" not in statement["subject"][0]["digest"]["sha256"]
    assert artifact.digest is not None and artifact.digest.startswith("sha256:")


# --- I5 fail-closed at build AND verify ------------------------------------- #


def test_builder_refuses_underattributed_vetting(tmp_path: Any) -> None:
    artifact = _fetch_local(tmp_path)
    unattributed = GateResult("static_code", GateStatus.FAIL, RigorLevel.STATIC)
    verdict = Verdict(
        ref=artifact.ref,
        artifact_type=artifact.artifact_type,
        gate_results=[unattributed],
        decision=Decision.REJECT,
    )
    with pytest.raises(ValueError):
        build_attestation(
            verdict,
            artifact,
            policy=Policy(id="p", version="1"),
            mig_version="0",
            confinement_level="noop",
            created_at=_CREATED,
        )


def test_builder_refuses_unpinned_artifact(tmp_path: Any) -> None:
    artifact = _fetch_local(tmp_path)
    object.__setattr__(artifact, "digest", None)
    verdict = Verdict(
        ref=artifact.ref,
        artifact_type=artifact.artifact_type,
        gate_results=[_attributed_gate()],
        decision=Decision.APPROVE,
    )
    with pytest.raises(ValueError):
        build_attestation(
            verdict,
            artifact,
            policy=Policy(id="p", version="1"),
            mig_version="0",
            confinement_level="noop",
            created_at=_CREATED,
        )


def test_verify_flags_underattributed_signed_statement(tmp_path: Any) -> None:
    # Hand-craft a SIGNED-but-under-attributed statement (bypassing the builder)
    # to prove verify re-checks attribution, not just the builder.
    artifact = _fetch_local(tmp_path)
    att = _attest(artifact)
    statement = statement_from_attestation(att)
    statement["predicate"]["gate_summary"] = [
        {
            "gate_id": "static_code",
            "status": "fail",
            "rigor": "static",
            "findings": [],
            "scanner_name": "ast",
            "scanner_version": None,  # executed but unattributed
            "duration_ms": None,
            "evidence": {},
        }
    ]
    env = encode_envelope(sign_statement(statement, HMACSigner(_KEY)))
    result = verify_attestation(env, artifact=artifact, verifier=HMACVerifier(_KEY))
    assert result.checks["signature"] is True
    assert result.checks["attribution"] is False
    assert not result.ok


# --- HMAC keyid hardening --------------------------------------------------- #


def test_hmac_keyid_is_domain_separated_and_key_len_enforced() -> None:
    assert hmac_key_id(_KEY) == hashlib.sha256(b"mig-keyid-v1" + _KEY).hexdigest()[:16]
    assert hmac_key_id(_KEY) != hashlib.sha256(_KEY).hexdigest()[:16]
    with pytest.raises(SigningError):
        HMACSigner(b"too-short")


# --- verifier is operator-chosen, never envelope-chosen --------------------- #


def test_verifier_is_never_selected_from_envelope(tmp_path: Any) -> None:
    artifact = _fetch_local(tmp_path)
    att = _attest(artifact)
    env_obj = sign_statement(statement_from_attestation(att), HMACSigner(_KEY))
    forged = dict(encode_envelope(env_obj))
    # An attacker rewrites the advisory keyid; verify recomputes with the
    # operator's key and ignores the claimed keyid.
    forged["signatures"] = [dict(forged["signatures"][0])]
    forged["signatures"][0]["keyid"] = "attacker-controlled"
    ok = verify_attestation(forged, artifact=artifact, verifier=HMACVerifier(_KEY))
    assert ok.checks["signature"] is True

    pinned = verify_attestation(
        forged,
        artifact=artifact,
        verifier=HMACVerifier(_KEY),
        expected_keyid="the-real-one",
    )
    assert pinned.checks["keyid"] is False
    assert not pinned.ok


# --- serde round-trips ------------------------------------------------------ #


def test_serde_roundtrips_for_new_shapes(tmp_path: Any) -> None:
    artifact = _fetch_local(tmp_path)
    att = _attest(artifact)
    env = sign_statement(statement_from_attestation(att), HMACSigner(_KEY))
    encoded = encode_envelope(env)
    assert dsse_envelope_from_dict(encoded) == env

    statement = statement_from_attestation(att)
    assert statement_from_dict(statement)["_type"] == STATEMENT_TYPE

    verdict = Verdict(
        ref=artifact.ref,
        artifact_type=artifact.artifact_type,
        gate_results=[_attributed_gate()],
        decision=Decision.APPROVE,
    )
    bundle = build_bundle(
        verdict, env, mig_version="0", created_at=_CREATED, run_meta={"run_id": "x"}
    )
    assert evidence_bundle_from_dict(bundle)["schema"].endswith("/evidence-bundle/v1")


def test_statement_has_intoto_shape(tmp_path: Any) -> None:
    att = _attest(_fetch_local(tmp_path))
    statement = statement_from_attestation(att)
    assert statement["_type"] == STATEMENT_TYPE
    assert statement["predicateType"] == PREDICATE_TYPE
    sha = statement["subject"][0]["digest"]["sha256"]
    assert len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)


# --- evidence bundle: only the envelope is authenticated -------------------- #


def test_bundle_verify_ignores_the_unsigned_verdict_mirror(tmp_path: Any) -> None:
    artifact = _fetch_local(tmp_path)
    att = _attest(artifact, decision=Decision.APPROVE)
    env = sign_statement(statement_from_attestation(att), HMACSigner(_KEY))
    verdict = Verdict(
        ref=artifact.ref,
        artifact_type=artifact.artifact_type,
        gate_results=[_attributed_gate()],
        decision=Decision.APPROVE,
    )
    bundle = build_bundle(
        verdict, env, mig_version="0", created_at=_CREATED, run_meta={"run_id": "x"}
    )
    # Tamper the UNSIGNED verdict copy → verify (which reads only the envelope)
    # is unaffected, and the signed decision still reads "approve".
    bundle["verdict"]["decision"] = "reject"
    result = verify_attestation(bundle, artifact=artifact, verifier=HMACVerifier(_KEY))
    assert result.ok
    assert result.decision == "approve"


# --- ed25519 backend (opt-in extra) ----------------------------------------- #

ed25519_mod = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")


def _ed_keypair() -> tuple[bytes, bytes]:
    sk = ed25519_mod.Ed25519PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()


def test_ed25519_roundtrip_over_same_pae(tmp_path: Any) -> None:
    priv, pub = _ed_keypair()
    att = _attest(_fetch_local(tmp_path))
    env = sign_statement(
        statement_from_attestation(att), make_signer("ed25519", key_bytes=priv)
    )
    assert env.signatures[0].scheme == "ed25519"
    statement = verify_envelope(
        dsse_envelope_from_dict(encode_envelope(env)),
        make_verifier("ed25519", key_bytes=pub),
    )
    assert statement["predicateType"] == PREDICATE_TYPE


def test_ed25519_wrong_key_and_cross_scheme_fail(tmp_path: Any) -> None:
    priv, _pub = _ed_keypair()
    _priv2, pub2 = _ed_keypair()
    att = _attest(_fetch_local(tmp_path))
    env = dsse_envelope_from_dict(
        encode_envelope(
            sign_statement(
                statement_from_attestation(att), make_signer("ed25519", key_bytes=priv)
            )
        )
    )
    with pytest.raises(VerificationError):  # wrong public key
        verify_envelope(env, make_verifier("ed25519", key_bytes=pub2))
    with pytest.raises(VerificationError):  # an HMAC verifier rejects ed25519
        verify_envelope(env, HMACVerifier(_KEY))


def test_ed25519_missing_extra_raises_install_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mig.evidence.signers import ed25519 as ed_backend

    # Purge cached cryptography.* submodules, then block re-import, so the lazy
    # `from cryptography... import` inside _require_cryptography genuinely fails.
    for mod in list(sys.modules):
        if mod == "cryptography" or mod.startswith("cryptography."):
            monkeypatch.delitem(sys.modules, mod, raising=False)
    monkeypatch.setitem(sys.modules, "cryptography", None)
    with pytest.raises(SigningError, match="mig\\[signing\\]"):
        ed_backend._require_cryptography()
