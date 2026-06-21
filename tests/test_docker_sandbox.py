"""PR6 behavioral sandbox: hardened confinement, egress capture, teardown.

Unit tests mock the single docker invocation seam (no daemon needed); the
harness tests run the real detonation harness as a subprocess (no Docker); the
integration test runs a real container and is skipped without a daemon.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from collections.abc import Mapping

import pytest

import mig.sandbox.docker as docker_mod
from conftest import make_artifact, make_model_dir, phone_home_pickle_bytes
from mig.core.artifact import ArtifactRef, ArtifactType
from mig.core.context import DefaultScanContext, make_context
from mig.core.pipeline import run_pipeline
from mig.core.verdict import Decision, GateStatus, RigorLevel, Severity
from mig.gates import default_gates
from mig.policy.schema import Policy
from mig.sandbox import _harness
from mig.sandbox.docker import DockerSandbox, DockerUnavailableError, docker_available
from mig.sandbox.spec import SandboxSpec
from mig.sources.local import LocalSource
from mig.storage.quarantine import Quarantine


def _sentinel(observation: Mapping[str, object], token: str) -> str:
    """A harness sentinel stamped with ``token`` (the host trusts only this one)."""
    return (
        f"\n{_harness.OBSERVATION_PREFIX}{token}:{json.dumps(observation)}"
        f"{_harness.OBSERVATION_SUFFIX}\n"
    )


def _patch_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    observation: Mapping[str, object] | None = None,
    raw_stdout: str | None = None,
    stderr: str = "",
    exit_code: int | None = 0,
    timed_out: bool = False,
    capture: list[list[str]] | None = None,
) -> None:
    """Mock the one docker seam. By default it echoes a sentinel stamped with the
    per-run nonce (the last ``run`` arg), mimicking the real harness; ``raw_stdout``
    overrides that with literal stdout (e.g. to simulate a crash with no sentinel).
    """

    def fake(
        docker_bin: str, args: list[str], *, timeout_s: int
    ) -> tuple[int | None, str, str, bool]:
        if capture is not None:
            capture.append(args)
        if raw_stdout is not None:
            return exit_code, raw_stdout, stderr, timed_out
        token = args[-1]  # the harness nonce is the final `docker run` argument
        stdout = _sentinel(observation if observation is not None else _CLEAN, token)
        return exit_code, stdout, stderr, timed_out

    monkeypatch.setattr(docker_mod, "_run_docker", fake)


_CLEAN = {"network_attempts": [], "dns_queries": [], "loaded": ["x"], "errors": []}


# --- hardened confinement spec ---------------------------------------------- #


def test_run_args_are_deny_by_default(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    captured: list[list[str]] = []
    _patch_run(monkeypatch, capture=captured)
    DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    args = " ".join(captured[0])
    assert "--network none" in args
    assert "--read-only" in args
    assert "--cap-drop ALL" in args
    assert "no-new-privileges:true" in args  # explicit form (gVisor-safe)
    assert "--pids-limit 256" in args
    assert "--tmpfs /tmp:rw,size=64m" in args  # bounded scratch
    assert "--rm" in args
    assert "timeout -s KILL" in args  # authoritative in-container wall-clock bound
    assert ":/artifact:ro" in args  # artifact mounted read-only


def test_gvisor_runtime_is_requested_and_labelled(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    captured: list[list[str]] = []
    _patch_run(monkeypatch, capture=captured)
    sandbox = DockerSandbox(runtime="runsc")
    assert sandbox.confinement_level == "gvisor"
    sandbox.detonate(make_artifact(), SandboxSpec(), ctx)
    assert "--runtime runsc" in " ".join(captured[0])


# --- observation parsing ---------------------------------------------------- #


def test_clean_load_passes_at_behavioral_rigor(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    _patch_run(monkeypatch)
    result = DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    assert result.status is GateStatus.PASS
    assert result.rigor is RigorLevel.BEHAVIORAL  # real behavioral rigor achieved


def test_egress_attempt_is_caught_and_fails(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    observation = {
        "network_attempts": [{"address": "('1.1.1.1', 80)", "blocked": True}],
        "dns_queries": ["1.1.1.1"],
        "loaded": [],
        "errors": [],
    }
    _patch_run(monkeypatch, observation=observation)
    result = DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    assert result.rigor is RigorLevel.BEHAVIORAL
    assert result.status is GateStatus.FAIL
    assert any(f.code == "behavioral_network_egress" for f in result.findings)
    assert result.network_attempts


def test_successful_egress_is_a_critical_breach(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    observation = {
        "network_attempts": [{"address": "('evil', 80)", "blocked": False}],
        "dns_queries": [],
        "loaded": [],
        "errors": [],
    }
    _patch_run(monkeypatch, observation=observation)
    result = DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    assert result.status is GateStatus.FAIL
    assert any(
        f.code == "behavioral_egress_not_confined" and f.severity is Severity.CRITICAL
        for f in result.findings
    )


def test_missing_observation_is_error(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    _patch_run(monkeypatch, raw_stdout="container exploded", exit_code=1)
    result = DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    assert result.status is GateStatus.ERROR
    assert any(f.code == "behavioral_no_observation" for f in result.findings)


def test_forged_clean_sentinel_cannot_mask_real_egress(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    """A detonated artifact shares stdout and could print a clean sentinel to hide
    its egress. Stamped with the wrong nonce, the forgery is ignored; only the
    real nonce-stamped observation (egress → FAIL) is trusted.
    """
    egress = {
        "network_attempts": [{"address": "('1.1.1.1', 80)", "blocked": True}],
        "dns_queries": [],
        "loaded": [],
        "errors": [],
    }

    def fake(
        docker_bin: str, args: list[str], *, timeout_s: int
    ) -> tuple[int | None, str, str, bool]:
        real_token = args[-1]
        forged = _sentinel(_CLEAN, "deadbeef-not-the-real-nonce")  # attacker-printed
        real = _sentinel(egress, real_token)  # harness-emitted
        return 0, forged + real, "", False

    monkeypatch.setattr(docker_mod, "_run_docker", fake)
    result = DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    assert result.status is GateStatus.FAIL
    assert any(f.code == "behavioral_network_egress" for f in result.findings)


def test_malformed_observation_fails_closed(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    """A non-list `network_attempts` (forged/corrupt, artifact-influenced) must be
    treated as untrusted → ERROR → REVIEW_REQUIRED, never a clean pass."""
    _patch_run(monkeypatch, observation={"network_attempts": 7, "dns_queries": []})
    result = DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    assert result.status is GateStatus.ERROR
    assert result.rigor is RigorLevel.NONE
    assert any(f.code == "behavioral_malformed_observation" for f in result.findings)


def test_dns_only_lookup_is_surfaced_but_passes(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    observation = {
        "network_attempts": [],
        "dns_queries": ["evil.example"],
        "loaded": [],
        "errors": [],
    }
    _patch_run(monkeypatch, observation=observation)
    result = DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    assert result.status is GateStatus.PASS  # LOW finding does not fail the gate
    assert any(
        f.code == "behavioral_dns_lookup" and f.severity is Severity.LOW
        for f in result.findings
    )


def _env_args(args: list[str]) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == "--env"]


def test_env_is_not_leaked_by_default(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    captured: list[list[str]] = []
    _patch_run(monkeypatch, capture=captured)
    DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    # Deny-by-default: only the two fixed, non-secret vars — no operator env.
    assert _env_args(captured[0]) == ["PYTHONDONTWRITEBYTECODE=1", "HOME=/tmp"]


def test_env_allowlist_is_forwarded_when_set(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    captured: list[list[str]] = []
    _patch_run(monkeypatch, capture=captured)
    DockerSandbox().detonate(make_artifact(), SandboxSpec(env={"MIG_FLAG": "1"}), ctx)
    assert "MIG_FLAG=1" in _env_args(captured[0])


def test_timeout_warns_and_tears_down(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    calls: list[list[str]] = []

    def fake(
        docker_bin: str, args: list[str], *, timeout_s: int
    ) -> tuple[int | None, str, str, bool]:
        calls.append(args)
        if args[0] == "run":
            return None, "", "", True  # timed out
        return 0, "", "", False  # the teardown `rm --force`

    monkeypatch.setattr(docker_mod, "_run_docker", fake)
    result = DockerSandbox().detonate(make_artifact(), SandboxSpec(timeout_s=1), ctx)
    assert result.status is GateStatus.WARN
    assert any(f.code == "behavioral_timeout" for f in result.findings)
    assert any(args[0] == "rm" for args in calls)  # ephemeral teardown forced


def test_docker_unavailable_is_error(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    def fake(
        docker_bin: str, args: list[str], *, timeout_s: int
    ) -> tuple[int | None, str, str, bool]:
        raise DockerUnavailableError("docker CLI not found")

    monkeypatch.setattr(docker_mod, "_run_docker", fake)
    result = DockerSandbox().detonate(make_artifact(), SandboxSpec(), ctx)
    assert result.status is GateStatus.ERROR
    assert any(f.code == "sandbox_unavailable" for f in result.findings)


# --- spec-emit mode (no Docker) --------------------------------------------- #


def test_emit_manifest_is_hardened() -> None:
    manifest = DockerSandbox(runtime="runsc").emit_manifest(
        make_artifact(), SandboxSpec()
    )
    assert manifest["network"] == "none"
    assert manifest["read_only_rootfs"] is True
    assert manifest["cap_drop"] == ["ALL"]
    assert manifest["runtime"] == "runsc"
    # No drift weaker than the inline run (M3): bounded tmpfs, workdir, ephemeral.
    assert manifest["tmpfs"] == ["/tmp:rw,size=64m"]
    assert manifest["workdir"] == "/tmp"
    assert manifest["auto_remove"] is True
    command = manifest["command"]
    assert isinstance(command, list)
    assert command[0] == "timeout"  # authoritative in-container bound
    assert "python" in command


def test_manifest_command_matches_inline_run(
    monkeypatch: pytest.MonkeyPatch, ctx: DefaultScanContext
) -> None:
    """The emitted command and the inline `docker run` command are one source of
    truth — they must be byte-identical except for the per-run nonce (M3)."""
    captured: list[list[str]] = []
    _patch_run(monkeypatch, capture=captured)
    sandbox = DockerSandbox()
    sandbox.detonate(make_artifact(), SandboxSpec(), ctx)
    inline = captured[0]
    image_idx = inline.index(DockerSandbox().image)
    inline_cmd = inline[image_idx + 1 : -1]  # drop the image and the nonce
    manifest_cmd = sandbox.emit_manifest(make_artifact(), SandboxSpec())["command"]
    assert isinstance(manifest_cmd, list)
    assert inline_cmd == manifest_cmd[:-1]  # same command, modulo the nonce


def test_spec_emit_defers_to_external_runner(ctx: DefaultScanContext) -> None:
    result = DockerSandbox(spec_emit=True).detonate(make_artifact(), SandboxSpec(), ctx)
    assert result.status is GateStatus.SKIPPED
    assert result.rigor is RigorLevel.NONE  # not run here
    assert "manifest" in result.raw


# --- I8 unblocked: executable + real behavioral PASS → APPROVE --------------- #


def test_executable_with_behavioral_pass_approves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    _patch_run(monkeypatch)
    model = make_model_dir(tmp_path)
    artifact = LocalSource(artifact_type=ArtifactType.MCP_SERVER).fetch(
        ArtifactRef(scheme="local", locator=str(model)),
        Quarantine(root=str(tmp_path / "q")),
    )
    ctx = make_context(
        policy=Policy(id="p", version="1"),
        quarantine=Quarantine(root=str(tmp_path / "q")),
        sandbox=DockerSandbox(),
    )
    verdict = run_pipeline(artifact, default_gates(), ctx)
    # Behavioral ran at BEHAVIORAL rigor and passed → I8 satisfied → APPROVE.
    assert verdict.behavioral_ran()
    assert verdict.decision is Decision.APPROVE


# --- detonation harness (subprocess; no Docker) ----------------------------- #


def _run_harness(artifact_dir: pathlib.Path) -> dict[str, object]:
    proc = subprocess.run(
        [sys.executable, _harness.__file__, str(artifact_dir)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    start = proc.stdout.find(_harness.OBSERVATION_PREFIX)
    end = proc.stdout.find(_harness.OBSERVATION_SUFFIX, start)
    assert start != -1 and end != -1, proc.stdout + proc.stderr
    body = proc.stdout[start + len(_harness.OBSERVATION_PREFIX) : end]
    # body is "<token>:<json>"; strip the (here empty) nonce prefix.
    payload = body.split(":", 1)[1]
    parsed: dict[str, object] = json.loads(payload)
    return parsed


def test_harness_benign_artifact_records_no_egress(tmp_path: pathlib.Path) -> None:
    observation = _run_harness(make_model_dir(tmp_path))
    assert observation["network_attempts"] == []


def test_harness_records_phone_home_attempt(tmp_path: pathlib.Path) -> None:
    (tmp_path / "evil.pkl").write_bytes(phone_home_pickle_bytes())
    observation = _run_harness(tmp_path)
    attempts = observation["network_attempts"]
    assert isinstance(attempts, list) and attempts  # the on-load connect was recorded
    first = attempts[0]
    assert isinstance(first, dict)
    assert first.get("blocked") is True  # refused (no server on 127.0.0.1:1)


def test_harness_records_connect_ex_and_sendto_egress(tmp_path: pathlib.Path) -> None:
    # connect() is not the only egress path — connect_ex (TCP poll) and sendto
    # (connectionless UDP) must be recorded too (F4).
    (tmp_path / "probe.py").write_text(
        "import socket\n"
        "tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "try:\n    tcp.connect_ex(('127.0.0.1', 1))\nexcept OSError:\n    pass\n"
        "udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "try:\n    udp.sendto(b'x', ('127.0.0.1', 1))\nexcept OSError:\n    pass\n"
    )
    observation = _run_harness(tmp_path)
    attempts = observation["network_attempts"]
    assert isinstance(attempts, list)
    addresses = [a["address"] for a in attempts if isinstance(a, dict)]
    assert sum("127.0.0.1" in addr for addr in addresses) >= 2  # both paths recorded


# --- real container (integration; skipped without a Docker daemon) ---------- #


@pytest.mark.skipif(not docker_available(), reason="no Docker daemon")
def test_real_container_blocks_and_catches_egress(tmp_path: pathlib.Path) -> None:
    model = make_model_dir(tmp_path)
    # Target an EXTERNAL host so --network none (not a missing listener) blocks it.
    (model / "evil.pkl").write_bytes(phone_home_pickle_bytes("203.0.113.1", 80))
    artifact = LocalSource(artifact_type=ArtifactType.MCP_SERVER).fetch(
        ArtifactRef(scheme="local", locator=str(model)),
        Quarantine(root=str(tmp_path / "q")),
    )
    ctx = make_context(
        policy=Policy(id="p", version="1"),
        quarantine=Quarantine(root=str(tmp_path / "q")),
        sandbox=DockerSandbox(),
    )
    result = DockerSandbox().detonate(artifact, SandboxSpec(timeout_s=120), ctx)
    assert result.rigor is RigorLevel.BEHAVIORAL
    # The artifact tried to phone home on load; --network none caught + blocked it.
    assert result.status is GateStatus.FAIL
    assert any(f.code == "behavioral_network_egress" for f in result.findings)
    assert not any(f.code == "behavioral_egress_not_confined" for f in result.findings)
    # ephemeral teardown: no mig-detonate container survives
    listing = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert "mig-detonate-" not in listing.stdout
