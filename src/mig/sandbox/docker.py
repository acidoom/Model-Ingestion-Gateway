"""DockerSandbox — confined behavioral detonation (Zone 2, PR6).

MIG *drives and verifies* confinement; the container runtime/kernel/network
*enforce* it. The default :class:`~mig.sandbox.spec.SandboxSpec` is deny-by-
default: ``--network none``, read-only rootfs, all caps dropped, no-new-
privileges, bounded memory/pids/cpu, no mounted secrets, and a wall-clock
timeout. The artifact is bind-mounted read-only and detonated by the in-container
:mod:`~mig.sandbox._harness`, which records any egress attempt (and whether the
kernel blocked it).

Outcomes (rigor=BEHAVIORAL): a network egress attempt on load → HIGH →
``FAIL`` (caught); egress that *succeeded* → CRITICAL (a confinement breach,
which ``--network none`` must prevent); a clean load → ``PASS`` at behavioral
rigor, which is what lets an executable type finally satisfy I8.

Two modes: the default runs the container inline; ``spec_emit=True`` instead
emits a portable Job manifest (:meth:`emit_manifest`) for an external runner
(PRD §10 PR6b) and reports the detonation as deferred.

``gVisor`` is selected by ``runtime="runsc"`` (a stronger sandbox than runc);
Firecracker/Kata are future runtimes the same seam supports.

Detection vs. confinement. The egress *block* is kernel-enforced by
``--network none`` and is the hard guarantee — an artifact simply cannot reach
the network. The *detection* (recording the attempt) is best-effort: the harness
loads the artifact in its own process, so a sophisticated artifact could suppress
or forge the in-process observation. A per-run nonce stamped into the sentinel
defeats lazy forgery (a sentinel printed without the right nonce is ignored), but
not an artifact that reads its own argv. Robust, out-of-process capture
(namespace/eBPF/strace) is a follow-on; the confinement claim does not depend on
it.
"""

from __future__ import annotations

import contextlib
import json
import os
import pathlib
import subprocess
from typing import TYPE_CHECKING, Any

from mig.core.verdict import Finding, GateStatus, RigorLevel, Severity
from mig.sandbox import _harness
from mig.sandbox.spec import SandboxObservation, SandboxSpec

if TYPE_CHECKING:
    from mig.core.artifact import Artifact
    from mig.core.context import ScanContext

#: Default container image — minimal Python; the harness is stdlib-only.
DEFAULT_IMAGE = "python:3.12-slim"

#: Mount point for the artifact inside the container.
_ARTIFACT_MOUNT = "/artifact"

#: Size-bounded writable scratch — required because the rootfs is read-only.
#: ``mode=1777`` so the non-root detonation user (see _run_as_user_spec) can use
#: it as HOME; ``noexec``/``nosuid`` keep it from being an execution staging area.
_TMPFS_MOUNT = "/tmp:rw,noexec,nosuid,size=64m,mode=1777"


class DockerUnavailableError(RuntimeError):
    """Raised when the Docker CLI/daemon cannot be reached."""


def _run_as_user_spec() -> str | None:
    """``uid:gid`` to run the container as — the host uid that owns the quarantine.

    The quarantine dir is ``0o700`` owned by the MIG process uid. We drop ALL
    capabilities, so a root container loses ``CAP_DAC_READ_SEARCH`` and could NOT
    read that mount. Running as the owning uid both fixes the read and means the
    detonation runs **non-root** (defense in depth). Returns ``None`` on non-POSIX
    hosts (e.g. Windows), where we fall back to the image default.
    """
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is None or getgid is None:
        return None
    return f"{getuid()}:{getgid()}"


def _run_docker(
    docker_bin: str, args: list[str], *, timeout_s: int
) -> tuple[int | None, str, str, bool]:
    """Invoke ``docker`` and return ``(exit, stdout, stderr, timed_out)``.

    The single seam every container invocation passes through — monkeypatched in
    unit tests so they need no Docker daemon.
    """
    try:
        proc = subprocess.run(
            [docker_bin, *args],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DockerUnavailableError(f"docker CLI not found: {docker_bin!r}") from exc
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        err = exc.stderr if isinstance(exc.stderr, str) else ""
        return None, out, err, True
    return proc.returncode, proc.stdout, proc.stderr, False


class DockerSandbox:
    """Detonate an artifact in a hardened, ephemeral container."""

    rigor: RigorLevel = RigorLevel.BEHAVIORAL

    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        *,
        runtime: str | None = None,
        docker_bin: str = "docker",
        spec_emit: bool = False,
    ) -> None:
        self.image = image
        self.runtime = runtime
        self.docker_bin = docker_bin
        self.spec_emit = spec_emit

    @property
    def confinement_level(self) -> str:
        return "gvisor" if self.runtime == "runsc" else "docker"

    # -- public API ---------------------------------------------------------- #

    def detonate(
        self, artifact: Artifact, spec: SandboxSpec, ctx: ScanContext
    ) -> SandboxObservation:
        if self.spec_emit:
            return self._deferred_observation(artifact, spec)
        return self._run(artifact, spec)

    def emit_manifest(self, artifact: Artifact, spec: SandboxSpec) -> dict[str, object]:
        """A portable confinement Job manifest for an external runner (PR6b).

        Built from the same :meth:`_container_command` / :meth:`_container_env` /
        ``_TMPFS_MOUNT`` the inline run uses, so the external-runner path cannot
        drift weaker than the inline path (M3).
        """
        token = os.urandom(16).hex()
        return {
            "image": self.image,
            "runtime": self.runtime,
            "command": self._container_command(spec, token),
            # The runner echoes the harness's sentinel; only one stamped with this
            # nonce is trusted (a detonated artifact cannot forge it blindly).
            "observation_token": token,
            "mounts": [
                {
                    "source": os.path.abspath(artifact.quarantine_path),
                    "target": _ARTIFACT_MOUNT,
                    "read_only": True,
                }
            ],
            "network": spec.network,
            "read_only_rootfs": spec.read_only,
            "cap_drop": list(spec.cap_drop),
            "no_new_privileges": spec.no_new_privileges,
            "seccomp": spec.seccomp,
            "pids_limit": spec.pids_limit,
            "memory": spec.memory,
            "cpus": spec.cpus,
            "timeout_s": spec.timeout_s,
            "env": self._container_env(spec),
            "user": _run_as_user_spec(),  # non-root; owner of the artifact mount
            "workdir": "/tmp",
            "tmpfs": [_TMPFS_MOUNT],
            "auto_remove": True,  # ephemeral — the runner must not retain it
        }

    # -- internals ----------------------------------------------------------- #

    @staticmethod
    def _harness_source() -> str:
        return pathlib.Path(_harness.__file__).read_text(encoding="utf-8")

    def _container_command(self, spec: SandboxSpec, token: str) -> list[str]:
        """The in-container command — the single source of truth shared by the
        inline run and the emitted manifest so they cannot drift (M3).

        ``timeout`` makes the wall-clock bound authoritative *inside* the sandbox
        (SIGKILL), independent of the host-side client timeout. It is part of
        coreutils (present in the default image); if a custom image lacks it the
        container fails to start → no observation → ERROR → REVIEW_REQUIRED,
        which is fail-safe.
        """
        return [
            "timeout",
            "-s",
            "KILL",
            str(spec.timeout_s),
            # `python -I`: isolated mode (ignore env/site) for a clean detonation.
            "python",
            "-I",
            "-c",
            self._harness_source(),
            _ARTIFACT_MOUNT,
            token,
        ]

    @staticmethod
    def _container_env(spec: SandboxSpec) -> dict[str, str]:
        """Env for the detonation. ``spec.env`` is an explicit operator allowlist
        and is always forwarded — it MUST NOT carry secrets (the artifact runs
        with full read access to its own environment). ``mount_secrets`` is
        reserved: MIG never mounts host secret stores into an untrusted
        detonation, regardless of its value.
        """
        env = {"PYTHONDONTWRITEBYTECODE": "1", "HOME": "/tmp"}
        env.update(spec.env)
        return env

    def _build_run_args(
        self, artifact: Artifact, spec: SandboxSpec, name: str, token: str
    ) -> list[str]:
        args = ["run", "--rm", "--name", name]
        args += ["--network", spec.network]
        user = _run_as_user_spec()
        if user is not None:
            # Non-root, and the owner of the 0700 quarantine mount (so cap-drop
            # ALL doesn't make the artifact unreadable). See _run_as_user_spec.
            args += ["--user", user]
        if spec.read_only:
            args += ["--read-only"]
        for capability in spec.cap_drop:
            args += ["--cap-drop", capability]
        if spec.no_new_privileges:
            # The explicit ``:true`` form — the bare token is honored
            # inconsistently across runtimes (notably gVisor).
            args += ["--security-opt", "no-new-privileges:true"]
        if spec.seccomp:
            args += ["--security-opt", f"seccomp={spec.seccomp}"]
        args += ["--pids-limit", str(spec.pids_limit)]
        args += ["--memory", spec.memory, "--cpus", spec.cpus]
        if self.runtime:
            args += ["--runtime", self.runtime]
        # Writable, size-bounded scratch so Python can run under a read-only rootfs.
        args += ["--tmpfs", _TMPFS_MOUNT, "--workdir", "/tmp"]
        for key, value in self._container_env(spec).items():
            args += ["--env", f"{key}={value}"]
        args += [
            "--volume",
            f"{os.path.abspath(artifact.quarantine_path)}:{_ARTIFACT_MOUNT}:ro",
        ]
        args += [self.image, *self._container_command(spec, token)]
        return args

    def _run(self, artifact: Artifact, spec: SandboxSpec) -> SandboxObservation:
        name = f"mig-detonate-{os.urandom(6).hex()}"
        token = os.urandom(16).hex()  # per-run nonce — see module docstring
        try:
            exit_code, stdout, _stderr, timed_out = _run_docker(
                self.docker_bin,
                self._build_run_args(artifact, spec, name, token),
                timeout_s=spec.timeout_s + 10,
            )
        except DockerUnavailableError as exc:
            return _error_observation("sandbox_unavailable", str(exc))

        if timed_out:
            self._force_remove(name)
            return SandboxObservation(
                rigor=RigorLevel.BEHAVIORAL,
                status=GateStatus.WARN,
                findings=[
                    Finding(
                        gate_id="behavioral",
                        severity=Severity.HIGH,
                        code="behavioral_timeout",
                        message=f"detonation exceeded {spec.timeout_s}s; killed",
                    )
                ],
            )
        if exit_code is not None and "Cannot connect to the Docker daemon" in _stderr:
            return _error_observation("sandbox_unavailable", _stderr.strip()[:200])
        return _observation_from_stdout(
            stdout, exit_code, token, expected_files=len(artifact.files)
        )

    def _force_remove(self, name: str) -> None:
        with contextlib.suppress(DockerUnavailableError):  # best-effort teardown
            _run_docker(self.docker_bin, ["rm", "--force", name], timeout_s=15)

    def _deferred_observation(
        self, artifact: Artifact, spec: SandboxSpec
    ) -> SandboxObservation:
        manifest = self.emit_manifest(artifact, spec)
        return SandboxObservation(
            rigor=RigorLevel.NONE,  # not run here — an external runner must execute it
            status=GateStatus.SKIPPED,
            findings=[
                Finding(
                    gate_id="behavioral",
                    severity=Severity.MEDIUM,
                    code="behavioral_spec_emitted",
                    message="emitted a sandbox Job manifest for external execution",
                )
            ],
            raw={"manifest": manifest},
        )


def _extract_observation(stdout: str, token: str) -> dict[str, Any] | None:
    # Only a sentinel stamped with this run's nonce is trusted; a forged one
    # printed by the detonated artifact (which shares this stdout) is ignored.
    marker = f"{_harness.OBSERVATION_PREFIX}{token}:"
    start = stdout.find(marker)
    end = stdout.find(_harness.OBSERVATION_SUFFIX, start)
    if start == -1 or end == -1:
        return None
    payload = stdout[start + len(marker) : end]
    try:
        parsed = json.loads(payload)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _observation_from_stdout(
    stdout: str, exit_code: int | None, token: str, expected_files: int = 0
) -> SandboxObservation:
    parsed = _extract_observation(stdout, token)
    if parsed is None:
        return SandboxObservation(
            rigor=RigorLevel.NONE,
            status=GateStatus.ERROR,
            findings=[
                Finding(
                    gate_id="behavioral",
                    severity=Severity.MEDIUM,
                    code="behavioral_no_observation",
                    message=f"detonation produced no observation (exit {exit_code})",
                )
            ],
            exit_code=exit_code,
        )

    attempts = parsed.get("network_attempts", [])
    dns_raw = parsed.get("dns_queries", [])
    # The observation is artifact-influenced; a non-list here is malformed/forged.
    # Treat it as untrustworthy → ERROR → REVIEW_REQUIRED (fail-closed), never a
    # clean pass an executable could ride to APPROVE.
    if not isinstance(attempts, list) or not isinstance(dns_raw, list):
        return SandboxObservation(
            rigor=RigorLevel.NONE,
            status=GateStatus.ERROR,
            findings=[
                Finding(
                    gate_id="behavioral",
                    severity=Severity.MEDIUM,
                    code="behavioral_malformed_observation",
                    message="detonation observation was malformed (untrusted)",
                )
            ],
            exit_code=exit_code,
        )
    dns = [str(q) for q in dns_raw]
    # Fail-closed: if the artifact has files but the harness observed absolutely
    # nothing — no file loaded, no error, no network/DNS — it never actually read
    # the artifact (e.g. an unreadable mount). That must NOT be a clean behavioral
    # PASS an executable could ride to APPROVE.
    loaded = parsed.get("loaded") or []
    errs = parsed.get("errors") or []
    if expected_files and not (loaded or errs or attempts or dns):
        return SandboxObservation(
            rigor=RigorLevel.NONE,
            status=GateStatus.ERROR,
            findings=[
                Finding(
                    gate_id="behavioral",
                    severity=Severity.MEDIUM,
                    code="behavioral_artifact_unreadable",
                    message=(
                        f"detonation observed none of the artifact's {expected_files} "
                        "file(s) — it was not actually loaded"
                    ),
                )
            ],
            exit_code=exit_code,
            raw=parsed,
        )
    findings: list[Finding] = []
    if attempts:
        addresses = [a.get("address") for a in attempts if isinstance(a, dict)]
        findings.append(
            Finding(
                gate_id="behavioral",
                severity=Severity.HIGH,
                code="behavioral_network_egress",
                message=f"artifact attempted network egress on load: {addresses}",
                metadata={"attempts": attempts},
            )
        )
        if any(isinstance(a, dict) and a.get("blocked") is False for a in attempts):
            findings.append(
                Finding(
                    gate_id="behavioral",
                    severity=Severity.CRITICAL,
                    code="behavioral_egress_not_confined",
                    message=(
                        "network egress SUCCEEDED in the sandbox — confinement breach"
                    ),
                )
            )
    elif dns:
        # Hostname resolution with no connection — recon-flavoured, surfaced (LOW)
        # but non-failing so a benign lookup doesn't block an executable's APPROVE.
        findings.append(
            Finding(
                gate_id="behavioral",
                severity=Severity.LOW,
                code="behavioral_dns_lookup",
                message=f"artifact resolved hostnames without connecting: {dns}",
                metadata={"dns_queries": dns},
            )
        )

    status = (
        GateStatus.FAIL
        if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        else GateStatus.PASS
    )
    return SandboxObservation(
        rigor=RigorLevel.BEHAVIORAL,
        status=status,
        findings=findings,
        dns_queries=dns,
        network_attempts=[str(a) for a in attempts],
        exit_code=exit_code,
        raw=parsed,
    )


def _error_observation(code: str, message: str) -> SandboxObservation:
    return SandboxObservation(
        rigor=RigorLevel.NONE,
        status=GateStatus.ERROR,
        findings=[
            Finding(
                gate_id="behavioral", severity=Severity.MEDIUM, code=code, message=message
            )
        ],
    )


def docker_available(docker_bin: str = "docker") -> bool:
    """True if a Docker daemon is reachable (used to skip integration tests)."""
    try:
        exit_code, _out, _err, timed_out = _run_docker(
            docker_bin, ["info", "--format", "{{.ServerVersion}}"], timeout_s=8
        )
    except DockerUnavailableError:
        return False
    return exit_code == 0 and not timed_out
