# MIG — Model Ingestion Gateway

> Vet AI artifacts **before** they enter trusted infrastructure.

MIG is a pure-Python, embeddable library that treats public sources (Hugging
Face, GitHub, PyPI, npm, object stores, internal registries) as **untrusted**
and runs them through a composable gate pipeline that produces a **categorical,
type-aware verdict** and a **signed attestation** — the traceability artifact
for compliance (EU AI Act / NIS2 / GxP / UKSC).

It ships as a library so the same vetting logic runs as a CLI, a CI gate, a
Kubernetes admission controller, or an embedded guard inside an agent/MLOps
platform — without coupling to any one deployment.

> **Status: pre-alpha.** This repository is being built one PR at a time
> against the implementation spec. PR1 laid the keystone (domain contracts +
> seams from spec §5, packaging, CI); **PR2** adds the pipeline runner, a
> `local` source, the format-allowlist + digest + behavioral gates, and a
> working `mig scan`. The system is **decision-only** — it never writes to a
> trusted store — until promotion is introduced deliberately late and gated (PR8).

## Quickstart

```console
$ mig scan ./path/to/model        # decision-only verdict as JSON
```

A clean safetensors model returns `"decision": "approve"` with a visible
`behavioral` gate result of `"status": "skipped"` (the default `NoopSandbox`
runs no dynamic analysis — I7). Scan the same artifact as an executable type and
it can never auto-approve at static-only rigor:

```console
$ mig scan ./path/to/server --type mcp_server   # → "decision": "review_required"  (I8)
$ mig manifest ./path/to/model                  # files + content digest
```

Ingest produces a **signed attestation** (a DSSE-wrapped in-toto Statement) that
binds the decision to the artifact's content digest; `verify` re-checks the
signature, re-binds the digest, and re-asserts attribution — failing closed
(exit `3`) on any tamper:

```console
$ export MIG_SIGNING_KEY=$(openssl rand -hex 32)
$ mig ingest ./path/to/model --out model.dsse.json     # decision-only: signs, never promotes (I6)
$ mig verify ./path/to/model --attestation model.dsse.json   # exit 0 verified / 3 tampered
$ mig evidence ./path/to/model --out evidence.json     # full bundle (verdict + signed envelope)
```

## Design invariants (non-negotiable)

These are encoded as tests, not just documented:

| # | Invariant |
|---|---|
| I1 | Static gates never import / `exec` / deserialize an artifact in-process. |
| I2 | Format headers are parsed without deserializing tensor data, hardened against adversarial input. |
| I3 | Sources pin + verify the digest/SHA at fetch and land bytes in **quarantine**. |
| I4 | The verdict is **categorical and type-aware** — never a bare bool or score threshold. |
| I5 | Every attestation encodes per-gate status + rigor + scanner version, plus overall confinement. |
| I6 | `ingest()` stops at the decision; `promote()` is a separate, gated call. |
| I7 | The default `NoopSandbox` emits a **loud** `SKIPPED` behavioral result. |
| I8 | Executable artifact types can't be `APPROVE`d at static-only rigor. |
| I9 | Prompt-injection inspection is a **WARN** signal, never a hard reject. |
| I10 | MIG's own dependencies are pinned, hash-checked, minimal, and audited. |

The core has **zero runtime dependencies** (I10) — it is stdlib-only. Integrations
arrive as opt-in extras (`mig[huggingface]`, `mig[scanners]`, `mig[policy]`,
`mig[signing]`) in their respective PRs. The Docker sandbox, the cosign signer,
and the OPA promotion gate drive host CLIs (`docker`, `cosign`, `opa`) and need no
Python dependency.

## The pipeline

```
fetch (digest-pinned → quarantine)
  → format allowlist            [cheap]
  → digest / manifest           [cheap]
  → serialization safety        [cheap]    (wraps picklescan / modelscan)
  → secrets / license / metadata[cheap]
  → static code (AST)           [medium]   (trust_remote_code, custom modeling_*.py)
  → prompt-injection            [medium, WARN-only]
  → behavioral (sandbox)        [expensive](NoopSandbox by default → loud SKIPPED)
  → policy evaluation           → Verdict  (categorical, type-aware)
  → evidence bundle + signed attestation
  --- decision boundary ---
  → promote() to trusted store  [separate, gated: re-verify → policy → write → audit]
```

## CLI

```
mig scan <ref>                 # decision-only verdict (JSON)        ✓ PR2
mig manifest <ref>             # files + content digest             ✓ PR2
mig policy test <ref> --policy p.yaml                                ✓ PR5
mig ingest <ref> --signer hmac --key k   # sign a DSSE attestation  ✓ PR7
mig verify <ref> --attestation a.dsse.json   # re-check + re-bind   ✓ PR7
mig evidence <ref> --out evidence.json   # full signed bundle       ✓ PR7
mig promote <ref> --attestation a.dsse.json --key k   # gated write ✓ PR8
```

## Promotion — crossing the decision boundary (PR8)

`mig promote` is the *only* command that writes into trusted infrastructure, and
it is gated so an unverified, tampered, or non-`APPROVE` artifact can never get
there. The ordered, fail-closed flow:

1. **load** the signed attestation (never the unsigned bundle mirror);
2. **fetch + re-hash** the artifact into a fresh quarantine;
3. **re-verify** signature + digest re-bind (I3) + attribution (I5) — abort (exit 3) on tamper;
4. **gate** the *verified* attestation through the **embedded safety floor** (`decision==approve`, all checks pass, executable types need behavioral rigor under docker/gvisor, a named policy) **AND** an optional OPA policy — **deny-overrides**: OPA can only further restrict, never loosen the floor (abort exit 1 on deny);
5. **write** atomically into a content-addressed local trusted store (`mig-trusted://sha256/…`, idempotent, no-clobber) and **audit** every attempt — denials included.

```console
$ mig promote ./model --attestation model.dsse.json --key k --store-root ./trusted
$ mig promote ./mcp --attestation mcp.dsse.json --key k \
    --opa cli --opa-policy policies/promotion.rego --require-asymmetric
```

OPA (`mig[opa]`) drives the host `opa` binary; the default path is the stdlib
embedded floor (offline/airgapped). `s3`/`harbor` store backends are reserved
extras (the local filesystem store is the default). Exit codes: `0` promoted /
idempotent · `1` policy denied · `2` operator error · `3` verification failure.

## Attestation & signing (PR7)

`ingest`/`evidence` build an [in-toto Statement v1](https://github.com/in-toto/attestation)
carrying a MIG vetting predicate, canonicalise it, and sign the
[DSSE](https://github.com/secure-systems-lab/dsse) Pre-Authentication Encoding.
The signature lives only in the envelope — never inside the signed payload — and
the artifact's content digest is the Statement subject, so it is *inside* the
signed bytes. `verify` fails closed unless the signature is valid, the live
re-hash matches the attested digest (I3), and every executed gate is attributed
(I5). The verifier is always operator-chosen (`--signer`/`--key`), never selected
from the envelope's advisory keyid.

| `--signer` | needs | notes |
|---|---|---|
| `hmac` (default) | nothing (stdlib) | offline/airgapped; **integrity-only**, not third-party provenance — `verify` says so |
| `ed25519` | `pip install mig[signing]` | publicly verifiable, promotion-grade |
| `cosign` | the `cosign` binary on `PATH` | `--key` file/KMS over the same PAE (keyless/Fulcio is a non-goal) |

## Development

Requires Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                 # create the env from the locked, hashed dep set
uv run pytest           # tests
uv run mypy             # strict type-check
uv run ruff check .     # lint
uv run ruff format .    # format
```

## Build plan

Implemented in PR order; each PR leaves the system green and exercisable.
The system stays decision-only until PR8.

- **PR1** — Core contracts & scaffolding ✓
- **PR2** — Pipeline runner + walking skeleton (`mig scan` end-to-end) ✓
- **PR3** — Quarantine + digest-pinned fetch + Hugging Face source ✓
- **PR4** — Static scanner suite (picklescan, AST static-code, secrets, license, prompt-injection) ✓
- **PR5** — Declarative policy engine (`--policy` / `--fail-on` / `mig policy test`) ✓
- **PR6** — Behavioral sandbox (Docker → gVisor/Firecracker) ✓
- **PR7** — Attestation & signing (in-toto Statement + DSSE; HMAC / ed25519 / cosign) ✓
- **PR8** — Gated trusted-store promotion (embedded floor + OPA deny-overrides) ✓

## License

Licensed under the [Apache License 2.0](LICENSE).
