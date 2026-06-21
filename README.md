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
> against the implementation spec. **PR1 (this PR)** lays the keystone: the
> domain contracts and seams from spec §5, packaging, and CI. The system is
> **decision-only** — it never writes to a trusted store — until promotion is
> introduced deliberately late and gated (PR8).

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
arrive as opt-in extras (`mig[huggingface]`, `mig[scanners]`, `mig[docker]`, …)
in their respective PRs.

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
  → promote() to trusted store  [separate, gated]
```

## CLI (surface; subcommands land per-PR)

```
mig scan <ref>                 # decision-only verdict (JSON)        — PR2
mig ingest <ref> --policy p.yaml                                     — PR5
mig verify <ref>               # verify a prior attestation          — PR7
mig manifest <ref>                                                   — PR2
mig policy test <ref> --policy p.yaml                                — PR5
mig evidence <ref> --out evidence.zip                                — PR7
mig promote <ref> --attestation a.json   # separate, gated          — PR8
```

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

- **PR1** — Core contracts & scaffolding *(this PR)*
- **PR2** — Pipeline runner + walking skeleton (`mig scan` end-to-end)
- **PR3** — Quarantine + digest-pinned fetch + Hugging Face source
- **PR4** — Static scanner suite (wrap picklescan/modelscan, secrets, AST)
- **PR5** — Declarative policy engine
- **PR6** — Behavioral sandbox (Docker → gVisor/Firecracker)
- **PR7** — Attestation & signing (in-toto / SLSA)
- **PR8** — Trusted-store promotion (separate, gated)

## License

Licensed under the [Apache License 2.0](LICENSE).
