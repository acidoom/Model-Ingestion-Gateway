# MIG — Model Ingestion Gateway

> Vet AI models, packages, and artifacts **before** they enter trusted infrastructure.

MIG is a pure-Python, embeddable library that treats public sources (Hugging
Face, GitHub, PyPI, npm, OCI registries) as **untrusted** and runs every artifact
through a composable, **fail-closed** gate pipeline that lands it in quarantine,
inspects it, and produces a **categorical, type-aware verdict** plus a **signed
attestation** — the traceability artifact for compliance (EU AI Act / NIS2 / GxP).
Nothing reaches trusted infrastructure until it has passed every gate and been
**signed and promoted** through a separate, gated step.

It ships as a library so the same vetting logic runs as a CLI, a CI gate, a
Kubernetes admission controller, or an embedded guard inside an agent/MLOps
platform — without coupling to any one deployment.

The **core is stdlib-only** (zero runtime dependencies); every integration is an
opt-in extra. Apache-2.0.

## Reference architecture

Public registries are Zone 1 (untrusted, pull-only). The gateway (Zone 2) is a
quarantined DMZ running a sequential, fail-closed inspection pipeline; only a
clean pass is signed and promoted into the trusted platform (Zone 3).

```mermaid
flowchart LR
    subgraph Z1["ZONE 1 — Untrusted sources (pull-only)"]
        direction TB
        HF[Hugging Face Hub] ~~~ PY[PyPI] ~~~ NP[npm] ~~~ GH[GitHub] ~~~ OCI[OCI registries]
    end

    subgraph Z2["ZONE 2 — Model Ingestion Gateway (DMZ / quarantine)"]
        direction TB
        Q["Land in quarantine<br/>digest-pinned · object-locked · no execution"]
        G1["G1 · Provenance &amp; reputation<br/>(integration point)"]
        G2["G2 · Format allowlist<br/>safetensors / GGUF · pickle banned"]
        G3["G3 · Static analysis<br/>picklescan · AST · secrets · license · injection"]
        G4["G4 · Signature &amp; attestation<br/>DSSE in-toto · re-bind digest"]
        G5["G5 · Behavioural sandbox<br/>Docker / gVisor · no egress"]
        G6["G6 · Policy gate<br/>embedded floor + OPA (deny-overrides)"]
        G7["G7 · Human review<br/>(integration point)"]
        SIGN["Sign &amp; promote<br/>cosign / HSM · attach attestation"]
        Q --> G1 --> G2 --> G3 --> G4 --> G5 --> G6 --> G7 --> SIGN
    end

    subgraph Z3["ZONE 3 — Trusted platform"]
        direction TB
        HB["Harbor registry<br/>signed artifacts only · digest-verified on pull"]
        IN[Inference clusters] ~~~ TR[Training &amp; eval] ~~~ VX[Vector indexers]
    end

    subgraph X["Cross-cutting"]
        direction LR
        SIEM[SIEM · audit &amp; IoCs] ~~~ OPA[OPA policy repo] ~~~ KC[Keycloak · identity]
    end

    Z1 -- "pull only" --> Q
    SIGN -- "promote · signed" --> HB
    G3 -. "reject + IoC" .-> SIEM
```

> The diagram is the **reference deployment architecture**. This repository is the
> **gateway core** — it implements the quarantine, gates **G2–G6**, the signed
> attestation, and the gated promotion. **G1** (provenance/reputation) and **G7**
> (human review) are integration points the categorical verdict routes to
> (`review_required`); Harbor / Keycloak / SIEM are reference deployment
> components MIG produces signed evidence for, not parts of the library.

| Reference gate | MIG implementation | Module / command |
|---|---|---|
| G2 · Format allowlist | safetensors/GGUF allow, pickle weights rejected | `gates/format_allowlist` |
| G3 · Static analysis | picklescan + AST static-code + secrets + license + prompt-injection | `gates/*` |
| G4 · Signature & attestation | in-toto Statement v1 + DSSE (HMAC / ed25519 / cosign) | `mig ingest` / `verify` |
| G5 · Behavioural sandbox | confined Docker / gVisor detonation, egress-blocked | `sandbox/docker` |
| G6 · Policy gate | declarative safety-floor engine; OPA at promotion | `policy/` · `promotion/` |
| Sign & promote | gated, content-addressed write into the trusted store | `mig promote` |

## Worked example

A clean safetensors model, end to end. (The banner is stderr-only and
TTY-gated; pipe stdout and you get clean JSON. Set `MIG_NO_BANNER=1` to silence it.)

### 1 · Scan — decision-only verdict

```console
$ mig scan ./sentiment-model
```
```jsonc
{
  "artifact_type": "model",
  "gate_results": [
    { "gate_id": "format_allowlist", "status": "pass", "rigor": "static",
      "scanner_name": "mig.format_allowlist", "scanner_version": "0.1.0.dev0",
      "evidence": { "allowed_weight_files": ["model.safetensors"], "unsafe_weight_files": [] } },
    { "gate_id": "digest", "status": "pass",
      "evidence": { "digest": "sha256:96fc78750744eb81520be011be3f84265bc345f384481102b69551647a53205e" } },
    { "gate_id": "serialization_safety", "status": "pass", "scanner_name": "picklescan", "scanner_version": "1.0.4" },
    /* secrets · license_metadata · static_code · prompt_injection → all pass */
    { "gate_id": "behavioral", "status": "skipped", "rigor": "none",
      "findings": [ { "severity": 3, "code": "behavioral_analysis_skipped",
        "message": "Behavioral analysis was SKIPPED: the configured sandbox is NoopSandbox ... Do not treat any APPROVE as behaviorally vetted (I7/I8)." } ],
      "scanner_name": "sandbox:noop" }
  ],
  "decision": "approve"
}
```

The default `NoopSandbox` emits a **loud `SKIPPED`** (I7) — an APPROVE is never
silently "behaviorally vetted". Scan the *same* artifact as an executable type and
it can never auto-approve at static-only rigor (I8):

```console
$ mig scan ./sentiment-model --type mcp_server --compact
{... "decision": "review_required"}
```

A **malicious** artifact (a pickle weight that runs `os.system` on load) is
rejected — `--fail-on reject` makes the exit code non-zero for CI:

```console
$ mig scan ./evil-model --fail-on reject
```
```json
{
  "decision": "reject",
  "findings": [
    { "gate": "format_allowlist",      "code": "unsafe_serialization_format", "sev": 4 },
    { "gate": "serialization_safety",  "code": "unsafe_pickle_global",        "sev": 4 }
  ]
}
```

### 2 · Ingest — produce a signed attestation

```console
$ export MIG_SIGNING_KEY=$(openssl rand -hex 32)
$ mig ingest ./sentiment-model --out model.dsse.json
```

The output is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope whose
payload is an [in-toto Statement v1](https://github.com/in-toto/attestation); the
signature is over the canonical-JSON PAE, and the artifact digest is the
**Statement subject** (inside the signed bytes):

```jsonc
// model.dsse.json
{ "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEi...",
  "signatures": [ { "keyid": "3b7498245244a4db", "scheme": "hmac-sha256", "sig": "wHRyKIWruSUiYCs8..." } ] }

// base64-decoded payload (the signed in-toto Statement):
{ "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://mig.dev/attestation/vetting/v1",
  "subject": [ { "name": "local:///sentiment-model",
                 "digest": { "sha256": "96fc78750744eb81520be011be3f84265bc345f384481102b69551647a53205e" } } ],
  "predicate": { "decision": "approve", "overall_rigor": "static", "confinement_level": "noop",
                 "gate_summary": [ /* every gate: status + rigor + scanner_name + scanner_version (I5) */ ] } }
```

### 3 · Verify — re-check signature, re-bind digest, fail closed

```console
$ mig verify ./sentiment-model --attestation model.dsse.json --compact
{"ok": true, "scheme": "hmac-sha256", "keyid": "3b7498245244a4db", "decision": "approve",
 "checks": {"signature": true, "digest_rebind": true, "attribution": true, "keyid": true},
 "warning": "integrity-only (shared-secret HMAC), NOT third-party provenance — use ed25519/cosign across a trust boundary"}
# exit 0
```

Tamper with one byte of the artifact and verify **fails closed** — the live
re-hash no longer matches the attested subject (I3), and the exit code is `3`
(verification failure, distinct from an operator error):

```console
$ echo '{"model_type":"BACKDOORED"}' > ./sentiment-model/config.json
$ mig verify ./sentiment-model --attestation model.dsse.json --compact
{"ok": false, ... "checks": {"signature": true, "digest_rebind": false, "attribution": true, "keyid": true},
 "problems": ["digest mismatch: live sha256:cdb324... != attested sha256:96fc78..."]}
# exit 3
```

### 4 · Promote — the gated write into the trusted store

`mig promote` re-verifies the signed attestation, runs the **embedded safety
floor AND** (optionally) OPA under **deny-overrides**, then writes atomically into
a content-addressed store and audits the attempt:

```console
$ mig promote ./sentiment-model --attestation model.dsse.json --store-root ./trusted --compact
2026-06-21 ... INFO mig.promotion promotion promoted: digest=sha256:96fc78...
{"ok": true, "outcome": "promoted", "store_uri": "mig-trusted://sha256/96fc78...",
 "decision": "approve", "gate": {"allow": true, "engine": "embedded", "reasons": []},
 "verification": {"ok": true, "checks": {"signature": true, "digest_rebind": true, "attribution": true, "keyid": true}}}
# exit 0
```
```console
$ find ./trusted -type f
./trusted/cas/sha256/96/96fc78…/.complete            # commit marker, written last
./trusted/cas/sha256/96/96fc78…/artifact/config.json
./trusted/cas/sha256/96/96fc78…/artifact/model.safetensors
./trusted/cas/sha256/96/96fc78…/attestation.dsse.json   # the signed envelope
./trusted/cas/sha256/96/96fc78…/receipt.json
./trusted/index/promotions.jsonl                     # append-only audit trail
```

Promoting a tampered artifact fails verification (exit 3); promoting a `reject` /
`review_required` attestation is denied by the floor (exit 1). The same digest
re-promotes idempotently. Exit codes: `0` promoted/idempotent · `1` policy denied
· `2` operator error · `3` verification failure.

## CLI

```
mig scan <ref>            decision-only verdict (JSON)                       --policy --fail-on --sandbox
mig manifest <ref>        files + content digest
mig policy test <ref>     evaluate a policy against an artifact              --policy
mig ingest <ref>          fetch + scan + sign a DSSE attestation            --signer --key --out --bundle
mig verify <ref>          re-check signature + re-bind digest + attribution --attestation --signer --key
mig evidence <ref>        emit a full signed evidence bundle                --out
mig promote <ref>         gated write into the trusted store                --attestation --store-root --opa
```

## Design invariants (non-negotiable — encoded as tests)

| # | Invariant |
|---|---|
| I1 | Static gates never import / `exec` / deserialize an artifact in-process. |
| I2 | Format headers are parsed without deserializing tensor data, hardened against adversarial input. |
| I3 | Sources pin + verify the digest/SHA at fetch and land bytes in **quarantine**. |
| I4 | The verdict is **categorical and type-aware** — never a bare bool or score threshold. |
| I5 | Every attestation encodes per-gate status + rigor + scanner version, plus overall confinement. |
| I6 | `ingest()` stops at the decision; `promote()` is a separate, gated call (and the only trusted-store writer). |
| I7 | The default `NoopSandbox` emits a **loud** `SKIPPED` behavioral result. |
| I8 | Executable artifact types can't be `APPROVE`d at static-only rigor. |
| I9 | Prompt-injection inspection is a **WARN** signal, never a hard reject. |
| I10 | MIG's own dependencies are pinned, hash-checked, minimal, and audited. |

## Signing & promotion backends

The core path is stdlib-only and works offline/airgapped. Stronger backends are
opt-in and drive host CLIs (no Python dependency):

| Purpose | Default (stdlib) | Opt-in |
|---|---|---|
| Attestation signing | HMAC-SHA256 (`--signer hmac`) — integrity-only | `ed25519` (`mig[signing]`) · `cosign` binary |
| Behavioural sandbox | `NoopSandbox` (loud SKIPPED) | Docker / gVisor (`docker` binary) |
| Promotion policy | embedded safety floor | OPA (`mig[opa]`, `opa` binary) — **deny-overrides only** |
| Trusted store | local content-addressed filesystem | `s3` / `harbor` (reserved) |
| Fetch sources | local path | Hugging Face (`mig[huggingface]`) |
| Scanners | — | picklescan (`mig[scanners]`) |
| Policy files | JSON | YAML (`mig[policy]`) |

## Development

Requires Python ≥ 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                 # create the env from the locked, hashed dep set
uv run pytest           # tests (279 passing)
uv run mypy             # strict type-check
uv run ruff check .     # lint
uv run ruff format .    # format
```

CI (`.github/workflows/ci.yml`) runs all four checks on Python 3.11–3.13 plus a
build·smoke job, on every PR.

## Build plan

Built one PR at a time; each PR leaves the system green and exercisable. The
system stays decision-only until PR8 introduces gated promotion. **All landed:**

- **PR1** — Core contracts & scaffolding ✓
- **PR2** — Pipeline runner + walking skeleton (`mig scan` end-to-end) ✓
- **PR3** — Quarantine + digest-pinned fetch + Hugging Face source ✓
- **PR4** — Static scanner suite (picklescan, AST static-code, secrets, license, prompt-injection) ✓
- **PR5** — Declarative policy engine (`--policy` / `--fail-on` / `mig policy test`) ✓
- **PR6** — Behavioral sandbox (Docker → gVisor) ✓
- **PR7** — Attestation & signing (in-toto Statement + DSSE; HMAC / ed25519 / cosign) ✓
- **PR8** — Gated trusted-store promotion (embedded floor + OPA deny-overrides) ✓

## License

Licensed under the [Apache License 2.0](LICENSE).
