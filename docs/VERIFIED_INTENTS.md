# Verified Intents — trades a malicious host can't forge, on any CPU

**Status:** SPEC (design + implementation plan; not built). The software-only counterpart to
[SEALED_AGENTS.md](./SEALED_AGENTS.md) (the hardware/TEE path). Companion to [SECURITY.md](../SECURITY.md).

**Premise (unchanged):** agents run on operators' **regular CPUs**, on machines the operator fully
controls. We cannot change that, and we will not require special hardware. So we do **not** try to hide
the agent from the host — we make the host's tampering *useless* by refusing to trust the host's trade
decision, and instead re-deriving it on the trusted side from **authenticated inputs**.

---

## 0. The issue, stated precisely (so we're aligned)

Today the off-box signer means a malicious host **cannot drain** an agent (the key is off-box; the
autonomous vocabulary is `buy | sell`, no transfer/withdraw). But the agent's **session token lives in
its environment on the host**, and the signer authenticates a trade by `{epoch, token}` alone — nothing
the host lacks. So a hostile host can **submit `buy`/`sell` intents of its own choosing** (within
policy): churn the wallet, time trades badly, push into a token it's about to dump. Bounded by caps, not
theft — but real. **We want to prevent forged/substituted trades, on a regular CPU.**

Containers don't help: every software sandbox protects the *host from the guest*, never the *guest from
the host* (the operator is the kernel/hypervisor). The only thing that hides the agent from the host is a
TEE — special hardware (see SEALED_AGENTS.md). **This spec takes the other road: don't hide, validate.**

## 1. Does zkTLS solve it?

**Partly — and only as one ingredient. zkTLS is necessary but not sufficient.** Be precise about what it
gives us:

- zkTLS (TLSNotary / DECO / Reclaim / zkPass) lets a party **prove that data came from a specific HTTPS
  server over a genuine TLS session** — without the server's cooperation, optionally in zero-knowledge.
  i.e. it authenticates **inputs** (the price/feed the agent claims it acted on).
- On its own, zkTLS does **not** stop a forged trade. The host could present *real* data and still submit
  a trade that the data doesn't justify.

The fix is **zkTLS-grade authenticated inputs *plus* a signer-side decision check**:

> The signer signs a trade **only if** (a) the inputs are authenticated, and (b) the trade is the correct
> output of the owner's agreed decision rule **re-evaluated on those inputs by the signer**.

Now the host can't fake the inputs (authenticity) and can't fake the decision (the signer recomputes it).
**It can no longer forge an arbitrary trade.** What it *can* still do is weaker (and bounded): withhold or
time genuinely-valid trades, and front-run/sandwich a known trade (MEV). Those are residuals we name in
§5, not forgery.

And a Circuit-specific simplification: **for Circuit's own data and AI, you don't need zkTLS at all** —
the data API and the inference gateway are *first-party* services that can simply **sign their
responses**. zkTLS is the heavier escape hatch for *third-party* web data the host could MITM (a CEX
order book, say). Best practice: use the cheapest authenticity mechanism the data source allows.

**So: zkTLS solves the *input-authenticity* half of the problem for third-party data. The whole problem
is solved (for checkable strategies, on any CPU) by "Verified Intents" — authenticated inputs (signed
first-party data and/or zkTLS) + a signer-side decision gate.** It does **not** cover opaque/un-checkable
strategies (those fall back to deterrence or a TEE), and it shifts some trust to oracles/notaries.

---

## 2. Design — Verified Intents

**Principle: validate, don't isolate.** The agent still decides; the signer no longer takes the
decision on faith — it demands *evidence* and re-derives the trade.

### 2.1 The verified intent

The agent submits, instead of a bare intent:

```jsonc
POST /v1/agents/{id}/intent
{
  "epoch": N, "token": "<session>",                 // the existing fence (unchanged)
  "intent":  { "kind": "buy|sell", "token": "<mint>", "sizeSol": 0.01, "amount": null, "maxSlippageBps": 100 },
  "rule":    "dip-v1",                                // which owner-committed decision rule justifies this
  "inputs":  { "price": 1.83, "rsi": 27, "aiVerdict": "BUY", ... },  // the values the rule consumed
  "evidence": [ <SignedQuote> | <InferenceReceipt> | <ZkTlsProof> ... ]   // proves each input is authentic
}
```

### 2.2 Input authenticity — two sources

| Source | Mechanism | Use for | Cost |
|---|---|---|---|
| **First-party signed data** | Circuit data API / inference gateway sign their responses (ed25519) | anything Circuit serves: prices, market data, **AI decisions** | cheap, low-latency, no MPC |
| **zkTLS** | TLSNotary (MPC-notary) or Reclaim/zkPass (proxy-attestor) | third-party web data the host could MITM (CEX, external API) | seconds of latency, notary trust |

**SignedQuote** (first-party, from circuit-data-api):
```jsonc
{ "kind": "signed-quote", "path": "/api/token-price?mint=…", "data": { "price": 1.83 },
  "ts": 1719…, "nonce": "ab12…", "key": "<data-api pubkey>", "sig": "<ed25519 over canonical(data,ts,nonce,path)>" }
```

**InferenceReceipt** (first-party, from the DLLM gateway — turns an AI decision into a verifiable input):
```jsonc
{ "kind": "inference-receipt", "input_hash": "<sha256(messages+params)>", "output_hash": "<sha256(content)>",
  "verdict": "BUY", "model_fp": "qwen2.5-72b-awq", "ts": …, "nonce": "…",
  "key": "<orchestrator mesh pubkey>", "sig": "<ed25519>" }
```

**ZkTlsProof** (third-party):
```jsonc
{ "kind": "zktls", "source": "api.exchange.com", "claim": { "symbol": "SOLUSDC", "price": 1.84 },
  "session_time": …, "notary": "<notary pubkey>", "proof": "<tlsnotary attestation | reclaim claim>" }
```

### 2.3 The signer-side decision gate

The owner **commits a decision rule** at agent creation (owner-signed): a small, deterministic program
`rule(inputs) -> Intent | null`, registered by id (`dip-v1`) with its accepted input keys/notaries. The
signer stores it. On every intent:

```
verify session epoch + token (the fence)                         ── unchanged
for each evidence item:  verify signature/proof  AND  freshness   ── new (anti-replay: ts within window + unused nonce)
check intent.inputs == the values proven by evidence              ── new (bind inputs to evidence)
re-run rule(intent.inputs)  →  must equal intent.intent           ── new (the decision gate)
then: policy caps (notional/daily/cooldown/allow) as today        ── unchanged (defense in depth)
sign  ── only now
```

Reject codes added: `evidence-invalid`, `evidence-stale`, `input-mismatch`, `decision-unjustified`,
`unknown-rule`. A host that submits a self-chosen trade fails `decision-unjustified` (the rule, re-run on
authenticated inputs, didn't produce it).

### 2.4 Flow

```
   ┌──────── agent (on untrusted host) ────────┐
   │ sense → gather AUTHENTICATED inputs:       │   signed quote  ◄── circuit-data-api (signs responses)
   │   • signed price (first-party)             │   receipt       ◄── DLLM gateway (signs inference output)
   │   • signed AI verdict (inference receipt)  │   zktls proof   ◄── TLSNotary/Reclaim (third-party data)
   │   • zktls proof (external data)            │
   │ decide via rule → buy/sell                 │
   └───────────────┬────────────────────────────┘
                   │  VERIFIED INTENT  { intent, rule, inputs, evidence }
                   ▼
   ┌──────────────────────── signer (off-box) ───────────────────────┐
   │ verify each evidence (sig/proof + freshness) → bind inputs       │
   │ RE-RUN rule(inputs); must equal the intent  → else reject        │
   │ policy caps → sign with the off-box key                          │
   └─────────────────────────────────────────────────────────────────┘
```

The host fully controls the agent and **still can't get a trade signed that the authenticated inputs +
the owner's rule don't justify.**

---

## 3. zkTLS, in depth (best practices)

Two production models; pick per trust/latency budget.

| Model | How | Trust | Latency / cost | Examples |
|---|---|---|---|---|
| **MPC-notary** | a Notary co-runs the TLS handshake via MPC (split session keys), never sees plaintext; signs a transcript attestation; prover selectively discloses | verifier trusts the Notary **not to collude with the prover** | latency-sensitive (TLS 8–30s window); historically ~20 MB/session, much better with the 2025 VOLE-IZK *QuickSilver* backend | **TLSNotary** |
| **Proxy-attestor** | an attestor proxies the TLS session, gets ephemeral keys, signs a claim | same collusion assumption; attestor IPs can be rate-limited by servers | fast (~2–4 s), SDK/mobile-friendly | **Reclaim**, **zkPass** (hybrid) |

**Recommendation:** start with **TLSNotary + a self-hosted Notary** (open-source, trust-minimized, the
Notary never sees plaintext) for the trust-sensitive path; offer **Reclaim** as a fast-integration option
for low-stakes feeds. Either way:

- **Decentralize the notary** — accept a *set* of independent notaries (or a threshold/multiparty notary,
  e.g. TACEO-style) so no single notary↔host collusion forges a proof. The signer's policy carries
  `acceptedNotaries` and a quorum.
- **Bind freshness** — the proof must carry the TLS session time + a signer-issued nonce; the signer
  rejects anything outside a tight window (anti-replay of a real-but-stale quote). **This is mandatory** —
  without it the host replays an old genuine quote to justify a now-bad trade.
- **Don't prove per-trade if you can avoid it** — MPC-TLS is slow. Prove the *feed* periodically (a fresh
  signed price every N seconds) and let many trade-decisions consume the latest proof within its freshness
  window. For Circuit-served data, skip zkTLS entirely (first-party signing is ms-fast).
- **Selective disclosure** — redact anything sensitive (API keys, account ids) from the transcript; prove
  only the field the rule needs (`price`).
- **Server rate-limiting** — expect exchanges to throttle known attestor IPs; rotate/spread, or prefer
  first-party Circuit data.

zkTLS can also *compose* with a TEE or zkVM (prove the data authentic, then prove the computation) — out
of scope here; noted for later.

---

## 4. Strategy expressiveness — the honest constraint

"Validate, don't isolate" only protects what the signer can **re-check**. Three tiers:

| Tier | Strategy shape | Guarantee |
|---|---|---|
| **T1 — deterministic rule** | `buy if price < X and rsi > Y` over signed/zkTLS inputs | **fully prevented** — signer re-runs the rule; host can't forge |
| **T2 — signed AI** | decision = a **signed inference verdict** from Circuit's DLLM over signed inputs | **prevented**, *modulo trusting the inference network's signature* (the host can't fake the verdict; the mesh produced + signed it) |
| **T3 — opaque / un-checkable** | a big black-box the signer can't re-run or get signed | **not prevented** — falls back to deterrence (stake/slash) or a TEE (SEALED_AGENTS.md) |

The lever that makes T2 work is **first-party inference signing**: the DLLM gateway signs *"for input P,
the model output O"*. That doesn't prove the output is *profitable* — it proves the host didn't *fake* the
AI's call. Most Circuit agents (rule-based, or rule-over-AI-verdict) land in T1/T2.

---

## 5. Security analysis

**Prevented** (T1/T2, regular CPU):
- the host forging/substituting a trade the inputs+rule don't justify (`decision-unjustified`);
- the host feeding fake data to justify a trade (`evidence-invalid` / authenticated inputs);
- replay of stale-but-real data (`evidence-stale` / freshness binding);
- (still) any drain — unchanged, off-box `buy/sell`-only.

**Residual** (named honestly):
- **Withholding / timing** — the host can refuse to submit a valid trade, or pick *when* among genuinely
  valid ones. Bounded griefing (missed trades), not forgery. Mitigate with liveness expectations +
  reputation/slashing for under-performing hosts.
- **MEV / front-running** — a host that sees the agent's pending trade could front-run/sandwich it.
  Mitigate with private submission, slippage caps (already in policy), and not leaking intent early.
- **Oracle / notary trust** — you now trust the data-API signing key, the inference signing keys, and the
  zkTLS notary(ies). Mitigate: publish + rotate keys, decentralize the notary (quorum), and keep these
  small auditable components. (This *moves* trust off the host onto a few named, decentralizable parties —
  a strict improvement.)
- **Signer still trusted for funds** — Verified Intents constrains *what gets signed*; the signer still
  holds the key. Removing that is the MPC-signer step (L3 in SEALED_AGENTS.md), independent of this.
- **Strategy constraint** — T3 isn't covered. That's the real limit of the software-only approach.

**Net:** on a regular CPU, Verified Intents turns "host can submit any in-policy trade" into "host can
only submit trades the authenticated market + the owner's rule actually justify, and can at most
withhold/time them." That is the strongest *prevention* (not just deterrence) achievable without special
hardware.

---

## 6. Implementation plan

**Data formats** — §2.2 (SignedQuote, InferenceReceipt, ZkTlsProof, VerifiedIntent). Canonical signing =
`stableStringify` (sorted keys, compact) over `{data|claim, ts, nonce, path|input_hash}`; ed25519. All
keys published at a well-known endpoint and (later) committed on-chain.

**Milestones** (each shippable, increasing coverage):

| M | Ships | Covers |
|---|---|---|
| **M0** | first-party **response signing** in circuit-data-api + DLLM gateway; SDK verifiers | the inputs become authenticatable |
| **M1** | **signer decision gate** + rule registry + owner-committed rules; `requireVerifiedIntent` policy; reference rule agent (`agentd`) | **T1 prevented** on Circuit data |
| **M2** | **inference receipts** wired end-to-end; rule-over-AI-verdict template | **T2 prevented** |
| **M3** | **zkTLS** evidence (TLSNotary self-hosted notary) for third-party feeds; notary set + freshness | third-party data |
| **M4** | decentralize the notary (quorum), key rotation, on-chain key/rule registry | trust-minimized |

Best practices: deterministic canonical encoding, mandatory freshness/nonce anti-replay, evidence
signature verification before any state change, fail-closed on unknown rule/notary, keep policy caps as
defense-in-depth, comprehensive unit tests with injected fakes (no live notary needed for CI).

---

## 7. Cross-repo updates

This spans the whole ecosystem; here's what each repo must do.

### `circuit-agent-cloud` (this repo — the core)
- **signer/server.js** — extend the `/v1/agents/{id}/intent` handler with: evidence verification
  (first-party sig + zkTLS), a freshness/nonce anti-replay store, a **rule registry** (owner-committed
  `ruleId → rule`), and the **decision gate** (re-run rule, compare to intent). New reject codes.
- **lib/proto.js** — extend `Policy` (`requireVerifiedIntent`, `ruleId`, `acceptedDataKeys`,
  `acceptedInferenceKeys`, `acceptedNotaries`, `evidenceMaxAgeMs`); add `VerifiedIntent`, `Evidence`,
  `Rule` types + `normalizeRule`.
- **control-plane** — accept the owner's committed `{ruleId, rule, acceptedKeys}` at agent create
  (owner-signed), pass to the signer at provision; agent spec carries `ruleId`.
- **node-host / agentd** — the reference workload collects evidence (calls signed data + inference) and
  submits a verified intent; demonstrates the rule template.
- **SECURITY.md / README** — document the verified-intent guarantee + the software/hardware split.

### `circuit-data-api`
- Add a **response-signing layer**: an ed25519 signing key; sign responses (`canonical(data,ts,nonce,path)`)
  and return a `sig` block or `X-Circuit-Signature` header, behind `?signed=1` (or always). Publish the
  public key at `/.well-known/circuit-data-key` (+ later on-chain). Reusable as a verifiable data feed
  beyond agents.

### `circuit-dllm` (inference gateway / engine)
- Add **inference-output signing**: the gateway/orchestrator signs `{input_hash, output_hash, verdict?,
  model_fp, ts, nonce}` with its **mesh node key** (the existing ed25519 `MeshIdentity` — reuse it) and
  returns an `attestation` block on `/v1/chat/completions`. Optionally a structured-verdict mode so a
  rule can consume a clean `BUY|SELL|HOLD`. (This signs *that the mesh produced the output*, not that it's
  correct — it removes the host's ability to fake the AI's call.)

### `circuit-sdk`
- **`@circuit/agent`** — a **verified-intent custody mode**: `this.buy/sell` collect evidence + attach
  `{rule, inputs, evidence}`; `SignerCustody` submits a `VerifiedIntent`. Helpers `this.signedData()` /
  `this.signedInference()` (clients that return + verify signatures), an **evidence collector**, and a
  **local rule evaluator** so a dev can test "evidence + rule → intent" offline (the same evaluator the
  signer runs — single source of truth).
- **New `@circuit/attest`** (or a submodule of agent) — verify SignedQuote / InferenceReceipt / ZkTlsProof
  (a TLSNotary + Reclaim verifier), the canonical signing helpers, the `Rule` schema + reference
  evaluator. Zero-/light-dep; reusable server-side (the signer can import the same verifiers).
- **`@circuit/data`** — `signed: true` option → request + verify signed responses.
- **`@circuit/inference`** — surface the `attestation` block from `chat`.
- **`@circuit/node`** — reuse `verifyMeshBody`/mesh-identity to verify inference receipts (already present).
- Docs + the threat-model box updated (see §8).

### `circuit-cli`
- `circuit agent create --rule <file>` — commit the decision rule + accepted keys (owner-signed); `circuit
  agent verify <intent>` — locally check evidence+rule→intent; show evidence/receipt in trade output.

---

## 8. README & docs cleanup (required, ecosystem-wide)

The conversation that produced this spec exposed that our docs over-state the safety story ("agents can't
be messed with") without the precise boundary. Fix it everywhere, consistently:

**circuit-sdk**
- `README.md` — tighten the safety claims: state plainly *no drain (always)*, *forged trades prevented for
  checkable strategies via Verified Intents*, *opaque strategies need deterrence or a TEE*. Add a short
  **"Trust & safety"** subsection that links both specs and the threat-model.
- `docs/agents.md` — extend the **"What a host can — and can't — do"** table with the Verified-Intents row
  ("with Verified Intents, a host can't forge trades the rule+inputs don't justify"); present the **two
  hardening paths** clearly — *Verified Intents (software, any CPU, checkable strategies)* vs *Sealed
  Agents (TEE, any strategy, special hardware)* — and when to pick which.
- **New `docs/verified-intents.md`** — developer guide: how to write a decision rule, collect evidence
  (signed data / inference receipt / zkTLS), the strategy tiers, the local evaluator, and a worked
  dip-buy example.
- `SDK.md` — update the `@circuit/agent` section + the custody model + the roadmap to include Verified
  Intents and the new `@circuit/attest` package; cross-reference both agent-cloud specs.
- Sweep for over-claims: anywhere that implies an agent is fully tamper-proof today gets qualified.

**circuit-agent-cloud**
- `README.md` + `SECURITY.md` — add the verified-intent guarantee; present the **software (Verified
  Intents) vs hardware (Sealed Agents)** options as the two roads to "host can't influence trades," with
  the residuals; link both `docs/` specs.

**Consistency pass (all repos)** — unify terminology (*custody · intent · evidence · rule · attestation ·
fence*), the CIRC CA, endpoints, and the "no drain / no forgery (checkable) / deterrence (opaque)" framing
so the story is identical everywhere. (Execute this as a follow-up PR set once M1 lands, so docs match
shipped behavior — not before.)

---

## 9. Decisions to make

1. **zkTLS provider** — self-hosted TLSNotary (trust-min) vs Reclaim (speed). Lean: TLSNotary for the
   trust-sensitive path, Reclaim optional. Or **skip zkTLS for v1** and ship M0–M2 (first-party signing
   only) since most Circuit agents trade on Circuit data + Circuit AI — zkTLS (M3) is the third-party
   escape hatch.
2. **Rule language** — a tiny sandboxed expression DSL (safe, easy to re-run, easy to commit) vs a
   WASM/JS module (expressive, heavier to sandbox in the signer). Lean: a small DSL for T1, signed-AI
   verdict for anything richer.
3. **Where rules + keys are committed** — owner-signed off-chain blob vs on-chain registry (composes with
   the existing Solana footprint + future MPC signer). Lean: on-chain registry by M4.
4. **Mandatory or opt-in** — `requireVerifiedIntent` per-agent (opt-in, gradual) vs network default for
   live agents. Lean: opt-in → default-for-live once the tooling is smooth.

## 10. References

- TLSNotary (MPC-TLS, notary, selective disclosure, 2025 QuickSilver backend, proxy mode):
  <https://tlsnotary.org/docs/intro/>, <https://tlsnotary.org/blog/2025/08/31/benchmarks/>
- Multiparty / threshold notaries for zkTLS (decentralizing notary trust):
  <https://core.taceo.io/articles/mpc-zktls/>
- Reclaim Protocol (proxy-attestor zkTLS, SDK): <https://blog.reclaimprotocol.org/posts/zk-in-zktls>
- zkPass (hybrid MPC / proxy-witness, TransGate): <https://medium.com/zkpass/zktls-the-cornerstone-of-verifiable-internet-da8609a32754>
- DECO (decentralized TLS oracle, prove provenance + ZK statements): <https://arxiv.org/pdf/1909.00938>
- zkTLS overview / trust + composability: <https://www.shoal.gg/p/zktls-verifiable-data-composability>
- Companion: TEE path — [SEALED_AGENTS.md](./SEALED_AGENTS.md)
