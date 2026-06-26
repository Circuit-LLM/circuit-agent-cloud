<div align="center">

# circuit-agent-cloud

**Decentralized CPU hosting for Circuit agents. Users launch agents that run 24/7 on the mesh; operators contribute spare CPU on their own terms and earn CIRC. Inference runs on the GPUs — agents run on the CPUs that hang off the same node-clients.**

[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![Status](https://img.shields.io/badge/status-alpha-orange)](https://github.com/Circuit-LLM/circuit-agent-cloud)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

[Website](https://circuitllm.xyz) · [Spec](https://github.com/Circuit-LLM/circuit-cli/blob/main/docs/agent-cloud-spec.md)

</div>

---

Four zero-dependency Node services that together form the agent cloud:

| Component | What it is |
| --------- | ---------- |
| **control-plane** | Scheduler + registry + log relay + placement authority. Nodes poll it; the CLI drives agents through it. The only inbound service. |
| **signer** | Custody. Holds each agent's wallet key **off-box** and signs policy-checked trade intents. The operator's machine never sees the key. Also issues the session lease that enforces **at-most-one** running instance per agent. |
| **node-host** | The operator's worker. Declares a resource budget, runs assigned agents (sandboxed, bounded), forwards health + logs. Polls out only — no inbound port. Receives only a scoped session token, never a key. Writes a local `status.json` snapshot so a co-located dashboard (the [circuit-node-client](https://github.com/Circuit-LLM/circuit-node-client) **Cloud** tab) can show what it's hosting. |
| **agentd** | A reference agent workload (self-contained paper trader). Production runs `circuit-agent` the same way — it's just another workload command. |

Driven from the terminal by **[circuit-cli](https://github.com/Circuit-LLM/circuit-cli)** (`circuit agent …`). Full design in the **[spec](https://github.com/Circuit-LLM/circuit-cli/blob/main/docs/agent-cloud-spec.md)**.

## How it works

```
┌── user ──┐  HTTPS   ┌──── control-plane ────┐  poll   ┌── operator ──┐
│ circuit  │ ───────► │ schedule · registry   │ ◄────── │  node-host   │
│  agent   │          │ · log relay · failover │         │ runs agentd/ │
└──────────┘          └───────────┬────────────┘         │ circuit-agent│
                       provision  │ session                └──────┬───────┘
                       wallet +   │ (epoch+token)        intent +  │ token
                       policy     ▼                      (no key)  ▼
                            ┌──────────────┐  sign  ◄───────────────┘
                            │    signer    │  ──────► signature
                            │ key off-box  │
                            └──────────────┘
```

A node registers with a **budget**; the control plane bin-packs agents onto nodes that fit; nodes heartbeat and get `start`/`stop` assignments. Each agent's signing key is generated and held by the **signer**, never on the operator node — so the agent runs its *brain* on borrowed CPU but can only *trade* by asking custody to sign, within the owner's policy. Positions live on-chain, so a crashed node's agents **reschedule and resume** elsewhere with nothing lost.

## Custody — one mechanism

There are no custody tiers. Every agent uses the **off-box signer**:

- **The key never touches the host.** The signer generates a real Solana (Ed25519) wallet per agent and seals it at rest (AES-256-GCM). The operator that runs the agent only ever receives a **session token** — good for *requesting* in-policy trades, useless for theft.
- **Funds can't leave through the agent.** The signer's vocabulary is `buy | sell` only — there is no transfer/withdraw verb, so value stays inside the agent wallet. The owner withdraws with their own key; the autonomous path can never move funds out. Worst case for a rogue operator: an in-policy swap, never a drain.
- **Policy is enforced on every trade** — max SOL per trade, max SOL per day (a live sell is priced on the SOL it returns, so it can't slip the caps), cooldown, and token allow/deny lists. On a **live** agent the signer builds the swap *itself* from the approved intent (taker = the agent's own wallet) and, **before signing, validates the broker's response**: the endpoint is https, the order matches the mints/amount it asked for, the agent is a required signer, and every program the transaction invokes that's resolvable from the static keys is on a swap-router allowlist (an unknown router is fail-closed until verified — Jupiter v6 and DFlow are allowlisted). Then it signs with the off-box key and lands it via **Jupiter Ultra**. Residual: programs loaded via v0 address-lookup tables aren't resolved without an RPC call — full ALT validation is the last hardening before unsupervised size. Paper agents stop at the signed attestation and never broadcast.
- **At-most-one (the fence).** Each agent has one wallet, so at most one instance may trade it. A session carries a monotonic **epoch**; opening a new one (on reschedule/failover) supersedes the old, so a crashed node's orphaned copy is fenced out — its intents are rejected as stale. Deploy as many *different* agents as you like; each runs in exactly one place.

Custody gives you **no drain**. The agent runs on the host's CPU, but it still **can't trade on its own terms** — Circuit closes that two ways, and you pick the one that fits your strategy:

- **Verified Intents (software, any CPU).** Commit a decision rule; the signer re-runs it on **authenticated inputs** (signed data / inference receipts / zkTLS) and signs **only** the trade that rule produces — so a host can't forge a trade or fake the data behind it. Covers any rule the signer can re-check, which is most agents (deterministic, or rule-over-signed-AI). Opt in with `requireVerifiedIntent`; enforced in `lib/verified-intent.js` + `signer/server.js`; spec: **[docs/VERIFIED_INTENTS.md](docs/VERIFIED_INTENTS.md)**.
- **Sealed Agents (hardware, any strategy).** Run the agent in a TEE; the signer trusts only an attested enclave. For a genuine black box the signer can't re-run. Design: **[docs/SEALED_AGENTS.md](docs/SEALED_AGENTS.md)**.

Net: funds can't be stolen, and trades can't be forged. The honest residuals are narrow — a host can *withhold* or *time* a genuinely-valid trade, never invent one — and are documented in **[SECURITY.md](SECURITY.md)**.

v1 is one trusted signer (Circuit's, or self-hosted). The same API can later sit behind an MPC or TEE signer with no change to agents or hosts. The full trust model — master key, live-trade validation, Verified Intents, and the documented residuals — is in **[SECURITY.md](SECURITY.md)**.

## Run it

No dependencies — pure Node ≥ 18.

**Signer** (custody — one per network, kept on trusted infra):

```bash
PORT=18981 node signer/server.js
# env: CIRCUIT_SIGNER_DIR, CIRCUIT_SIGNER_MASTER_KEY (32 bytes hex/base64 — back it up),
#      CIRCUIT_SIGNER_KEY (bearer for the control plane),
#      JUPITER_ULTRA_API (paid Ultra key; omit to use the keyless lite-api host)
```

Live trades land through **Jupiter Ultra** (it broadcasts, so the signer needs no RPC). An agent trades live only when created with `--live` *and* its wallet is funded; otherwise it's paper.

**Control plane** (one per network — point it at the signer):

```bash
PORT=18980 CIRCUIT_SIGNER_URL=http://127.0.0.1:18981 \
CIRCUIT_SIGNER_PUBLIC_URL=https://signer.circuitllm.xyz \
node control-plane/server.js
# env: HOST, NODE_TIMEOUT_MS, CIRCUIT_CLOUD_KEY (shared bearer), CIRCUIT_CLOUD_STATE
```

`CIRCUIT_SIGNER_URL` is where the control plane reaches custody; `CIRCUIT_SIGNER_PUBLIC_URL` is the URL handed to workloads (defaults to the same). If unset, custody is disabled and agents run paper-only — fine for a dev/demo, never for live funds.

**Node host** (each operator — opt-in, bounded, revocable):

```bash
CONTROL_PLANE=https://agents.circuitllm.xyz \
NODE_ID=my-node MAX_AGENTS=20 MAX_MEMORY_MB=512 \
node node-host/host.js
```

Or, from the CLI: `circuit agent host --max-agents 20` (and `--off` to drain & stop).

### Operator budget

The opt-in controls — set via env or `circuit agent host` — are **off by default** and enforced with hard caps:

| Knob | Meaning |
| ---- | ------- |
| `MAX_AGENTS` | hard ceiling on hosted agents |
| `MAX_MEMORY_MB` | per-agent memory cap (best-effort kill on Linux; cgroups in prod) |
| `CONTROL_PLANE` | which network to join |

Lowering the budget or stopping the host **drains** its agents — they reschedule elsewhere. The operator never holds an agent's key regardless of budget — custody is always off-box.

## Test

```bash
npm test     # node test/e2e-signer.mjs
```

End-to-end (22 checks): provisions an off-box wallet, verifies a real Ed25519 signature against the agent's address, exercises every policy gate and the fence, stands up the full stack (control plane + 2 node-hosts + signer), proves the key is at the signer and **not** on the control plane, kills the owning node to confirm the agent **reschedules and the session rotates** (the old node fenced out), and drives the **live submit path** (routes on-chain, fails safe, no phantom accounting — without broadcasting). The byte-level transaction signing has its own offline check: `node test/submit-check.mjs`.

## Status & roadmap

Alpha, end-to-end tested **and proven on mainnet**. Working: control plane, **off-box signer custody**, **live on-chain submit** (Jupiter Ultra, signed with the off-box key) — validated with a real funded round-trip (a buy via Jupiter v6 and a sell via DFlow's sponsored-payer route, both built → validated → off-box-signed → landed) — node-host, reference workload, scheduling, health/log relay, **crash failover**, and the **at-most-one fence**. During that dry-run the pre-sign validation did its job: it fail-closed on an unrecognized router until it was verified and allowlisted. Per the [spec](https://github.com/Circuit-LLM/circuit-cli/blob/main/docs/agent-cloud-spec.md), next up: full ALT (address-lookup-table) program resolution before unsupervised size, cgroup/container sandboxing, an MPC/TEE signer behind the same API, and a Postgres store for HA.

## License

MIT © Circuit LLM
