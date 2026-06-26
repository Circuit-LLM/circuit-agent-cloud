# Security

circuit-agent-cloud runs other people's trading agents on operator-contributed
CPU. The whole design question is: **how does an agent trade without the machine
that runs it being able to steal its funds?** The answer is the **signer**.

## Custody — the one mechanism

The signing key is generated and held by the **signer** (`signer/server.js`),
never by the node that runs the agent.

- **Keys at rest.** Each agent gets a real Solana (Ed25519) wallet; the 32-byte
  seed is sealed with **AES-256-GCM** under a master key (`keys.json`). The
  control plane and node-hosts never receive key material — only the wallet
  address and a scoped session token.
- **The operator gets a token, not a key.** A node-host receives a short-lived,
  rotating **session token** scoped to one agent + epoch. It authorizes
  *requesting* in-policy trades; it cannot move funds.
- **The autonomous path can't move funds out.** The agent/host trade vocabulary is
  `buy | sell` only — no transfer/withdraw. So the worst a hostile host or a leaked
  session token can do is an *in-policy swap*; it can never send funds to an arbitrary
  address.
- **The owner gets funds back (owner-gated, not the autonomous path).** Two routes,
  neither reachable by the host or a session token:
  - **`withdraw`** sends the wallet's SOL to the agent's **committed owner address only**
    (set at create / via the owner route) — never an arbitrary destination, so it's not a
    drain vector. The owner skims or fully recovers without exposing the key.
  - **`export`** hands the owner the wallet's private key to take full self-custody. After
    export the off-box guarantee no longer holds for that wallet (the key now exists
    elsewhere) — a deliberate owner choice.
  - **`destroy` fails closed on a non-empty wallet** (the key-wipe is irreversible), telling
    you to withdraw/export first; `force` overrides to abandon remaining funds.
- **Custodial reality (v1, be honest about it).** Today `withdraw`/`export`/`destroy` are
  gated by the **operator bearer key**, and the operator holds the master key + sealed
  seeds — so the signer is a **custodian of the agent trading wallets**. The host can't
  steal, but a compromised signer host or a malicious operator could. A **multi-tenant**
  deployment must add **per-owner authentication** in front of these owner actions (and
  ideally move to the non-custodial path below) before holding other people's funds.
- **Policy is enforced on every trade** — max SOL per trade, max SOL per day
  (a live sell is priced on the SOL it returns, so it can't slip the caps),
  cooldown, and token allow/deny lists.

Custody guarantees **no drain**. On its own it bounds a hostile host to an *in-policy*
`buy`/`sell` — but since the agent runs on the host's CPU, *which* in-policy trade fires is
the host's to pick until you close it. **Verified Intents** closes it in software (any CPU);
**Sealed Agents** closes it in hardware (any strategy). Both below — for a trading agent,
Verified Intents is the one to reach for.

## Verified Intents — closing trade forgery in software (any CPU)

*Validate, don't isolate.* The owner commits a **decision rule** (`rule(inputs) → buy/sell`)
and the producer keys it trusts. With `requireVerifiedIntent` set, the signer signs a trade
only if — beyond the fence + policy — the trade is the genuine output of that rule on
**authenticated inputs**:

```
fence (epoch + token)            ── who is asking
for each evidence:  verify signature/proof + freshness + unused nonce
bind intent.inputs == the values the evidence proves
re-run rule(inputs)  →  must equal the submitted intent      ── the decision gate
policy caps (notional/daily/cooldown/allow)
sign  ── only now
```

Evidence is **first-party signed data** (`circuit-data-api ?signed=1`), a **signed inference
receipt** (the DLLM gateway, turning an AI verdict into a checkable input), or a **zkTLS proof**
(third-party data). A host that forges a trade, fakes the data, or replays a stale-but-real
quote is rejected before signing — `decision-unjustified` / `evidence-invalid` /
`evidence-stale` / `input-mismatch`. Implemented in `lib/verified-intent.js` (a byte-identical
port of `@circuit/attest`), enforced in `signer/server.js`. Full spec + threat model:
[docs/VERIFIED_INTENTS.md](docs/VERIFIED_INTENTS.md).

- **Prevents** (regular CPU): trade forgery and fake-data justification for **checkable**
  strategies — deterministic rules (T1) and rules over a signed-AI verdict (T2).
- **Residual:** a host can still *withhold* a valid trade or pick *when* among genuinely-justified
  moments; **opaque** strategies (T3) the signer can't re-run aren't covered — use the hardware road.

## Sealed Agents — the hardware road (any strategy)

For strategies the signer can't re-check, run the agent inside a **TEE** (SEV-SNP / TDX / SGX /
Nitro / H100 CC); the signer trusts trades only from an attested enclave, so the host can't
observe or alter the agent at all. Needs special hardware. Design:
[docs/SEALED_AGENTS.md](docs/SEALED_AGENTS.md).

**Summary:** no drain (always) · no forgery for checkable strategies (Verified Intents, any CPU) ·
no influence at all for any strategy (Sealed Agents, TEE hardware).

## The master key

`CIRCUIT_SIGNER_MASTER_KEY` (32 bytes, hex or base64) unlocks every agent wallet
the signer holds. If unset, the signer generates one to `<dir>/master.key` (mode
`0600`) on first run.

- **Back it up.** Losing it loses access to every custodied wallet.
- **Keep it off the operator fleet.** It belongs only on the trusted signer host.
- v1 is **one trusted signer** (Circuit's, or self-hosted). The same API can later
  sit behind an **MPC or TEE signer** so no single party holds the key — with no
  change to agents or hosts.

## Live trading — what's enforced before signing, and the residual

When `paper=false`, the signer builds the swap **itself** from the approved intent
(taker = the agent's own wallet) and validates the broker's response **before
signing** (`signer/submit.js`):

- **https-only** endpoint (plaintext rejected for non-loopback hosts);
- `requestId` binds the executed transaction to the order we requested;
- the order's **input/output mints and amount match** what we asked for;
- the agent is a **required signer** of the transaction (it need not be the fee
  payer — Jupiter Ultra's RFQ routers, e.g. DFlow, sponsor the agent's gas with a
  relayer fee payer);
- every top-level program **resolvable from the static account keys** is on a
  swap-router allowlist (System, ComputeBudget, SPL Token, Token-2022, Associated
  Token, Jupiter v6, DFlow). An unknown router is **fail-closed** — the signer
  refuses to sign until it's verified and added (`CIRCUIT_SIGNER_EXTRA_PROGRAMS`).
- the swap's **SOL value is capped** per-trade and per-day; the daily budget is
  charged by the actual executed value, not the requested `sizeSol`.

**Residual (known, documented):** programs/accounts loaded via v0 **address-lookup
tables** are not resolved (that needs an RPC `getAddressLookupTable` round-trip),
so a *malicious* Jupiter endpoint could in principle hide an instruction there.
Today this is mitigated by trusting Jupiter over authenticated https. **Full ALT
resolution is the last hardening before running a live agent unsupervised at
size.** Paper agents never broadcast.

## At-most-one (the fence)

Each agent has one wallet, so at most one instance may trade it. A session carries
a monotonic **epoch**; opening a new one (on reschedule/failover) supersedes the
old, so a crashed node's orphaned copy is fenced out — its intents are rejected as
stale. Users run unlimited *different* agents; each runs in exactly one place.

## Dependencies

Zero npm dependencies — pure Node ≥ 18 (native `crypto` for Ed25519 + AES-GCM,
native `fetch`). Nothing to `npm audit`; no supply chain beyond Node itself.

## Reporting

Email **circuitllm@protonmail.com** with steps to reproduce. Please do not open a
public issue for an unfixed vulnerability.
