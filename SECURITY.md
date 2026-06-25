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
- **Funds can't leave through the agent.** The signer's intent vocabulary is
  `buy | sell` only — there is **no transfer/withdraw verb**. Value stays inside
  the agent wallet. The owner withdraws with their own key; the autonomous path
  can never send funds to an arbitrary address. Worst case for a malicious
  operator (or a leaked session token): an *in-policy swap*, never a drain.
- **Policy is enforced on every trade** — max SOL per trade, max SOL per day
  (a live sell is priced on the SOL it returns, so it can't slip the caps),
  cooldown, and token allow/deny lists.

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
