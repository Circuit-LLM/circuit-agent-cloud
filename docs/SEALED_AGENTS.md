# Sealed Agents — execution integrity for agents on untrusted hosts

**Status:** SPEC / design exploration (not built). The design we'd build toward to close the one gap the
current custody model leaves open. Companion to [SECURITY.md](../SECURITY.md) (today's custody model) and
the agent-cloud spec.

**The premise we cannot change:** Circuit runs agents on **other people's computers**. The operator has
full control of the box. So this is the *trusted execution on adversarial hardware* problem, and we have
to solve it *with that constraint*, not by removing it.

**The question that started this:** today a malicious host can't *steal* funds (the key is off-box and
the only verbs are `buy`/`sell`), but it *can* read the agent's session token from its environment and
submit `buy`/`sell` intents of **its own choosing** within the owner's policy. We want to take that away
— make trades come only from the genuine, unmodified agent, even on hardware we don't trust.

---

## 1. The problem, precisely

### What's already enforced (today, "L0")

The off-box signer holds each agent's key sealed at rest; the host gets only a scoped **session token**
+ a monotonic **epoch** (the fence). The signer's vocabulary is `buy | sell` — **no transfer/withdraw** —
so value can never leave the wallet. Worst case: an in-policy swap, never a drain. Policy caps
(`maxNotionalSol`, `maxDailySol`, `cooldownMs`, allow/deny lists) bound it; paper mode (default) means no
real trades at all.

### The gap

The session token lives in the agent's environment on a box the adversary controls. The signer
authenticates an intent by `{epoch, token}` alone — nothing the host lacks. So a malicious host can:

- **substitute trade decisions** — submit its own `buy`/`sell` intents (within policy) instead of, or in
  addition to, the agent's genuine strategy;
- **read the agent's secrets** — the session token, any strategy/API keys, an inference-payment wallet;
- **tamper with the strategy** — modify the agent's code/inputs so it "decides" what the host wants.

All bounded by policy, so the exposure is *griefing within your caps* (slippage / churn / bad-timing
losses), not theft. But it's real, and "set tight caps + fund small" is mitigation, not a fix.

### The hard truth

**Software alone, on hardware the adversary owns, cannot prevent the adversary from impersonating the
software.** Any secret the agent holds, the host can extract; any computation it does, the host can
tamper with. A real fix therefore needs one of: a **hardware root of trust** the host can't forge
(confidential computing), a **mathematical proof** of correct execution (ZK), or to **move the trusted
decision off the host** entirely. The rest of this doc surveys those and picks one.

---

## 2. The solution space

### 2.1 Confidential computing + remote attestation — *the deployable answer*

Run the agent inside a **Trusted Execution Environment** (TEE): a hardware-isolated enclave or
confidential VM whose memory the host OS/hypervisor cannot read or modify. The hardware can produce a
**remote attestation** — a signed quote, rooted in a CPU/GPU vendor key burned in at manufacture, that
proves *"this is a genuine TEE running exactly this measured code"*. Any change to the bootloader, OS
image, or container alters the measurement and the attestation fails.

The mechanism we need falls right out of it:

1. The agent's **intent-signing key is generated *inside* the enclave** and never leaves it (the host
   can't extract it).
2. On launch the enclave **attests** — proving genuine-TEE + the exact agent image — and publishes its
   fresh public key.
3. The signer issues a session **only** to an enclave whose attestation is valid *and* whose measured
   code equals the owner's committed image, and binds the session to the enclave's key.
4. Every intent must be **signed by the in-enclave key**. The host can't forge it, can't read the
   strategy, can't tamper with it.

Hardware landscape (commodity-reachable today):

| Tech | Shape | Where |
|---|---|---|
| **AMD SEV-SNP**, **Intel TDX** | confidential **VM** — run a normal container, full-VM isolation, attest | Azure (DCasv5 / DCa), GCP (N2D / C3), select AWS EC2 |
| **AWS Nitro Enclaves** | enclave carved from an EC2 instance; AWS-rooted attestation | most modern EC2 families |
| **Intel SGX** | process **enclave** (smallest TCB, most porting) | niche / server |
| **NVIDIA H100/H200 confidential computing** | **GPU** TEE (encrypted VRAM, attested) — for confidential *inference* | pairs with a CPU CVM |

This is not theoretical — it's shipping for exactly our use case:

- **Oasis ROFL** (Runtime Off-chain Logic, mainnet 2025): *"define an agent that pulls price data from a
  Web2 API, runs it through an AI model, and decides whether to buy or sell, running off-chain inside a
  TEE and producing an attestation of its computation."* That is our agent, verbatim. Attestations are
  registered on-chain as the app's verified code fingerprint.
- **Phala `dstack`** (open-source, Intel TDX + NVIDIA GPU, audited by zkSecurity 2025): a TEE runtime that
  runs a normal `docker-compose` in a confidential VM and exposes **KMS + a signing RPC + attestation** to
  the workload over a socket — i.e. exactly the "in-enclave key + attest" primitive, as a library we
  could build on rather than from scratch. Runs on AWS / GCP / Phala Cloud.

**Cost:** a hardware bar (modern CPU / confidential-VM instance) and some runtime overhead. **Residual:**
the host can still refuse to run or kill the enclave (liveness/DoS) — but can't forge, read, or tamper.

### 2.2 Verifiable computation — zkVM / ZKML (*trustless math; not ready for whole agents*)

Instead of trusting hardware, prove the math: the agent emits a **zero-knowledge proof** that its intent
is the correct output of the agreed strategy on the agreed inputs; the signer verifies the proof before
signing. No trusted hardware, fully trustless — but expensive. zkVMs (RISC Zero R0VM 2.0, Succinct SP1)
hit near-real-time for *constrained* programs in 2025 (~44 s / ~10× cheaper on GPU), but **ZKML for LLM
inference is research-stage, shipping through 2026.** So ZK is viable today for a **thin, deterministic
decision gate** (a small fixed function over signed inputs), not for proving a whole AI strategy. Keep it
as a future option / a verifiable final-gate, not the primary mechanism.

### 2.3 Authenticated inputs — zkTLS (*closes a sub-hole*)

Even a perfect enclave acts on data the host's network can feed it. **TLSNotary / DECO (zkTLS)** let the
agent prove *"this price came from exchange X over a real TLS session"* — without the server's
cooperation or trusted hardware — and prove statements about it in zero-knowledge. Requiring intents to
carry such a proof stops a host from feeding fake data to trigger an in-policy-but-malicious trade.
Complementary to a TEE (or a standalone hardening step).

### 2.4 Decentralized conditional signing — MPC (*removes the trusted signer*)

Today there's one trusted signer. **Lit Protocol** shows the trustless version: a **PKP** (programmable
key pair) is generated by **threshold MPC / DKG** across a node network (no single node holds the key),
and it signs **only if the conditions in a "Lit Action" pass** — and *those conditions are a program
stored on IPFS*. We can adopt the same shape: the signer becomes an **MPC network** that co-signs an
intent only when an attestation (2.1) and/or proof (2.2/2.3) checks out. This removes the single trusted
verifier; it does **not** by itself solve host-forgery (it still needs 2.1/2.2 to know the intent is
genuine).

### 2.5 Where IPFS fits — the honest answer

IPFS is **content-addressing**: a file is named by the hash (CID) of its bytes, so it's immutable and
tamper-evident *at rest*. That gives us two real, valuable things — but **not** execution integrity:

- ✅ **The agent image is addressed by its CID.** Everyone agrees on "what is running," and the TEE
  *measurement* is the hash of that image — so you can pin the exact attested code on IPFS and let anyone
  independently fetch, reproduce, and verify what the attestation claims.
- ✅ **The authorization/policy logic can be IPFS-pinned** (exactly how Lit Actions work): the signer (or
  MPC network) enforces a content-addressed program, so the rules are public and immutable.
- ❌ **IPFS cannot make the host run that code honestly.** Content-addressing proves *what* the code is,
  never *that it executed faithfully*. That assurance comes from the TEE (2.1) or the proof (2.2).

> **So: IPFS is the *anchor* (what), TEE/ZK/MPC is the *integrity* (honest execution). Use IPFS for the
> image + policy identity; use a TEE for the integrity.** This is precisely the ROFL (attest a CID'd
> image) and Lit (IPFS-pinned signing logic) pattern.

---

## 3. Recommended design — Sealed Agents

Put the agent in a **sealed runtime**: a confidential VM (SEV-SNP / TDX, optionally via `dstack` or
ROFL), with the intent-signing key born and kept **inside** it, and the signer gated by **remote
attestation** of a **content-addressed agent image**. Build on an existing, audited TEE runtime rather
than rolling our own enclave plumbing.

```
   owner commits {imageCID, policy}            ┌──────────── control plane ────────────┐
        (optionally on-chain)  ───────────────►│ verifies attestation · placement:      │
                                               │ live agents → ATTESTED nodes only       │
   ┌──────── attested node (operator) ─────────┤                                         │
   │  ┌──── sealed runtime (TEE / CVM) ────┐   │                                         │
   │  │  agent image (== imageCID)         │   └───────────────┬─────────────────────────┘
   │  │  in-enclave key  (never leaves)    │                   │  attestation quote +
   │  │  tick(): sense · think · decide    │ ──── attest ─────►│  enclave pubkey
   │  └──────────────┬─────────────────────┘                   ▼
   │  host can DoS,   │  intent SIGNED by the              ┌──────── signer (custody) ────────┐
   │  NOT read/forge  │  in-enclave key                    │ issue session ⇔ valid quote AND   │
   └─────────────────┼───────────────────────────────────►│ measured code == imageCID;        │
                     │                                     │ then sign ONLY intents bearing    │
                     └──────────────  buy/sell  ──────────►│ the bound enclave key             │
                                                           └───────────────────────────────────┘
```

**Why it closes the gap:** the host can't extract the key (in-enclave), can't tamper with the strategy
(measurement changes → attestation fails → no session), and can't forge intents (no enclave key). The
session token stops being a bearer secret; the real auth is *the attested enclave key*.

**Tiered network (the migration lever):**

| Node | May host |
|---|---|
| **Attested** (TEE-capable, valid quote) | **live** custody agents |
| **Non-attested** | **paper** agents, read-only / non-custodial workloads |

Paper agents run anywhere (today's behavior); live custody requires a sealed runtime. Operators without
TEE hardware still participate and earn — they just can't be trusted with live trades.

---

## 4. How the environment changes

This is a network change, not just an SDK change.

- **Operators (node-host).** To host *live* agents, run TEE-capable hardware — a modern AMD SEV-SNP /
  Intel TDX machine, a confidential-VM cloud instance, or join via a `dstack`/Phala-style runtime.
  Registration gains an **attestation report**; the control plane records the node's TEE capability +
  TCB version. Non-TEE operators keep hosting paper/other workloads. The opt-in budget model is
  unchanged; "attested" is a new capability flag.
- **Control plane.** Verifies attestation evidence at registration and on session open; **placement gains
  a constraint** (live custody agent → attested node only); tracks the measured `imageCID` per running
  agent. Failover/reschedule must move a live agent only to another attested node.
- **Signer (custody).** Evolves from *session-token auth* to *attestation-gated, enclave-key-bound*:
  1. accept a session request only with a **valid genuine-TEE quote** from a trusted manufacturer/root
     (AMD/Intel/NVIDIA/AWS Nitro), with an acceptable TCB version;
  2. require the quote's **measurement == the owner's committed `imageCID`**;
  3. **bind** the session to the enclave's ephemeral public key, and from then on **sign only intents
     carrying that key's signature** (the epoch fence still supersedes old sessions on reschedule).
  The policy engine and `buy|sell`-only vocabulary are unchanged — this is defense in depth on top.
  (Optionally, later: make the signer an **MPC network**, Lit-style, to drop the single trusted verifier.)
- **Agent packaging.** Agents become **reproducible, content-addressed images** (deterministic build →
  `imageCID`). The owner commits `{imageCID, policy}` (optionally on-chain, à la ROFL) so anyone can
  verify what's authorized. This is also a real supply-chain win (you know *exactly* what's running).
- **SDK (`@circuit/agent`).** Gains a **sealed-runtime mode**: the custody client signs intents with the
  in-enclave key (via the runtime's KMS/Sign-RPC, e.g. the `dstack` socket) instead of a plaintext token,
  and exposes the attestation to the control plane. **Crucially, how you *write* an agent does not change
  — still `extends CircuitAgent` + `tick()`.** Sealing is a deployment/runtime concern, not an API one.
- **Inputs (optional hardening).** Require zkTLS/oracle-signed market data for live agents so the host
  can't feed fake inputs into an honest enclave.

---

## 5. Migration — shippable layers

| Layer | What ships | Protection | New hardware? |
|---|---|---|---|
| **L0** (today) | off-box key · `buy/sell`-only · policy · paper-default | **no drain**; live trades host-influenceable, bounded by caps | no |
| **L1** | authenticated inputs (zkTLS) + a declared thin decision-gate the signer checks | host can't trigger trades with fake data; constrained strategies host-resistant | no |
| **L2** | **Sealed Agents** — TEE-attested runtime, in-enclave key, attestation-gated sessions, CID'd images; tiered live/paper | **host can't forge, read, or tamper** — trades are genuinely the agent's | **yes** (operators who want to host live) |
| **L3** | MPC/threshold signer (Lit-style), accepted-measurement registry on-chain | removes the single trusted signer; fully decentralized custody | no (network) |

Each layer is independently useful; L2 is the one that actually answers the original question.

---

## 6. Residual risks (the honest list)

- **Liveness / DoS.** A host can refuse to run, kill, throttle, or network-isolate the enclave. It earns
  nothing and the agent reschedules (the fence prevents a double); **integrity is preserved**. This is the
  irreducible residual of "someone else's computer" — and it's the acceptable one.
- **TEE side-channels & vulnerabilities.** SGX/SEV-SNP/TDX have had real attacks. Mitigate: pin minimum
  TCB/microcode in the attestation policy, support multiple vendors, keep the policy caps as
  belt-and-suspenders, track CVEs.
- **Attestation root-of-trust.** You trust the CPU/GPU vendor's key + attestation service. Mitigate:
  multi-vendor acceptance, an on-chain registry of accepted roots/measurements, independent verification
  of the CID'd image.
- **Integrity ≠ profitability.** A TEE proves you ran *your* code honestly — not that your strategy is
  good. Caps and paper mode still matter.
- **Input authenticity (without L1).** A bare enclave still sees host-controlled network; it can't be fed
  a forged TLS session to a real exchange, but data can be withheld/delayed. zkTLS or trusted oracles
  close this.
- **Operator bar / cost.** Confidential VMs need capable hardware and add overhead — which shrinks the
  *live* operator pool. The tiered model (paper anywhere) keeps the network open.

---

## 7. Decisions to make

1. **Build on `dstack`/ROFL, or roll our own enclave runtime?** Strong lean: build on an audited,
   open-source TEE runtime (`dstack`) — confidential plumbing is exactly what you don't want to write
   from scratch.
2. **Which TEEs to accept first?** AMD SEV-SNP + Intel TDX (confidential VMs, least agent-porting) is the
   pragmatic start; add NVIDIA GPU CC if/when agents need confidential inference.
3. **Where does the committed `{imageCID, policy}` live?** Off-chain signed vs on-chain (ROFL-style
   registry). On-chain composes with the existing Solana footprint and a future L3.
4. **L1 first or straight to L2?** L1 (zkTLS inputs) needs no new hardware and removes the fake-data
   vector cheaply; L2 is the real fix but raises the operator bar. Likely both, L1 → L2.
5. **MPC signer (L3) now or later?** Later — it removes trust in our signer but doesn't add integrity that
   L2 doesn't already provide.

---

## 8. References

- Oasis ROFL — verifiable off-chain compute / trustless agents in TEEs:
  <https://oasis.net/blog/trustless-agents>, <https://docs.oasis.io/adrs/0024-off-chain-runtime-logic/>
- Phala `dstack` — open-source TEE runtime (TDX + NVIDIA GPU), sealed agents:
  <https://phala.com/dstack>, <https://github.com/Phala-Network/phala-cloud>
- NVIDIA H100 confidential computing — GPU TEE + attestation:
  <https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/>
- AMD SEV-SNP / Intel TDX confidential VMs (empirical analysis):
  <https://dl.acm.org/doi/10.1145/3700418>
- AWS Nitro Enclaves — confidential compute on commodity EC2:
  <https://www.redhat.com/en/blog/deploy-confidential-computing-aws-nitro-enclaves-red-hat-enterprise-linux>
- Lit Protocol — threshold-MPC PKPs + IPFS-pinned signing conditions (Lit Actions):
  <https://developer.litprotocol.com/concepts/programmable-signing-concept>
- RISC Zero / Succinct SP1 — zkVMs; ZKML status:
  <https://blog.icme.io/the-definitive-guide-to-zkml-2025/>
- TLSNotary / DECO — zkTLS, authenticated web data without trusted hardware:
  <https://tlsnotary.org/docs/intro/>, <https://arxiv.org/pdf/1909.00938>
