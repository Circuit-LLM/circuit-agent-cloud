# Agent Bundles — hosting arbitrary user agents on the mesh

**Status:** B0 + B1 + B2 **BUILT & TESTED** (localnet); B3 (microVM isolation) **scaffolded** —
rank + detect + scheduler gating + container spec land (the live Kata run is gated on a node that
actually has KVM + Kata); B4 (confidential microVM / TEE) is future. Companion to
[SECURITY.md](../SECURITY.md), [VERIFIED_INTENTS.md](./VERIFIED_INTENTS.md), and
[SEALED_AGENTS.md](./SEALED_AGENTS.md).

> **What's live:** `lib/bundle.js` (content-addressed signed bundles), `lib/bundle-store.js` (CAS +
> SSRF-hardened pull), `lib/netguard.js` (private-IP/SSRF guard), `node-host/{env,egress-proxy,oci}.js`
> + the bundle/oci branches in `host.js`, `control-plane` owner-binding + sandbox-gated placement
> (`lib/proto.js nodeSatisfies`), and `circuit agent create --bundle` in the CLI. Tests:
> `test/{node-host-env,ssrf,bundle,bundle-binding,egress-proxy,sandbox-gating}.test.mjs`. The one thing
> not exercised on this box: a *live* container run (no usable runtime here) — `detectOciRuntime()`
> returns null and the node fails safe (won't advertise `oci`, won't be handed an untrusted bundle).
>
> **Hardened per the 2026-06-27 security review** (see [SECURITY_REVIEW_2026-06-27.md](./SECURITY_REVIEW_2026-06-27.md)):
> signed `egress`/`resources`, safe-entry, agentId binding, IP-pinned egress (no DNS-rebind), port-pin,
> resource caps, keyed-RPC withheld from bundles. **Operator MUST, before enabling untrusted `oci`:**
> (1) set `CIRCUIT_EGRESS_NETWORK` to a `--internal` bridge whose only reachable host is the proxy (+ a
> `DOCKER-USER` drop rule) — the node refuses oci otherwise; (2) pin the base image by digest +
> `CIRCUIT_SECCOMP_PROFILE`; (3) turn on the **multi-tenant auth** built 2026-06-27 — `CIRCUIT_REQUIRE_OWNER_AUTH=1`
> (per-owner wallet auth, no IDOR), `CIRCUIT_REQUIRE_NODE_AUTH=1` (node-identity), mark trusted nodes via
> `PUT /v1/nodes/:id/trust` (oci only lands on attested nodes), pin `CIRCUIT_FIRST_PARTY_KEYS` (node-runtime
> = first-party only), and front the CP↔node channel with **TLS** (the one remaining deployment item).

**Premise.** Today the node-host runs only **known, pre-installed workloads** — `agentd` (the reference
paper trader) and `circuit-agent` (Circuit's own bot). `resolveWorkload()` resolves a fixed set and the
spawned process **inherits the operator's full environment**. To let a developer write their *own*
`@circuit/agent` and have **Circuit's mesh host it on a stranger's CPU**, three things are needed — and
note which one is already done:

- **DONE — custody.** Off-box signing already makes hosting untrusted agent *logic* safe for funds: a
  malicious agent can't drain (no transfer verb), can't forge trades (Verified Intents), and can't run
  twice (the epoch fence). The money side is solved and is **not** what this spec is about.
- **MISSING #1 — distribution.** Package a user's agent and ship it to whatever node the scheduler
  picks, verifiably and immutably.
- **MISSING #2 — host-protection sandbox.** Run that untrusted code **without endangering the operator's
  machine**. This is the inverse of custody: custody protects the *agent's funds from the host*; the
  sandbox protects the *host from the agent*.

There is also a **live bug** in the current code that is a prerequisite for any of this and worth fixing
on its own: the workload inherits `...process.env`, leaking the operator's keys/tokens to every hosted
agent (see §1, §10-B0).

---

## 0. Current state (what exists today)

Grounding the spec in the actual code so the deltas are precise:

| Piece | Today | File |
|---|---|---|
| Workload resolution | fixed set: `agentd` \| `circuit-agent` | `node-host/host.js` `resolveWorkload()` |
| Env passed to workload | **`{ ...process.env, … }` — full operator env (leak)** | `node-host/host.js` `startAgent()` |
| Isolation | `cwd: dataDir` only — no ns/cgroup/seccomp | `node-host/host.js` `spawn()` |
| Resource limit | best-effort RSS poll + SIGKILL | `node-host/host.js` `enforceMemory()` |
| Start assignment | carries `signer` block; **no `bundle` block** | `control-plane/server.js` |
| Node capabilities | advertises `caps: { cpu }` only — **no `sandbox`** | `node-host/host.js` `register()` |
| CLI | no `publish`, no `--bundle` | `circuit-cli` |

Nothing in the repo (node-host, control-plane, CLI, node-client) implements bundling, sandboxing, OCI, or
a bundle store. This spec is greenfield on top of the table above.

---

## 1. Shape

```
 dev:   circuit agent publish my-bot
          └─ build → content-addressed BUNDLE (sha256) → sign manifest → upload to bundle store → ref

 bind:  circuit agent create my-bot --bundle <ref>
          └─ control-plane verifies publisherPubkey == agent.owner, then stores
             spec.bundle = { ref, sha256, runtime, manifestSig }

 node:  start assignment carries { bundle:{url, sha256, runtime, manifestSig}, signer:{…} }
          └─ pull (cache by sha256) → VERIFY hash + manifest sig → run SANDBOXED
             with a CURATED env → forward health/logs
          └─ teardown on stop/drain; reschedule pulls the SAME sha256 elsewhere
```

Two invariants thread through everything:

1. **Content is identity.** A bundle is its `sha256`. A node runs exactly the bytes that were published;
   a reschedule pulls the same bytes; a mismatch never executes.
2. **The node, not the manifest, is the authority on limits.** The manifest *requests* resources and
   egress; the node's cgroup budget and egress proxy *grant* them, capped at what the operator offered.

---

## 2. The bundle (artifact)

A **content-addressed** artifact identified by its `sha256`. Two forms, declared by `runtime`:

| `runtime` | Artifact | Isolation | For |
|---|---|---|---|
| `node` | tarball: built single-file agent + manifest | curated-env subprocess + cgroup + RO mount | **trusted / first-party / own-fleet** nodes |
| `oci`  | OCI image (agent on a minimal base) | rootless container: RO rootfs, seccomp, dropped caps, **forced through the egress proxy** | **untrusted** community nodes (the default for strangers) |

A `node` bundle is lighter (no image build, no registry) but is only safe on nodes its owner or Circuit
trusts. **Untrusted bundles must be `oci`** and are only placed on nodes advertising `caps.sandbox: "oci"`.
Either form is **immutable** — the `sha256` is the identity.

**Manifest** (inside the bundle, signed by the publisher):
```jsonc
{
  "agentId": "…",                  // the control-plane agent this bundle may bind to
  "runtime": "node" | "oci",
  "entry":   "agent.js",           // node-runtime only
  "sdk":     "@circuit/agent@x",   // compatibility check at the node
  "egress":  ["signer","data","inference","rpc","jupiter"],  // requested network CLASSES (not hosts)
  "resources": { "maxMemoryMb": 512, "maxCpu": 0.5 },        // a REQUEST; node budget is the cap
  "publisherPubkey": "<ed25519>",
  "sig": "<ed25519 over canonical {sha256, agentId, runtime, entry, sdk, egress, resources}>"
}
```

`egress` lists **classes**, never hosts or keys — the node resolves classes to concrete upstreams (§5).
A class the operator hasn't enabled is simply denied; the agent gets no say in what those hosts are.

---

## 3. Publish (CLI)

`circuit agent publish <name>`:
1. Build the agent to a single-file `dist` (node) or build the OCI image (oci).
2. Compute the `sha256`; sign the manifest with the **owner key** (= the agent's owner).
3. Upload to the **bundle store** (§4); print the `ref` (`bundle://<sha256>` or an OCI digest).

`circuit agent create <name> --bundle <ref> [--runtime oci]` then binds it (§7).

---

## 4. Distribution — the bundle store

A content-addressed store the scheduler can hand a node a `{url, sha256}` for. Two backends:

- **`oci`** → an OCI registry (Circuit's or ghcr) addressed by **digest** — the digest *is* the integrity
  check; the node pulls with its container runtime.
- **`node`** → object storage / a Circuit "bundle CDN"; the node fetches the tarball and **verifies the
  `sha256` before unpacking** (reject on mismatch — no unverified bytes are unpacked, ever).

This is real infra, so the store must specify:
- **Push auth.** Only the bundle's owner key may push; uploads are signed. No anonymous pushes.
- **Immutability.** Content-addressed — re-pushing the same bytes is a no-op; a hash mismatch is rejected.
- **Quotas.** Per-owner storage cap to bound abuse.
- **GC.** Bundles are ref-counted by live `spec.bundle` references; unreferenced bundles past a TTL are
  collected. A bundle a running agent depends on is never collected.

The control-plane `start` assignment gains a `bundle` block beside the existing `signer` block:
```jsonc
{ "action":"start", "agent": { "id":"…", "spec":{…},
    "bundle": { "url":"…", "sha256":"…", "runtime":"oci", "manifestSig":"…" },
    "signer": { "url":"…", "agentId":"…", "epoch":N, "token":"…" } } }
```
Nodes **cache by `sha256`**, so a reschedule onto a node that already has the bytes is instant.

---

## 5. The sandbox (protecting the operator)

The contract: **the bundle can reach its data dir and an egress allowlist, and nothing else.**

### 5.1 Curated env — the live-bug fix, and the foundation of everything
Replace `{ ...process.env, … }` with an **explicit allowlist**. The workload receives:

- **Process minimum:** a controlled `PATH`, `HOME`/`TMPDIR` pointed *inside* the dataDir, `LANG`/`TZ`.
  (The node binary is launched by absolute path, so no inherited `PATH` is required.)
- **Circuit identity/session:** `CIRCUIT_SIGNER_URL`, `CIRCUIT_AGENT_ID`, `CIRCUIT_AGENT_EPOCH`,
  `CIRCUIT_AGENT_SESSION`, `CIRCUIT_AGENT_ADDRESS`, `CIRCUIT_AGENT_PAPER`, `CIRCUIT_AGENT_DATA_DIR`.
- **Service endpoints — URLs only, never keys:** `CIRCUIT_DATA_URL`, `CIRCUIT_INFERENCE_URL`,
  `CIRCUIT_RPC_URL`, `CIRCUIT_JUPITER_URL`. The agent pays per request via x402 with its **own** session/
  wallet, so it never needs — and never receives — the operator's API keys. For an `oci` (untrusted)
  bundle these point at the **egress proxy**, not at the real upstreams (§5.5).
- **Agent-declared env** from `spec.env`, **namespaced and validated** so it can't shadow any `CIRCUIT_*`
  var or inject a secret-shaped value.

**Never** the operator's environment. This single change makes even the *existing* first-party hosting
safer and is shippable today, independent of bundles (§10-B0).

### 5.2 Filesystem
Read-only rootfs; the **only** writable mount is the per-agent `dataDir`. No access to the operator's
home, the host's `~/.circuit-host`, or any other agent's dir.

### 5.3 Resources
cgroup v2 `cpu` / `memory` / `pids`, replacing the best-effort RSS poll. OOM-kill stays inside the
agent's cgroup, never the host. The manifest's `resources` is a request; the cgroup is set to
`min(manifest, node budget)`.

### 5.4 Privilege (oci)
Drop all Linux capabilities, `no-new-privileges`, a seccomp profile, non-root UID, rootless runtime, no
host devices.

### 5.5 Network — forced through the egress proxy
The agent has **no default route**. Its only reachable network endpoint is the node's **egress proxy**
(§6), which is the component that actually enforces the allowlist. A trusted `node` bundle may use the
proxy in best-effort mode; an untrusted `oci` bundle is **wired so the proxy is the only path out**.

### 5.6 Node advertises what it can enforce
A node registers `caps.sandbox: "microvm" | "oci" | "node" | "none"` (strongest → weakest;
`SANDBOX_RANK` in `lib/proto.js`). The scheduler places a bundle only on a node whose sandbox ≥ its
requirement — the runtime's floor (`oci` ⇒ a container node; `node` ⇒ curated-env), raised to the
owner's optional `spec.requireSandbox`. A `none` node keeps running only the trusted built-in workloads
— exactly today's behavior, unchanged.

Because `microvm` outranks `oci`, a microVM node runs every `oci` bundle VM-backed **transparently** (a
free isolation upgrade); an owner sets `requireSandbox: "microvm"` to *insist* on a separate-kernel host.
That requirement is an agent-spec field, **not** a signed manifest field — so demanding stronger
isolation never changes the bundle bytes or signature.

The agent **still can't touch funds** regardless of the sandbox — that's custody's job. The sandbox is
the *other* direction.

### 5.7 microVM — escape-proof isolation without a TEE (B3)

§5.4's container is strong, but it **shares the host kernel** — so the residual (§9) is "a 0-day in the
runtime/proxy → escape." A **microVM** closes exactly that: each agent runs inside a lightweight virtual
machine with **its own guest kernel**, so reaching the host requires breaking the *hypervisor* (a tiny,
purpose-built surface — this is why AWS runs untrusted Lambda/Fargate on Firecracker) instead of finding
one of the many host-kernel bugs.

**It needs only KVM, not a TEE.** microVM isolation rides on hardware virtualization (`/dev/kvm` — Intel
VT-x / AMD-V), which is present on **~every consumer CPU**. That is the key property: strong,
separate-kernel isolation on commodity hardware that has **no** confidential-computing silicon. (Secrecy
— hiding the agent's memory *from* the host — is the orthogonal TEE property; that's B4, below.)

**It reuses all of B2 — only the container runtime changes.** The recommended backend is **Kata
Containers**, which runs an ordinary OCI container *inside* a microVM. So the artifact stays `oci`, the
**signed manifest is untouched**, and `buildContainerSpec` is byte-for-byte identical except for one
flag: `--runtime <kata>`. The read-only rootfs, dropped capabilities, `no-new-privileges`, seccomp,
non-root UID, the egress-proxy sidecar, the curated env, and the resource caps **all carry over verbatim**
(the VM's fixed vCPU/RAM allocation also *becomes* the resource cap, cleaner than cgroups). Firecracker
direct (a VM-image artifact + a hand-managed tap device, no container engine) is a leaner future path with
its own run path; this scaffolding gates on the Kata path.

**Wiring (scaffolded):**
- `detectMicroVm()` (`node-host/oci.js`) — honest detection: usable `/dev/kvm` **and** a Kata runtime, else
  `null`. A node with neither advertises `oci` (or lower), never `microvm` — **fail-closed**, so the
  scheduler never hands it microvm-required work.
- `resolveSandbox()` (`node-host/host.js`) — auto-detect strongest-first: `microvm` → `oci` → `node`.
- `SANDBOX_RANK` + `nodeSatisfies` (`lib/proto.js`) — `microvm:3` above `oci:2`; honors
  `spec.requireSandbox`.
- `buildContainerSpec({ …, vmRuntime })` — when the node is `microvm`, the `oci` launch path passes
  `vmRuntime = CIRCUIT_MICROVM_RUNTIME_CLASS` (default `io.containerd.kata.v2`); otherwise the default
  host-kernel runtime (runc).

What's **not** in this pass: the live Kata run can't be exercised where there's no `/dev/kvm` + Kata, and
the same operator-config discipline as B2 applies (the isolated egress network must still be present —
`host.js` fails closed without it).

---

## 6. The egress proxy (the load-bearing piece for untrusted hosting)

Untrusted hosting is only as safe as this component, so it is first-class, not an afterthought.

A **per-node forward proxy** that every hosted agent's traffic is funneled through:

- **Class → host resolution.** The node maps each enabled `egress` class to a small fixed registry of
  concrete upstreams (`signer`→the agent's signer URL, `data`→data-api, `inference`→inference-gateway,
  `rpc`→a *public/proxied* RPC, `jupiter`→Jupiter). Unknown class → denied.
- **Deny by default, and explicitly block the host's own network.** Reject all RFC-1918, loopback,
  link-local, and the node's management ports — so a hostile agent can't portscan Joe's LAN or hit his
  other services.
- **Per-agent identity.** The proxy tags each connection with the agentId for per-agent rate caps and
  logging; a runaway bundle hammering the signer/data-api is throttled at the proxy, on top of the
  upstream's own x402/policy limits.
- **Enforcement.** `oci`: the container's only route is the proxy (pinned address / unix socket); there
  is no other egress. `node` (trusted): the agent is *configured* to use the proxy; isolation is
  best-effort because the node is trusted not to host hostile code.
- **No secret termination.** The proxy forwards; it does not inject the operator's credentials. Agents
  authenticate to paid upstreams with their own x402 session.

DNS is resolved by the proxy against the allowlist (not by the agent), so hostname→IP rotation can't be
used to slip past an IP rule.

---

## 7. Publisher ↔ agent authorization

Binding a bundle to an agent is an explicit, owner-gated step — "signed" is not enough; it must be
"signed by someone allowed."

- At `agent create <name> --bundle <ref>`: the control-plane already knows the agent's **owner** pubkey.
  It verifies the manifest `sig` against `publisherPubkey` **and** that `publisherPubkey == agent.owner`
  (or is on an owner-approved publisher allowlist). Only then is `spec.bundle` stored.
- At node start: the node re-verifies the `sha256` and the `manifestSig` carried in the assignment before
  any code runs. Defense in depth — a compromised distribution path still can't make a node run unbound
  or tampered code.

---

## 8. Node-host changes

`resolveWorkload(spec)` gains a third branch:
- `spec.bundle` present → **bundle path**: ensure-pulled (verify `sha256` + manifest sig) → build the
  sandbox spec (curated env, RO rootfs + writable dataDir, egress via proxy, cgroup) → launch under the
  node's sandbox runtime → wire stdout/heartbeat exactly as today.
- No bundle → the existing `agentd` / `circuit-agent` branches, **but** these now also get the curated
  env from §5.1 (the leak fix is not bundle-specific).

Everything downstream is unchanged: the heartbeat/health/log relay, the `status.json` snapshot (it gains
`runtime: "bundle"`), `enforceMemory` becomes the cgroup limit, and stop/drain tears the sandbox down
with no residue. Fix the misleading "(sandboxed, bounded)" header comment to match what's actually
enforced at each phase.

---

## 9. Trust model (both directions)

| Concern | Protected by | Residual |
|---|---|---|
| Agent steals the host's funds | off-box custody (no transfer verb) | none |
| Agent is forced into a bad trade | Verified Intents (signer re-derives) | host can *withhold*/time |
| Host harms the agent's funds | off-box custody | none |
| **Agent reads the operator's secrets** | **curated env (§5.1)** | none once `...process.env` is gone |
| **Agent attacks the operator's machine/LAN** | sandbox FS/cgroup/caps + egress proxy; on a **`microvm`** node, a separate guest kernel (§5.7) | container node: a runtime/kernel 0-day. **`microvm` node: a hypervisor/VMM escape** — a tiny surface |
| Node runs tampered/unbound code | bundle `sha256` + manifest sig + owner binding (§7) | none if verified |
| Host reads the agent's strategy | — | a **confidential microVM** (B4 — SEV-SNP/TDX) closes it; see [Sealed Agents](./SEALED_AGENTS.md) |

microVM (§5.7, B3) shrinks the machine/LAN-escape residual from a host-kernel 0-day to a hypervisor break.
The one thing isolation still does **not** give is **strategy secrecy** — even behind a separate kernel the
operator owns the hypervisor and can read the guest's memory. That is closed by a **confidential microVM**
(B4): the same VM run under a TEE (SEV-SNP/TDX) so the host can't read it either. It composes cleanly —
**B4 is B3 plus encrypted memory** — and is the [Sealed Agents](./SEALED_AGENTS.md) goal realized as a
confidential VM.

---

## 10. Failover (unchanged)

A host going down still triggers the existing reschedule. The only addition: the new node **pulls the
same `sha256`** (often cached) before starting, then opens a fresh session. The fence, custody, and
on-chain position reconstruction are unchanged — failover just carries a content hash along.

---

## 11. Phased rollout

| Phase | Scope | Distribution | Sandbox | Status |
|---|---|---|---|---|
| **B0** | **leak fix** | — | **curated env in `startAgent`** (§5.1) | ✅ **built + tested** |
| **B1** | trusted / own-fleet | `node` tarball + sha256 (local CAS) | curated env + cgroup v2 + RO tree (**no ns/seccomp**) | ✅ **built + tested** (publish → verify → unpack → spawn) |
| **B2** | untrusted / community | content-addressed store + SSRF-safe pull | hardened container (RO rootfs, cap-drop, non-root, pids/mem) + **egress proxy (§6)** + sandbox-gated placement | ✅ **built + tested** (live container run gated on a usable runtime) |
| **B3** | **escape-proof isolation** | `oci` (unchanged) | **microVM** — the same hardened container, own guest kernel via Kata/KVM (§5.7) | 🟡 **scaffolded** (rank + detect + gating + spec; live run gated on a KVM/Kata node) |
| **B4** | strategy-secret | `oci`, attested | **confidential microVM** — B3 + a TEE (SEV-SNP/TDX): the host can't read guest memory either; the [Sealed Agents](./SEALED_AGENTS.md) goal | ⏳ future |

- **B0** is a standalone security hotfix — ~20 lines, no new concepts, ships first and on its own.
- **B1** is deliberately *small*: on a trusted node you do **not** need namespaces/seccomp (that's most of
  the work of a real container, hand-rolled). Curated env + cgroup + read-only bind is enough when the
  node is trusted not to host hostile code. This makes "my own agent on my contributed nodes" real fast.
- **B2** is where the real isolation lives, and it is **gated on the egress proxy (§6)** being built —
  that, not the OCI runtime, is the hard part and the thing the untrusted-safety claim rests on.
- **B3** (microVM) closes the one residual B2 leaves — a runtime/kernel 0-day escaping the *shared* kernel
  — by giving each agent its own guest kernel. It needs only **KVM** (hardware virtualization, on ~all
  consumer CPUs; **no TEE**), reuses the entire B2 path (only the container `--runtime` changes), and
  ranks above `oci` so it upgrades existing bundles transparently.
- **B4** (confidential microVM) is **B3 + a TEE**: the same microVM run under SEV-SNP/TDX so the operator
  can't read the agent's memory/strategy either — *secrecy* layered on *isolation*, no redesign. It is the
  [Sealed Agents](./SEALED_AGENTS.md) goal realized as a confidential VM; hardware-gated. B3/B4 must not
  block B1/B2.

---

## 12. Open questions / risks

- **OCI runtime narrows the contributor pool.** Requiring rootless podman/runc on every community CPU
  excludes casual nodes. Mitigation: keep `node`-runtime for trusted/own nodes; gate untrusted bundles to
  `oci`-capable nodes via `caps.sandbox`. Consider shipping the node-host itself as a container that
  carries the runtime (composes with the existing GPU-node Docker onboarding) — but nested containers
  need sysbox/privileged, which is its own decision.
- **microVM (B3) needs KVM — and nested virt on cloud nodes.** It requires `/dev/kvm` (hardware
  virtualization). Bare-metal and home machines have it; a node that is *itself* a cloud VM needs the
  provider to expose **nested virtualization** (not always available, sometimes slower) — so a
  contributor's real desktop is a *better* microVM host than a budget VPS. This narrows the `microvm` pool
  the way the OCI runtime narrows the `oci` pool, and it fails closed the same way: no `/dev/kvm` + Kata →
  the node advertises `oci` (or lower), never `microvm`, and simply isn't handed microvm-required work.
- **Bundle cold-start.** Large `node_modules` make first-pull slow; require a bundled single-file dist,
  and lean on the sha256 cache for reschedules.
- **Supply chain / reproducibility.** The manifest sig pins the publisher; pin/lock the SDK + deps so a
  rebuild is reproducible from the sha256. A verified-build attestation can come later.
- **Proxy as a bottleneck/SPOF on a node.** It's per-node, so its blast radius is one operator's agents;
  size its rate caps and fail closed (no proxy → no egress → agent paused, not unrestricted).
