# Agent Bundles — hosting arbitrary user agents on the mesh

**Status:** SPEC (design + implementation plan; not built). Companion to
[SECURITY.md](../SECURITY.md), [VERIFIED_INTENTS.md](./VERIFIED_INTENTS.md), and
[SEALED_AGENTS.md](./SEALED_AGENTS.md).

**Premise.** Today the node-host runs only **known, pre-installed workloads** (`agentd`, the reference
paper trader, and `circuit-agent`, Circuit's own bot) — `resolveWorkload()` resolves a fixed set, and
the spawned process inherits the operator's full environment. To let a developer write *their own*
`@circuit/agent` and have **Circuit's mesh host it on a stranger's CPU**, two things are missing — and
note which one is *not*:

- **NOT custody.** Off-box signing already makes hosting untrusted agent *logic* safe for funds: a
  malicious agent can't drain (no transfer verb), can't forge trades (Verified Intents), and can't run
  twice (the fence). The money side is solved.
- **MISSING #1 — distribution.** A way to package a user's agent and ship it to whatever node the
  scheduler picks, verifiably.
- **MISSING #2 — sandbox.** A way to run that untrusted code **without endangering the operator's
  machine**. Every container protects the host from the guest, which is exactly the direction we need
  here (protect Joe from the agent he's hosting).

This spec covers both, and the trust model in both directions.

---

## 0. Shape

```
 dev:   circuit agent publish my-bot
          └─ build → content-addressed BUNDLE (sha256) → upload to the bundle store → ref

 deploy: circuit agent create my-bot --bundle <ref>
          └─ spec.bundle = { ref, sha256, runtime }

 node:  start assignment carries { bundle:{url, sha256, runtime}, signer:{…} }
          └─ pull (cache by sha256) → VERIFY hash → run SANDBOXED → forward health/logs
          └─ teardown on stop/drain; reschedule pulls the SAME sha256 elsewhere
```

---

## 1. The bundle (artifact)

A **content-addressed** artifact identified by its `sha256`. Two supported forms, declared by `runtime`:

| `runtime` | Artifact | Isolation | For |
|---|---|---|---|
| `oci`  | an OCI image (agent baked onto a minimal base) | OS-level (rootless container) | **untrusted** user agents on community nodes (the default) |
| `node` | a tarball: built agent + locked deps + manifest | a locked-down subprocess (cgroup + namespaces + seccomp) | trusted / first-party / own-fleet nodes |

A `node`-runtime bundle is lighter (no image build, no registry) but is only safe on nodes the agent's
owner or Circuit trusts; **untrusted bundles go `oci`.** Either way the bundle is **immutable** — the
`sha256` is the identity, so a node always runs exactly what was published, and reschedules pull the
same bytes.

**Manifest** (in the bundle, signed by the publisher):
```jsonc
{
  "agentId": "…",                 // bound to the control-plane agent
  "runtime": "oci" | "node",
  "entry":   "agent.js",          // node-runtime only
  "sdk":     "@circuit/agent@x",  // for compatibility checks
  "egress":  ["signer", "data", "inference", "rpc", "jupiter"],  // requested network classes
  "resources": { "maxMemoryMb": 512, "maxCpu": 0.5 },
  "publisherPubkey": "<ed25519>", // signs the manifest + the sha256
  "sig": "<ed25519 over {sha256, agentId, …}>"
}
```

---

## 2. Publish (CLI)

`circuit agent publish <name>`:
1. Build the agent (`tsup`/bundle to a single dist, or build the OCI image).
2. Compute the `sha256`; sign the manifest with the owner key.
3. Upload to the **bundle store** (see §3); print the `ref` (`bundle://<sha256>` or an OCI digest).

Then `circuit agent create <name> --bundle <ref> [--runtime oci]` registers it with the control plane,
which stores `spec.bundle = { ref, sha256, runtime }`.

---

## 3. Distribution

A **content-addressed bundle store** the scheduler can hand a node a pull-URL + hash for:
- **`oci`** → an OCI registry (Circuit's, or ghcr) addressed by digest. Nodes pull with their container
  runtime; the digest *is* the integrity check.
- **`node`** → object storage / a Circuit "bundle CDN"; the node fetches the tarball and **verifies the
  `sha256` before unpacking** (reject on mismatch — no unverified code ever executes).

The control-plane `start` assignment gains a `bundle` block next to the existing `signer` block:
```jsonc
{ "action":"start", "agent": { "id":"…", "spec":{…},
    "bundle": { "url":"…", "sha256":"…", "runtime":"oci", "manifestSig":"…" },
    "signer": { "url":"…", "agentId":"…", "epoch":N, "token":"…" } } }
```
Nodes **cache by `sha256`**, so a reschedule onto a node that already has the bytes is instant, and the
common case (same agent bouncing between a few nodes) pulls once.

---

## 4. The sandbox (protecting the operator)

The contract: **the bundle can reach its data dir and an egress allowlist, and nothing else.** Concretely:

- **Minimal env — fixes a real leak.** The current node-host passes `...process.env` into the workload;
  an untrusted bundle must instead get a **curated env only**: `CIRCUIT_SIGNER_URL`, `CIRCUIT_AGENT_ID`,
  `CIRCUIT_AGENT_EPOCH`, `CIRCUIT_AGENT_SESSION`, `CIRCUIT_AGENT_ADDRESS`, `CIRCUIT_AGENT_PAPER`,
  `CIRCUIT_AGENT_DATA_DIR`. **Never** the operator's environment (which may hold the operator's own
  keys/tokens).
- **Filesystem.** Read-only rootfs; the **only** writable mount is the per-agent `dataDir`. No access to
  the operator's home, the host's `~/.circuit-host`, or any other agent's dir.
- **Network egress allowlist.** The agent needs outbound to the signer, data-api, inference gateway, an
  RPC, and Jupiter — and nothing else. Resolve the manifest's `egress` classes to concrete hosts and
  **block everything else**, especially the operator's `localhost`/LAN and RFC-1918 ranges, so a hostile
  agent can't portscan Joe's network or hit his other services.
- **Resource limits.** cgroup v2 `cpu` / `memory` / `pids` (replacing today's best-effort RSS kill);
  OOM-kill stays inside the agent, never the host.
- **Privilege.** Drop all Linux capabilities, `no-new-privileges`, a seccomp profile, non-root UID,
  rootless runtime. No host devices.
- **Node advertises what it can enforce.** A node registers `caps.sandbox: "oci" | "node" | "none"`;
  the scheduler only places an **untrusted** bundle on a node whose sandbox ≥ the bundle's requirement.
  A `none` node keeps running only the trusted built-in workloads.

The agent **still can't touch funds** regardless of the sandbox — that's custody's job. The sandbox is
the *other* direction: it stops the guest from hurting the host.

---

## 5. Node-host changes

`resolveWorkload(spec)` gains a third branch:
- `spec.bundle` present → **bundle path**: ensure-pulled (verify `sha256` + manifest sig) → build the
  sandbox spec (curated env, RO rootfs + writable dataDir, egress filter, cgroup) → launch under the
  node's sandbox runtime → wire stdout/heartbeat exactly as today.
- No bundle → the existing `agentd` / `circuit-agent` branches (unchanged).

Everything downstream is unchanged: the heartbeat/health/log relay, the `status.json` snapshot (it just
gains `runtime: "bundle"`), `enforceMemory` becomes the cgroup limit, and stop/drain tears the sandbox
down with no residue.

---

## 6. Trust model (both directions)

| Concern | Protected by | Residual |
|---|---|---|
| Agent steals the host's funds | off-box custody (no transfer verb) | none |
| Agent is forced to make a bad trade | Verified Intents (signer re-derives) | host can *withhold*/time |
| Host harms the agent's funds | off-box custody | none |
| **Agent harms the operator's machine** | **this sandbox** (FS/net/cgroup/caps) | a 0-day in the runtime |
| Host reads the agent's strategy | — | **yes — use [Sealed Agents](./SEALED_AGENTS.md) (TEE) for secrecy** |
| Node runs tampered code | bundle `sha256` + manifest signature | none if verified |

The one thing bundling + sandboxing does **not** give a user is **strategy secrecy** — the operator can
still observe the running code/memory. That residual is exactly what the TEE path (Sealed Agents) closes,
and it composes: a sealed bundle runs in an attested enclave.

---

## 7. Interplay with failover (unchanged)

A host going down still triggers the existing reschedule. The only addition: the new node **pulls the
same `sha256` bundle** (often cached) before starting, then opens a fresh session as usual. The fence,
custody, and on-chain position reconstruction are all unchanged — failover just carries a content hash
along.

---

## 8. Phased rollout

| Phase | Distribution | Sandbox | Runs |
|---|---|---|---|
| **B1** | `node` tarball + sha256 | curated-env subprocess + cgroup (fix the env leak first) | **own-fleet / trusted** nodes |
| **B2** | OCI registry (digest) | rootless container, RO rootfs, egress allowlist, seccomp | **untrusted** community nodes |
| **B3** | OCI, attested | TEE (Sealed Agents) | strategy-secret agents |

B1 is small and high-value (it makes "my own agent on my own contributed nodes" real and closes the env
leak). B2 is the one that makes the mesh a true open marketplace for arbitrary agents. B3 is the
confidential tier.

---

## 9. Open questions / risks

- **Egress resolution.** Allowlisting by hostname is brittle (IPs rotate); resolve via a per-node
  forward proxy that only permits the named upstreams, rather than raw IP rules.
- **Bundle size / cold-start.** Large `node_modules` make first-pull slow; prefer bundled single-file
  dist, and the sha256 cache makes reschedules cheap.
- **Runtime dependency.** Requiring a container runtime narrows the contributor pool; keep `node`-runtime
  for casual/own nodes and gate untrusted bundles to `oci`-capable nodes via the scheduler cap.
- **DoS via the agent.** A bundle that hammers the signer/data-api is bounded by policy + rate limits,
  but add per-agent egress rate caps at the proxy.
- **Supply chain.** The manifest signature pins the publisher; pin/lock the SDK + deps in the bundle so
  a rebuild is reproducible from the sha256.
