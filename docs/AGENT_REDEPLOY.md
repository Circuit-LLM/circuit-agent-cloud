# Agent Redeploy — rolling updates without losing the wallet

**Status:** SPEC / proposed. Closes the "update an agent" gap: today there is no in-place update, and the
only workaround (`destroy` + re-deploy) deletes the off-box wallet and re-funds from scratch.

Companion to [AGENT_BUNDLES.md](AGENT_BUNDLES.md) (bundle format, owner-binding §7, the trust/runtime
model) and the custody model (off-box signer + epoch fence).

---

## 0. The problem, precisely (what exists today)

- **Deploy is create-only.** `control-plane POST /v1/agents` throws `agent id "<id>" already exists`
  (server.js, the `store.getAgent(id)` guard). The CLI's `deployFlow` always calls `agents.create()`,
  which throws the same locally (`cli services/agents.js`). So re-deploying a changed bundle under the
  same name **errors** — there is no "attach a new bundle to the existing agent."
- **The only update path is destructive.** To ship v2 you must:
  1. withdraw funds (`destroy` refuses while the wallet is non-empty; `--force` *abandons* them),
  2. `destroy` — which **cascades to the signer** (`DELETE /v1/agents/:id`) and wipes the sealed key,
  3. re-deploy — the signer, finding no record, **provisions a brand-new wallet** (new address).
- Net: an "update" is a teardown + a fresh agent with a **new wallet** to re-fund and reconfigure.

The primitives for a clean update already exist — this spec just wires the missing middle:
- **Bundles are content-addressed by `sha256`** — a new version is simply a new hash; `bundle-store`
  already dedupes + GCs unreferenced blobs.
- **The epoch fence already guarantees at-most-one** running instance: each `openSession()` mints a new
  monotonic `epoch` at the signer, and "the new epoch supersedes any prior one, fencing out an orphan."
- **The signer is idempotent by `agentId` while the record lives** — provisioning a known agent returns
  the *existing* wallet. We just must not `DELETE` it.

---

## 1. Goal

`circuit agent redeploy <name>` (and `deploy` of an existing name) ships new code with **everything
else preserved**:

| Preserved (unchanged) | Changed |
|---|---|
| wallet address + funds (no signer DELETE) | `spec.bundle` → new `sha256` |
| owner, policy, verified-intent config | session `epoch` (bumped → fences the old instance) |
| agent `id`, `name`, on-chain vault | running code on the node |

Brief restart is acceptable (an agent is an autonomous loop, not a live-traffic server). Optional
phase 2 makes it near-zero-downtime using the fence.

---

## 2. New endpoint — `POST /v1/agents/:id/bundle`

```
POST /v1/agents/:id/bundle      (owner-authed)
body: { bundle }                // same shape as spec.bundle on create
→ 200 { agent }                 // with the new spec.bundle + state=PENDING (rollout started)
```

Validation — **reuse the create-path gates** so update is exactly as safe as create:
1. `authOwner(ctx)` must equal `agent.owner` (owner-only; no IDOR).
2. `assertBundleOwnerBinding({ bundle }, owner, id)` — the new manifest's `publisherPubkey` === owner
   **and** `manifest.agentId` === this `:id` (a bundle still binds to its owner *and* this exact agent).
3. `verifyManifest(bundle.manifest)` — signature valid.
4. Runtime gate unchanged: an untrusted publisher's `node`-runtime bundle is still refused (must be `oci`).
5. If `bundle.sha256 === agent.spec.bundle.sha256` → no-op unless `?force=1` (e.g. re-pin to retry).

Effect (the rollout, see §3):
- `agent.lastGoodBundle = agent.spec.bundle` (pin the current sha for rollback + keep it GC-safe).
- `agent.spec.bundle = bundle`; `agent.desired = 'running'`.
- Hand off to the reconcile to swap the running instance.

**The signer is never touched** — same `agentId`, same sealed key, same wallet. Only `openSession()`
runs again during re-placement, which bumps the epoch.

---

## 3. The rollout

### Phase 1 — drain-then-start (MVP, simplest + safe)

On a bundle change, the control plane drains the current placement and lets the existing reconcile
re-place it with the new bundle:

1. Tell the current node to stop the old instance (the node already tears down a sandbox when an agent
   leaves its assignment); set `agent.nodeId = null; agent.state = PENDING`.
2. The reconcile loop re-places the PENDING agent (same node or another that satisfies it).
3. Placement calls `openSession()` → **new epoch** → any lingering old instance is fenced (its `{epoch}`
   is stale, the signer rejects it — it cannot trade even if it is slow to die).
4. The node pulls the **new `sha256`** from `bundleBlockFor(agent)`, verifies hash + manifest signature
   **before running** (unchanged), and starts it.

Downtime = one re-place + pull + start (seconds, or a minute on a cold bundle). Fine for an agent.

### Phase 2 — fenced overlap (optional, near-zero downtime)

Because the epoch fence already makes only the current epoch able to sign:
1. Bump the epoch first → the **old** instance is immediately inert (can run, cannot trade).
2. Start the **new** instance (it gets the new epoch's session).
3. Once the new instance reports `RUNNING` healthy, tell the old node to tear down.

During the brief overlap both processes may be alive, but **only the new one can act** — the fence
already forbids double-trading. No new safety surface; it just trims the gap. Ship phase 1 first.

---

## 4. Failed-update auto-rollback

A bad v2 (crash-loops, never reaches `RUNNING`) must not leave the agent worse off than v1:

- Keep `agent.lastGoodBundle` (the pre-update sha) referenced so GC (`runGc`) never collects it.
- If the new bundle fails to reach `RUNNING` within `REDEPLOY_MAX_ATTEMPTS` placements (reuse the
  existing stuck-watchdog `placeAttempts`), the control plane **rolls back**: `spec.bundle =
  lastGoodBundle`, re-place. The old bytes are content-addressed and usually still cached → fast revert.
- Surface it: `log("⚠ agent <id> update to <sha> failed N starts — rolled back to <lastGoodSha>")`, and
  expose the last rollout result on the agent record so `circuit agent status` shows it.

This is the safety the *current* destroy+recreate path lacks entirely — today a bad redeploy just loops.

---

## 5. CLI

```
circuit agent redeploy <name> [--dir ./agent] [--entry agent.js] [--force]
```
- Re-pack the local dir → new bundle (new sha256), signed by the wallet/owner with the **same** agentId
  (same `publishDir({ dir, agentId: name, entry })` the deploy flow already uses).
- `POST /v1/agents/:id/bundle` with the new bundle; stream rollout state (draining → pulling → running),
  and on failure report the auto-rollback.
- Same `excludedSecrets` notice as deploy (`.env` etc. still never ship).

And make `deploy` of an existing name **route to redeploy** instead of erroring:
- `deployFlow` / `agents.create`: if the agent already exists **and is owned by this wallet**, call the
  redeploy path; otherwise keep the "already exists" error (a different owner can't hijack the name).

---

## 6. State, store, safety

- **State machine:** reuse existing states — set `desired='running'`, `state=PENDING`, `nodeId=null`,
  record `targetSha`. The dashboard shows SCHEDULED → JOINING → RUNNING as normal. (Optional cosmetic
  `REDEPLOYING` flag for clearer UX.)
- **Store:** add `agent.lastGoodBundle` and a small `agent.lastRollout = { sha, at, ok, attempts }`.
- **GC:** `runGc` must treat both `spec.bundle.sha256` **and** `lastGoodBundle.sha256` as referenced.
- **Rate limit:** reuse `rateLimitOwner` on the bundle endpoint; reject a new redeploy while one is in
  flight for that agent (or supersede the in-flight target).
- **Custody/fence/verified-intents:** entirely unchanged. Funds were always safe (off-box, buy/sell-only);
  this change never moves a key. The epoch fence is what makes the swap safe.

---

## 7. Out of scope

- Multi-replica / horizontal scale (the fence is single-instance by design).
- Changing `owner` (separate `PUT /v1/agents/:id/owner` already exists) or `policy` mid-rollout.
- Secret delivery to untrusted hosts — that's [SEALED_AGENTS.md](SEALED_AGENTS.md), unrelated.

## 8. Build order

1. `POST /v1/agents/:id/bundle` + the create-path gate reuse (§2). **← unblocks updates immediately**
2. Drain-then-start rollout + `lastGoodBundle` GC pin (§3 phase 1).
3. `circuit agent redeploy` + `deploy`-routes-to-redeploy (§5).
4. Auto-rollback on failed update (§4).
5. (Optional) fenced-overlap near-zero downtime (§3 phase 2).
