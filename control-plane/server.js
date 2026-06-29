#!/usr/bin/env node
// Circuit Agent Cloud — Control Plane.
// Stateless API over an in-memory+JSON store. Nodes POLL it (heartbeat), so
// hosts need no inbound connectivity. The CLI drives agents through it.
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { Router, sendJson } from '../lib/http.js';
import { Store } from '../lib/store.js';
import { STATE, nodeSatisfies, normalizePolicy, normalizeVerified, newId, now } from '../lib/proto.js';
import { verifyManifest } from '../lib/bundle.js';
import { sha256hex } from '../lib/ed25519.js';
import { MAX_BUNDLE_BYTES } from '../lib/bundle-store.js';
import { verifyOwnerRequest, NonceStore } from '../lib/owner-auth.js';
import { verifyNodeRequest } from '../lib/node-auth.js';

const PORT = Number(process.env.PORT || 18980);
const HOST = process.env.HOST || '127.0.0.1';
const STATE_FILE = process.env.CIRCUIT_CLOUD_STATE || path.join(os.homedir(), '.circuit-cloud', 'state.json');
const NODE_TIMEOUT_MS = Number(process.env.NODE_TIMEOUT_MS || 30000);
// Transition watchdog: an agent SCHEDULED to a node but never reported running within STUCK_MS (the
// node accepted it but couldn't start it — missing workload, spawn error, …) is bounced to a DIFFERENT
// node so it can't sit stuck. It keeps retrying (self-heals when a node is fixed); after
// MAX_PLACE_ATTEMPTS distinct failed placements it's logged loudly so the operator notices.
const STUCK_MS = Number(process.env.CIRCUIT_STUCK_MS || 45000);
const MAX_PLACE_ATTEMPTS = Number(process.env.CIRCUIT_MAX_PLACE_ATTEMPTS || 3);
const KEY = process.env.CIRCUIT_CLOUD_KEY || ''; // optional shared bearer

// Off-box signer = the one custody mechanism. The control plane is the placement
// authority: it provisions each agent's wallet, and opens a fresh session (epoch
// + token = the at-most-one fence) on every placement. SIGNER_URL is where the CP
// reaches the signer; SIGNER_PUBLIC_URL is what workloads use (defaults to the
// same). If unset, custody is disabled and agents run paper-only (dev/demo).
const SIGNER_URL = (process.env.CIRCUIT_SIGNER_URL || '').replace(/\/$/, '');
const SIGNER_PUBLIC_URL = (process.env.CIRCUIT_SIGNER_PUBLIC_URL || SIGNER_URL).replace(/\/$/, '');
const SIGNER_KEY = process.env.CIRCUIT_SIGNER_KEY || '';

const store = new Store(STATE_FILE);

// Shared bundle store — the content-addressed blob backend nodes pull from (next to the state file).
const BUNDLE_DIR = process.env.CIRCUIT_BUNDLE_DIR || path.join(path.dirname(STATE_FILE), 'bundles');
fs.mkdirSync(BUNDLE_DIR, { recursive: true });

function readRaw(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = []; let len = 0;
    req.on('data', (c) => {
      len += c.length;
      if (len > max) { req.destroy(); reject(Object.assign(new Error('bundle exceeds size cap'), { status: 413 })); }
      else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const log = (...a) => console.log(`[${new Date().toISOString()}] [cp]`, ...a);

async function signerApi(method, p, body, timeoutMs = 8000) {
  const r = await fetch(SIGNER_URL + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...(SIGNER_KEY ? { Authorization: `Bearer ${SIGNER_KEY}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(j.error || `signer ${p} -> ${r.status}`); e.status = r.status; e.code = j.code; throw e; }
  return j;
}

// Open a fresh session for the agent's current placement when it changes nodes.
// The new epoch supersedes any prior one at the signer, fencing out an orphan on
// a node we've given up on. No-op if custody is disabled or already current.
async function ensureSession(a) {
  if (!SIGNER_URL || !a.nodeId) return;
  if (a.session && a.session.node === a.nodeId) return; // already current
  try {
    const s = await signerApi('POST', `/v1/agents/${a.id}/session`, { node: a.nodeId });
    a.session = { epoch: s.epoch, token: s.token, node: a.nodeId };
    a.paper = s.paper;
    store.persist();
    log(`session ${a.id} epoch ${s.epoch} for ${a.nodeId}`);
  } catch (e) {
    log(`session open failed for ${a.id}: ${e.message} (workload will run without custody)`);
  }
}

// The signer block handed to the node-host → workload. Scoped: a per-session
// token that authorizes only in-policy swaps for this one agent + epoch.
function signerBlockFor(a) {
  if (!SIGNER_PUBLIC_URL || !a.session) return undefined;
  return {
    url: SIGNER_PUBLIC_URL,
    agentId: a.id,
    epoch: a.session.epoch,
    token: a.session.token,
    address: a.address || null,
    paper: a.paper !== false,
  };
}

// B1 — the bundle block the node pulls + verifies. Carries the pull URL, the content hash, the
// runtime, and the signed manifest (so the node re-checks the sig + owner binding before running).
function bundleBlockFor(a) {
  const b = a.spec?.bundle;
  if (!b) return undefined;
  return { url: b.url, sha256: b.sha256, runtime: b.runtime || b.manifest?.runtime || 'node', manifest: b.manifest };
}

// Owner-binding gate (AGENT_BUNDLES.md §7): a bundle may only be attached to an agent by its owner.
// "Signed" isn't enough — the publisher key must equal the agent's owner. Throws on any mismatch.
function assertBundleOwnerBinding(spec, owner, agentId) {
  const b = spec?.bundle;
  if (!b) return;
  const m = b.manifest;
  if (!m) throw new Error('spec.bundle requires a signed manifest');
  if (!owner) throw new Error('a bundle-backed agent requires an owner');
  if (!verifyManifest(m)) throw new Error('bundle manifest signature is invalid');
  if (m.publisherPubkey !== owner) throw new Error('bundle publisher is not the agent owner');
  if (agentId && m.agentId !== agentId) throw new Error('bundle manifest is not bound to this agent');
  if (m.sha256 !== b.sha256) throw new Error('bundle sha256 does not match its manifest');
  if (m.runtime !== (b.runtime || m.runtime)) throw new Error('bundle runtime mismatch');
}

function auth(ctx) {
  if (!KEY) return; // open in dev / localhost
  const got = (ctx.req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (got !== KEY) { const e = new Error('unauthorized'); e.status = 401; throw e; }
}

// ── Per-owner authorization (multi-tenant) ──────────────────────────────────────────────────────────
// REQUIRE_OWNER_AUTH=1 makes wallet-signed owner auth mandatory on every owner route (the live / multi-
// tenant posture). Off (own-fleet dev): a signature is still verified + enforced when present, but an
// unsigned request falls back to the shared-bearer gate above.
const REQUIRE_OWNER_AUTH = process.env.CIRCUIT_REQUIRE_OWNER_AUTH === '1';
const nonceStore = new NonceStore();

// Per-owner sliding-window rate limit (agent creates / min). 0 = off (own-fleet dev). Bounds one tenant
// from exhausting shared infra (signer provisioning, store growth) at others' expense.
const OWNER_RATE_PER_MIN = Number(process.env.CIRCUIT_OWNER_RATE_PER_MIN || 0);
const ownerHits = new Map();
function rateLimitOwner(owner) {
  if (!OWNER_RATE_PER_MIN || !owner) return;
  const t = now();
  const hits = (ownerHits.get(owner) || []).filter((x) => t - x < 60_000);
  if (hits.length >= OWNER_RATE_PER_MIN) { const e = new Error('rate limit exceeded — slow down'); e.status = 429; throw e; }
  hits.push(t);
  ownerHits.set(owner, hits);
}

// Authenticate the caller as an owner. Returns the owner pubkey, or null when unsigned (and allowed).
function requireOwner(ctx) {
  const path = new URL(ctx.req.url, 'http://x').pathname;
  const owner = verifyOwnerRequest(
    { method: ctx.req.method, path, body: ctx.body, headers: ctx.req.headers },
    { nonceStore },
  );
  if (!owner && REQUIRE_OWNER_AUTH) { const e = new Error('owner signature required'); e.status = 401; throw e; }
  return owner;
}

// A caller may only act on an agent they own. In strict mode an owned agent REQUIRES a matching signer.
function assertOwns(agent, owner) {
  if (owner && agent.owner && agent.owner !== owner) { const e = new Error('not your agent'); e.status = 403; throw e; }
  if (REQUIRE_OWNER_AUTH && agent.owner && owner !== agent.owner) { const e = new Error('owner auth required for this agent'); e.status = 403; throw e; }
}

// ── Node-identity auth (multi-tenant) — a node proves possession of its key on every request. ──────────
const REQUIRE_NODE_AUTH = process.env.CIRCUIT_REQUIRE_NODE_AUTH === '1';
const nodeNonceStore = new NonceStore();

function requireNode(ctx) {
  const path = new URL(ctx.req.url, 'http://x').pathname;
  const node = verifyNodeRequest(
    { method: ctx.req.method, path, body: ctx.body, headers: ctx.req.headers },
    { nonceStore: nodeNonceStore },
  );
  if (!node && REQUIRE_NODE_AUTH) { const e = new Error('node signature required'); e.status = 401; throw e; }
  return node;
}

// The nodeId is bound to the first pubkey that registered it (TOFU); a different key can't claim it.
function assertNodeIdentity(nodeId, authedNode) {
  if (!authedNode) return; // unsigned (own-fleet dev)
  const n = store.getNode(nodeId);
  if (n?.pubkey && n.pubkey !== authedNode) { const e = new Error('nodeId bound to a different key'); e.status = 403; throw e; }
}

// Identity-or-shared-key gates for the multi-tenant routes. A valid node/owner SIGNATURE fully
// authorizes the request — an outside operator NEVER needs the admin CLOUD_KEY to join or to manage
// their own agents (handing that key out would also grant trust-promotion + global reads). The shared
// key stays as a fallback ONLY for unsigned own-fleet/dev requests. Each calls require*() exactly once
// (the nonce is single-use), so the result must be captured and reused, never re-derived.
function authNode(ctx) {
  const node = requireNode(ctx); // throws 401 when REQUIRE_NODE_AUTH and the signature is missing/bad
  if (!node) auth(ctx);          // unsigned own-fleet path → shared-bearer gate
  return node;
}
function authOwner(ctx) {
  const owner = requireOwner(ctx);
  if (!owner) auth(ctx);
  return owner;
}

const countAssigned = (nodeId) =>
  store.listAgents((a) => a.nodeId === nodeId && a.desired === 'running').length;

// Place an agent on the best live node that satisfies its custody/confidential needs.
// Best live node that satisfies the agent + has a free slot, excluding nodes that already failed to
// start it (`avoid`). Spreads load by free capacity.
function pickNode(agent, avoid) {
  return store
    .listNodes()
    .filter((n) => n.status === 'up' && !avoid.has(n.nodeId) && nodeSatisfies(n, agent))
    .map((n) => ({ n, free: (n.budget?.maxAgents ?? 0) - countAssigned(n.nodeId) }))
    .filter((x) => x.free > 0)
    .sort((a, b) => b.free - a.free)[0]?.n || null;
}

function schedule(agent) {
  if (agent.desired !== 'running') return;
  if (agent.nodeId) {
    const n = store.getNode(agent.nodeId);
    if (n && n.status === 'up') return; // already placed on a live node
  }
  let node = pickNode(agent, new Set(agent.failedNodes || []));
  // If every capable node has already failed this agent, clear the blocklist and try them all again
  // (a node may have been fixed / freed up) rather than wedging the agent in PENDING forever.
  if (!node && agent.failedNodes?.length) { agent.failedNodes = []; node = pickNode(agent, new Set()); }
  if (!node) {
    agent.nodeId = null;
    agent.state = STATE.PENDING;
    return;
  }
  agent.nodeId = node.nodeId;
  agent.state = STATE.SCHEDULED;
  agent.placedAt = now(); // start the watchdog clock for this placement
  log(`scheduled ${agent.id} (${agent.name}) -> ${agent.nodeId}`);
}

// ── Failover / reschedule sweep ───────────────────────────────────────────────
setInterval(() => {
  const t = now();
  let changed = false;
  for (const n of store.listNodes()) {
    if (n.status !== 'down' && t - (n.lastSeen || 0) > NODE_TIMEOUT_MS) {
      n.status = 'down';
      changed = true;
      log(`node ${n.nodeId} DOWN (no heartbeat ${Math.round((t - n.lastSeen) / 1000)}s)`);
      for (const a of store.listAgents((a) => a.nodeId === n.nodeId && a.desired === 'running')) {
        a.state = STATE.FAILED;
        a.nodeId = null;
      }
    }
  }
  // Watchdog: an agent SCHEDULED long enough that the node should have started it, but it's still not
  // running, can't run there — bounce it off that node (remember it) so the reschedule below moves it
  // to a different one. Keeps trying; logs loudly once it's exhausted several nodes.
  for (const a of store.listAgents((a) => a.desired === 'running' && a.state === STATE.SCHEDULED && a.nodeId && t - (a.placedAt || 0) > STUCK_MS)) {
    a.failedNodes = [...new Set([...(a.failedNodes || []), a.nodeId])];
    a.placeAttempts = (a.placeAttempts || 0) + 1;
    log(`agent ${a.id} stuck on ${a.nodeId} (${Math.round((t - (a.placedAt || 0)) / 1000)}s, never started) — re-placing [attempt ${a.placeAttempts}]`);
    if (a.placeAttempts >= MAX_PLACE_ATTEMPTS) log(`⚠ agent ${a.id} (${a.name}) failed to start on every node tried — check the node-host workload/logs`);
    a.nodeId = null;
    a.state = STATE.PENDING;
    changed = true;
  }
  for (const a of store.listAgents((a) => a.desired === 'running' && (!a.nodeId || a.state === STATE.PENDING || a.state === STATE.FAILED))) {
    schedule(a);
    changed = true;
  }
  if (changed) store.persist();
}, 5000).unref?.();

// ── API ───────────────────────────────────────────────────────────────────────
const r = new Router();

// Aggregate cloud counts. The full node/agent LISTS are admin-gated (/v1/nodes, /v1/agents), but
// these bare counts are harmless and let any operator's dashboard show how big the cloud is.
const cloudCounts = () => {
  const nodes = store.listNodes();
  return {
    nodes: nodes.length,
    nodesUp: nodes.filter((n) => n.status === 'up').length,
    agents: store.agents.size,
    agentsRunning: store.listAgents((a) => a.state === STATE.RUNNING).length,
  };
};
r.get('/health', () => ({ ok: true, service: 'circuit-control-plane', ...cloudCounts() }));
// Public counts INSIDE the proxied /v1 namespace — nginx exposes /v1/* but not /health, so the
// dashboard reads this. No auth: it returns only counts, never node addresses or agent details.
r.get('/v1/summary', () => cloudCounts());

// Operator node registers + declares its resource budget.
r.post('/v1/nodes/register', (ctx) => {
  const { nodeId, caps = {}, budget = {} } = ctx.body;
  if (!nodeId) throw new Error('nodeId required');
  const authedNode = authNode(ctx); // node identity authorizes registration; admin key not required
  assertNodeIdentity(nodeId, authedNode); // can't re-register another node's id under a new key
  const node = store.upsertNode({
    nodeId,
    pubkey: authedNode || store.getNode(nodeId)?.pubkey || null, // bind the id to this key (TOFU)
    caps,
    budget,
    status: 'up',
    lastSeen: now(),
    registeredAt: store.getNode(nodeId)?.registeredAt || now(),
  });
  log(`node ${nodeId} registered — budget=${JSON.stringify(budget)}`);
  return { ok: true, node: { nodeId: node.nodeId } };
});

// Heartbeat: node reports what it's running; gets back start/stop assignments.
r.post('/v1/nodes/heartbeat', async (ctx) => {
  const { nodeId, running = [], usage = {} } = ctx.body;
  assertNodeIdentity(nodeId, authNode(ctx)); // only the node that owns this id may heartbeat as it
  const node = store.getNode(nodeId);
  if (!node) { const e = new Error('unknown node — register first'); e.status = 409; throw e; }
  node.status = 'up';
  node.lastSeen = now();
  node.usage = usage;

  const assignments = [];
  // Free budget slots left after what the node already reports running. We only start up to this many
  // NEW agents; any further desired-but-not-running agents assigned here are OVER budget (e.g. budget
  // was lowered, or they piled on while this was the only capacity) → unassign so the sweep reschedules
  // them onto a node with room. Without this they'd sit "scheduled" forever while other nodes idle.
  let freeSlots = (node.budget?.maxAgents ?? 0) - running.length;
  // Reconcile agents this node owns.
  for (const a of store.listAgents((a) => a.nodeId === nodeId)) {
    const isRunning = running.includes(a.id);
    if (a.desired === 'running' && !isRunning) {
      if (freeSlots <= 0) {
        // node is at budget and isn't running this one → bounce it back to the scheduler
        a.nodeId = null;
        a.state = STATE.PENDING;
        continue;
      }
      freeSlots--;
      await ensureSession(a); // (re)open the lease for this placement — the fence
      assignments.push({ action: 'start', agent: { id: a.id, name: a.name, owner: a.owner, spec: a.spec, bundle: bundleBlockFor(a), signer: signerBlockFor(a) } });
    } else if (a.desired === 'running' && isRunning) {
      a.state = STATE.RUNNING;
      // It actually started here — clear the watchdog's failure memory so a future reschedule is fresh.
      if (a.placeAttempts || a.failedNodes?.length) { a.placeAttempts = 0; a.failedNodes = []; }
    } else if (a.desired !== 'running' && isRunning) {
      a.state = STATE.STOPPING;
      assignments.push({ action: 'stop', agentId: a.id });
    } else if (a.desired !== 'running' && !isRunning) {
      a.state = STATE.STOPPED;
    }
  }
  // Orphans: node runs something we don't assign to it → stop it.
  for (const rid of running) {
    const a = store.getAgent(rid);
    if (!a || a.nodeId !== nodeId) assignments.push({ action: 'stop', agentId: rid });
  }
  node.available = (node.budget?.maxAgents ?? 0) - countAssigned(nodeId);
  store.persist();
  return { assignments };
});

// Agent self-report (health/pnl) relayed by the node.
r.post('/v1/agents/:id/report', (ctx) => {
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  // Only the node actually running this agent may report its health/logs (no cross-node poisoning).
  const authedNode = authNode(ctx);
  if (authedNode) {
    const runner = a.nodeId && store.getNode(a.nodeId);
    if (!runner || runner.pubkey !== authedNode) { const e = new Error('not the node running this agent'); e.status = 403; throw e; }
  }
  a.health = ctx.body.health || a.health;
  a.lastReport = now();
  if (ctx.body.lines?.length) store.appendLogs(a.id, ctx.body.lines);
  return { ok: true };
});

// ── Agent CRUD (CLI side) ──
r.post('/v1/agents', async (ctx) => {
  const { name, owner, spec = {}, policy, verified } = ctx.body;
  if (!name) throw new Error('name required');
  // The agent's owner is the authenticated signer (multi-tenant) — the body's owner is only a fallback
  // in own-fleet dev. A user can only ever create agents owned by themselves.
  const authedOwner = authOwner(ctx);
  const agentOwner = authedOwner || owner || null;
  rateLimitOwner(agentOwner); // bound one tenant's create rate
  // For a bundle-backed agent the id is the manifest's (client-chosen) agentId, so the signed binding
  // matches the agent by construction. Validate the charset (safe for fs paths / argv) + uniqueness.
  let id;
  if (spec?.bundle?.manifest?.agentId) {
    id = String(spec.bundle.manifest.agentId);
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(id)) throw new Error('bundle agentId must be alphanumeric-led, [A-Za-z0-9_-], ≤64 chars');
    if (store.getAgent(id)) throw new Error(`agent id "${id}" already exists`);
  } else {
    id = newId('agt');
  }
  assertBundleOwnerBinding(spec, agentOwner, id); // a bundle binds only to its owner AND this exact agent id
  const agent = {
    id,
    name,
    owner: agentOwner,
    spec,
    custody: 'offbox-signer',
    policy: normalizePolicy(policy),
    // Verified-intent config (docs/VERIFIED_INTENTS.md) — forwarded to the signer, which
    // re-runs the committed rule on authenticated inputs before signing a trade.
    verified: verified ? normalizeVerified(verified) : null,
    address: null, // filled by the signer below
    desired: 'stopped',
    state: STATE.PENDING,
    nodeId: null,
    session: null,
    health: null,
    createdAt: now(),
  };
  // Provision the off-box wallet + register the policy with the signer. The key
  // is generated and kept there — the control plane only ever learns the address.
  if (SIGNER_URL) {
    try {
      const s = await signerApi('POST', '/v1/agents', { agentId: agent.id, policy: agent.policy, ...(agent.verified ? { verified: agent.verified } : {}), ...(agent.owner ? { owner: agent.owner } : {}) });
      agent.address = s.address;
      agent.paper = s.policy?.paper !== false;
    } catch (e) {
      log(`signer provisioning failed for ${agent.id}: ${e.message}`);
      const err = new Error(`signer unavailable: ${e.message}`); err.status = 503; throw err;
    }
  }
  store.putAgent(agent);
  log(`agent created ${agent.id} (${name})${agent.address ? ' wallet ' + agent.address : ''}`);
  return { agent };
});

r.post('/v1/agents/:id/start', (ctx) => {
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, authOwner(ctx));
  a.desired = 'running';
  if (a.state === STATE.STOPPED || a.state === STATE.FAILED) a.state = STATE.PENDING;
  schedule(a);
  store.persist();
  return { agent: a };
});

r.post('/v1/agents/:id/stop', (ctx) => {
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, authOwner(ctx));
  a.desired = 'stopped';
  a.state = a.state === STATE.RUNNING ? STATE.STOPPING : STATE.STOPPED;
  store.persist();
  return { agent: a };
});

r.delete('/v1/agents/:id', async (ctx) => {
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, authOwner(ctx));
  // Destroy the off-box wallet FIRST. The signer fails closed on a non-empty wallet
  // (key-wipe is irreversible) — so if it refuses, surface that and DON'T delete the
  // control-plane record. `?force=1` overrides (abandons any remaining funds).
  if (SIGNER_URL) {
    const q = ctx.query?.force === '1' ? '?force=1' : '';
    await signerApi('DELETE', `/v1/agents/${a.id}${q}`);
  }
  store.deleteAgent(a.id); // host drains it; orphan-stop cleans the node next beat
  log(`agent destroyed ${a.id}`);
  return { ok: true };
});

// Owner-recovery proxies → the signer (custody). The control plane never sees the key.
r.put('/v1/agents/:id/owner', async (ctx) => {
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, authOwner(ctx)); // only the CURRENT owner can hand the agent to a new owner
  // If a bundle is attached, the new owner must still satisfy the binding (publisher == owner) — else
  // the stored "publisher == owner" invariant silently breaks and the node would reject the bundle.
  assertBundleOwnerBinding(a.spec, ctx.body.owner, a.id);
  a.owner = ctx.body.owner;
  const s = await signerApi('PUT', `/v1/agents/${a.id}/owner`, { owner: ctx.body.owner });
  store.putAgent(a);
  return { agent: a, signer: s };
});
r.post('/v1/agents/:id/withdraw', async (ctx) => {
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, authOwner(ctx)); // funds go to the committed owner — only the owner may trigger it
  return signerApi('POST', `/v1/agents/${a.id}/withdraw`, { amountSol: ctx.body.amountSol }, 45000); // confirm can take ~30s
});
r.post('/v1/agents/:id/export', async (ctx) => {
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, authOwner(ctx)); // export reveals the key — owner only
  return signerApi('POST', `/v1/agents/${a.id}/export`, {});
});

r.get('/v1/agents/:id', (ctx) => {
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, authOwner(ctx));
  return { agent: a };
});

r.get('/v1/agents', (ctx) => {
  const owner = authOwner(ctx);
  // A signed caller sees only THEIR agents; unsigned (own-fleet dev) sees all.
  const all = store.listAgents().sort((a, b) => a.createdAt - b.createdAt);
  return { agents: owner ? all.filter((a) => a.owner === owner) : all };
});

r.get('/v1/agents/:id/logs', (ctx) => {
  const owner = authOwner(ctx); // authenticate first, unconditionally — even for an unknown id
  const a = store.getAgent(ctx.params.id);
  if (a) assertOwns(a, owner);
  const since = Number(ctx.query.since || 0);
  return { lines: store.getLogs(ctx.params.id, since) };
});

r.get('/v1/nodes', (ctx) => {
  auth(ctx);
  return { nodes: store.listNodes() };
});

// Admin: mark a node trusted/attested → eligible to host UNTRUSTED (oci) bundles. Operator-gated by the
// shared admin KEY (NOT a node or owner) — the trust decision comes from the attestation/probation
// system, never from the node's self-reported caps. Requires CIRCUIT_CLOUD_KEY to be set.
r.put('/v1/nodes/:id/trust', (ctx) => {
  if (!KEY) { const e = new Error('node trust requires CIRCUIT_CLOUD_KEY (admin) to be configured'); e.status = 403; throw e; }
  auth(ctx);
  const n = store.getNode(ctx.params.id);
  if (!n) throw new Error('no such node');
  n.trusted = ctx.body.trusted === true;
  store.persist?.();
  log(`node ${n.nodeId} trust = ${n.trusted}`);
  return { node: { nodeId: n.nodeId, trusted: n.trusted } };
});

// ── Shared bundle store ─────────────────────────────────────────────────────────────────────────
// The content-addressed blob backend every node pulls from (so an agent published on machine A runs
// on machine B). Bytes are content-addressed + signed, so the store is LOW-TRUST: the node re-verifies
// sha256 + manifest signature + owner-binding before a byte runs (resolveBundle in node-host). PUT is
// owner-signed (anti-abuse); GET is open (integrity is enforced downstream, not here).
r.putRaw('/v1/bundles/:name', async (ctx) => {
  const m = /^([0-9a-f]{64})\.tgz$/.exec(ctx.params.name);
  if (!m) { const e = new Error('bundle name must be <sha256>.tgz'); e.status = 400; throw e; }
  const sha = m[1];
  const ownerPath = new URL(ctx.req.url, 'http://x').pathname;
  const owner = verifyOwnerRequest({ method: 'PUT', path: ownerPath, body: {}, headers: ctx.req.headers }, { nonceStore });
  if (!owner) { const e = new Error('owner signature required to upload a bundle'); e.status = 401; throw e; }
  const buf = await readRaw(ctx.req, MAX_BUNDLE_BYTES);            // reject unauthorized BEFORE reading the body
  if (sha256hex(buf) !== sha) { const e = new Error('bytes do not match the sha256 in the path'); e.status = 400; throw e; }
  const file = path.join(BUNDLE_DIR, `${sha}.tgz`);
  if (!fs.existsSync(file)) {                                     // content-addressed → write-once, idempotent
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, buf);
    fs.renameSync(tmp, file);
    log(`bundle ${sha.slice(0, 12)} stored (${buf.length}b) by ${owner.slice(0, 8)}`);
  }
  return { ok: true, sha256: sha, bytes: buf.length };
});

r.get('/v1/bundles/:name', (ctx) => {
  const m = /^([0-9a-f]{64})\.tgz$/.exec(ctx.params.name);
  if (!m) { sendJson(ctx.res, 400, { error: 'bundle name must be <sha256>.tgz' }); return; }
  const file = path.join(BUNDLE_DIR, `${m[1]}.tgz`);
  if (!fs.existsSync(file)) { sendJson(ctx.res, 404, { error: 'bundle not found' }); return; }
  const buf = fs.readFileSync(file);
  ctx.res.writeHead(200, { 'Content-Type': 'application/gzip', 'Content-Length': buf.length });
  ctx.res.end(buf);
});

// ── Bundle GC — reference-aware mark-and-sweep ────────────────────────────────────────────────────
// A blob is "live" while any agent references its sha. Sweep blobs that are unreferenced AND older
// than a grace window (the grace covers the upload→create gap + brief redeploy churn — an in-use or
// just-uploaded bundle is never a candidate). DRY-RUN by default: set CIRCUIT_BUNDLE_GC=1 to delete.
const BUNDLE_GC_LIVE        = process.env.CIRCUIT_BUNDLE_GC === '1';
const BUNDLE_GC_GRACE_MS    = Number(process.env.CIRCUIT_BUNDLE_GC_GRACE_MS    || 24 * 3600 * 1000);
const BUNDLE_GC_INTERVAL_MS = Number(process.env.CIRCUIT_BUNDLE_GC_INTERVAL_MS || 24 * 3600 * 1000);
const BUNDLE_DISK_WARN      = Number(process.env.CIRCUIT_BUNDLE_DISK_WARN_BYTES || 5 * 1024 * 1024 * 1024);

function bundleGcSweep(doDelete = BUNDLE_GC_LIVE) {
  const report = { applied: doDelete, kept: 0, candidates: [], freedBytes: 0, totalBytes: 0 };
  let files;
  try { files = fs.readdirSync(BUNDLE_DIR); } catch { return report; }
  const live = new Set();                                          // mark — every agent's referenced sha
  for (const a of store.listAgents()) { const sha = a?.spec?.bundle?.sha256; if (sha) live.add(`${sha}.tgz`); }
  const cutoff = now() - BUNDLE_GC_GRACE_MS;
  for (const f of files) {
    const p = path.join(BUNDLE_DIR, f);
    let st; try { st = fs.statSync(p); } catch { continue; }
    if (f.endsWith('.tmp')) { if (st.mtimeMs < cutoff) { try { fs.unlinkSync(p); } catch {} } continue; } // orphaned interrupted upload
    if (!/^[0-9a-f]{64}\.tgz$/.test(f)) continue;
    report.totalBytes += st.size;
    if (live.has(f) || st.mtimeMs > cutoff) { report.kept++; continue; } // referenced or within grace → keep
    report.candidates.push({ sha: f.slice(0, 12), bytes: st.size, ageH: Math.round((now() - st.mtimeMs) / 3600000) });
    report.freedBytes += st.size;
    if (doDelete) { try { fs.unlinkSync(p); } catch (e) { log(`bundle-gc: delete ${f} failed: ${e.message}`); } }
  }
  return report;
}

function runGc(doDelete) {
  let r; try { r = bundleGcSweep(doDelete); } catch (e) { log('bundle-gc error:', e.message); return { error: e.message }; }
  if (r.candidates.length) log(`bundle-gc${r.applied ? '' : ' [dry-run]'}: ${r.candidates.length} orphan(s) ${r.applied ? 'deleted' : 'would delete'} (${(r.freedBytes / 1048576).toFixed(1)}MB) · ${r.kept} kept`);
  if (r.totalBytes > BUNDLE_DISK_WARN) log(`bundle-gc: WARNING store is ${(r.totalBytes / 1073741824).toFixed(2)}GB (> ${(BUNDLE_DISK_WARN / 1073741824).toFixed(1)}GB)`);
  return r;
}
setTimeout(() => runGc(), 60_000).unref();                         // first sweep ~1min after startup
setInterval(() => runGc(), BUNDLE_GC_INTERVAL_MS).unref();

// Admin: report what GC would do (dry-run), or ?apply=1 to delete now regardless of the env flag.
r.post('/v1/bundles/gc', (ctx) => { auth(ctx); return runGc(ctx.query.apply === '1'); });

r.listen(PORT, HOST, () => log(`control plane on http://${HOST}:${PORT}  state=${STATE_FILE}  bundles=${BUNDLE_DIR}  gc=${BUNDLE_GC_LIVE ? 'on' : 'dry-run'}  auth=${KEY ? 'on' : 'open'}`));
