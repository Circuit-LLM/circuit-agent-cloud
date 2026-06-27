#!/usr/bin/env node
// Circuit Agent Cloud — Control Plane.
// Stateless API over an in-memory+JSON store. Nodes POLL it (heartbeat), so
// hosts need no inbound connectivity. The CLI drives agents through it.
import os from 'node:os';
import path from 'node:path';
import { Router, sendJson } from '../lib/http.js';
import { Store } from '../lib/store.js';
import { STATE, nodeSatisfies, normalizePolicy, normalizeVerified, newId, now } from '../lib/proto.js';
import { verifyManifest } from '../lib/bundle.js';
import { verifyOwnerRequest, NonceStore } from '../lib/owner-auth.js';
import { verifyNodeRequest } from '../lib/node-auth.js';

const PORT = Number(process.env.PORT || 18980);
const HOST = process.env.HOST || '127.0.0.1';
const STATE_FILE = process.env.CIRCUIT_CLOUD_STATE || path.join(os.homedir(), '.circuit-cloud', 'state.json');
const NODE_TIMEOUT_MS = Number(process.env.NODE_TIMEOUT_MS || 30000);
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

const countAssigned = (nodeId) =>
  store.listAgents((a) => a.nodeId === nodeId && a.desired === 'running').length;

// Place an agent on the best live node that satisfies its custody/confidential needs.
function schedule(agent) {
  if (agent.desired !== 'running') return;
  if (agent.nodeId) {
    const n = store.getNode(agent.nodeId);
    if (n && n.status === 'up') return; // already placed on a live node
  }
  const candidates = store
    .listNodes()
    .filter((n) => n.status === 'up' && nodeSatisfies(n, agent))
    .map((n) => ({ n, free: (n.budget?.maxAgents ?? 0) - countAssigned(n.nodeId) }))
    .filter((x) => x.free > 0)
    .sort((a, b) => b.free - a.free); // spread load
  if (!candidates.length) {
    agent.nodeId = null;
    agent.state = STATE.PENDING;
    return;
  }
  agent.nodeId = candidates[0].n.nodeId;
  agent.state = STATE.SCHEDULED;
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
  for (const a of store.listAgents((a) => a.desired === 'running' && (!a.nodeId || a.state === STATE.PENDING || a.state === STATE.FAILED))) {
    schedule(a);
    changed = true;
  }
  if (changed) store.persist();
}, 5000).unref?.();

// ── API ───────────────────────────────────────────────────────────────────────
const r = new Router();

r.get('/health', () => ({ ok: true, service: 'circuit-control-plane', nodes: store.nodes.size, agents: store.agents.size }));

// Operator node registers + declares its resource budget.
r.post('/v1/nodes/register', (ctx) => {
  auth(ctx);
  const { nodeId, caps = {}, budget = {} } = ctx.body;
  if (!nodeId) throw new Error('nodeId required');
  const authedNode = requireNode(ctx);
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
  auth(ctx);
  const { nodeId, running = [], usage = {} } = ctx.body;
  assertNodeIdentity(nodeId, requireNode(ctx)); // only the node that owns this id may heartbeat as it
  const node = store.getNode(nodeId);
  if (!node) { const e = new Error('unknown node — register first'); e.status = 409; throw e; }
  node.status = 'up';
  node.lastSeen = now();
  node.usage = usage;

  const assignments = [];
  // Reconcile agents this node owns.
  for (const a of store.listAgents((a) => a.nodeId === nodeId)) {
    const isRunning = running.includes(a.id);
    if (a.desired === 'running' && !isRunning) {
      await ensureSession(a); // (re)open the lease for this placement — the fence
      assignments.push({ action: 'start', agent: { id: a.id, name: a.name, owner: a.owner, spec: a.spec, bundle: bundleBlockFor(a), signer: signerBlockFor(a) } });
    } else if (a.desired === 'running' && isRunning) {
      a.state = STATE.RUNNING;
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
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  // Only the node actually running this agent may report its health/logs (no cross-node poisoning).
  const authedNode = requireNode(ctx);
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
  auth(ctx);
  const { name, owner, spec = {}, policy, verified } = ctx.body;
  if (!name) throw new Error('name required');
  // The agent's owner is the authenticated signer (multi-tenant) — the body's owner is only a fallback
  // in own-fleet dev. A user can only ever create agents owned by themselves.
  const authedOwner = requireOwner(ctx);
  const agentOwner = authedOwner || owner || null;
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
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, requireOwner(ctx));
  a.desired = 'running';
  if (a.state === STATE.STOPPED || a.state === STATE.FAILED) a.state = STATE.PENDING;
  schedule(a);
  store.persist();
  return { agent: a };
});

r.post('/v1/agents/:id/stop', (ctx) => {
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, requireOwner(ctx));
  a.desired = 'stopped';
  a.state = a.state === STATE.RUNNING ? STATE.STOPPING : STATE.STOPPED;
  store.persist();
  return { agent: a };
});

r.delete('/v1/agents/:id', async (ctx) => {
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, requireOwner(ctx));
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
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, requireOwner(ctx)); // only the CURRENT owner can hand the agent to a new owner
  // If a bundle is attached, the new owner must still satisfy the binding (publisher == owner) — else
  // the stored "publisher == owner" invariant silently breaks and the node would reject the bundle.
  assertBundleOwnerBinding(a.spec, ctx.body.owner, a.id);
  a.owner = ctx.body.owner;
  const s = await signerApi('PUT', `/v1/agents/${a.id}/owner`, { owner: ctx.body.owner });
  store.putAgent(a);
  return { agent: a, signer: s };
});
r.post('/v1/agents/:id/withdraw', async (ctx) => {
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, requireOwner(ctx)); // funds go to the committed owner — only the owner may trigger it
  return signerApi('POST', `/v1/agents/${a.id}/withdraw`, { amountSol: ctx.body.amountSol }, 45000); // confirm can take ~30s
});
r.post('/v1/agents/:id/export', async (ctx) => {
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, requireOwner(ctx)); // export reveals the key — owner only
  return signerApi('POST', `/v1/agents/${a.id}/export`, {});
});

r.get('/v1/agents/:id', (ctx) => {
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  assertOwns(a, requireOwner(ctx));
  return { agent: a };
});

r.get('/v1/agents', (ctx) => {
  auth(ctx);
  const owner = requireOwner(ctx);
  // A signed caller sees only THEIR agents; unsigned (own-fleet dev) sees all.
  const all = store.listAgents().sort((a, b) => a.createdAt - b.createdAt);
  return { agents: owner ? all.filter((a) => a.owner === owner) : all };
});

r.get('/v1/agents/:id/logs', (ctx) => {
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (a) assertOwns(a, requireOwner(ctx));
  const since = Number(ctx.query.since || 0);
  return { lines: store.getLogs(ctx.params.id, since) };
});

r.get('/v1/nodes', (ctx) => {
  auth(ctx);
  return { nodes: store.listNodes() };
});

r.listen(PORT, HOST, () => log(`control plane on http://${HOST}:${PORT}  state=${STATE_FILE}  auth=${KEY ? 'on' : 'open'}`));
