#!/usr/bin/env node
// Circuit Agent Cloud — Control Plane.
// Stateless API over an in-memory+JSON store. Nodes POLL it (heartbeat), so
// hosts need no inbound connectivity. The CLI drives agents through it.
import os from 'node:os';
import path from 'node:path';
import { Router, sendJson } from '../lib/http.js';
import { Store } from '../lib/store.js';
import { STATE, nodeSatisfies, normalizePolicy, normalizeVerified, newId, now } from '../lib/proto.js';

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

async function signerApi(method, p, body) {
  const r = await fetch(SIGNER_URL + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...(SIGNER_KEY ? { Authorization: `Bearer ${SIGNER_KEY}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) { const e = new Error(`signer ${p} -> ${r.status}`); e.status = r.status; throw e; }
  return r.json();
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

function auth(ctx) {
  if (!KEY) return; // open in dev / localhost
  const got = (ctx.req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (got !== KEY) { const e = new Error('unauthorized'); e.status = 401; throw e; }
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
  const node = store.upsertNode({
    nodeId,
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
      assignments.push({ action: 'start', agent: { id: a.id, name: a.name, spec: a.spec, signer: signerBlockFor(a) } });
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
  const agent = {
    id: newId('agt'),
    name,
    owner: owner || null,
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
      const s = await signerApi('POST', '/v1/agents', { agentId: agent.id, policy: agent.policy, ...(agent.verified ? { verified: agent.verified } : {}) });
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
  a.desired = 'stopped';
  a.state = a.state === STATE.RUNNING ? STATE.STOPPING : STATE.STOPPED;
  store.persist();
  return { agent: a };
});

r.delete('/v1/agents/:id', async (ctx) => {
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  // Mark stopped so the host drains it; orphan-stop cleans the node next beat.
  store.deleteAgent(a.id);
  if (SIGNER_URL) await signerApi('DELETE', `/v1/agents/${a.id}`).catch((e) => log(`signer wipe failed ${a.id}: ${e.message}`));
  log(`agent destroyed ${a.id}`);
  return { ok: true };
});

r.get('/v1/agents/:id', (ctx) => {
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  return { agent: a };
});

r.get('/v1/agents', (ctx) => {
  auth(ctx);
  return { agents: store.listAgents().sort((a, b) => a.createdAt - b.createdAt) };
});

r.get('/v1/agents/:id/logs', (ctx) => {
  auth(ctx);
  const since = Number(ctx.query.since || 0);
  return { lines: store.getLogs(ctx.params.id, since) };
});

r.get('/v1/nodes', (ctx) => {
  auth(ctx);
  return { nodes: store.listNodes() };
});

r.listen(PORT, HOST, () => log(`control plane on http://${HOST}:${PORT}  state=${STATE_FILE}  auth=${KEY ? 'on' : 'open'}`));
