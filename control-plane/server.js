#!/usr/bin/env node
// Circuit Agent Cloud — Control Plane.
// Stateless API over an in-memory+JSON store. Nodes POLL it (heartbeat), so
// hosts need no inbound connectivity. The CLI drives agents through it.
import os from 'node:os';
import path from 'node:path';
import { Router, sendJson } from '../lib/http.js';
import { Store } from '../lib/store.js';
import { STATE, nodeSatisfies, newId, now } from '../lib/proto.js';

const PORT = Number(process.env.PORT || 18980);
const HOST = process.env.HOST || '127.0.0.1';
const STATE_FILE = process.env.CIRCUIT_CLOUD_STATE || path.join(os.homedir(), '.circuit-cloud', 'state.json');
const NODE_TIMEOUT_MS = Number(process.env.NODE_TIMEOUT_MS || 30000);
const KEY = process.env.CIRCUIT_CLOUD_KEY || ''; // optional shared bearer

const store = new Store(STATE_FILE);

const log = (...a) => console.log(`[${new Date().toISOString()}] [cp]`, ...a);

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
  const { nodeId, caps = {}, budget = {}, custodyMax } = ctx.body;
  if (!nodeId) throw new Error('nodeId required');
  const node = store.upsertNode({
    nodeId,
    caps,
    budget,
    custodyMax: custodyMax ?? 3,
    status: 'up',
    lastSeen: now(),
    registeredAt: store.getNode(nodeId)?.registeredAt || now(),
  });
  log(`node ${nodeId} registered — budget=${JSON.stringify(budget)} tee=${!!caps.tee}`);
  return { ok: true, node: { nodeId: node.nodeId } };
});

// Heartbeat: node reports what it's running; gets back start/stop assignments.
r.post('/v1/nodes/heartbeat', (ctx) => {
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
      assignments.push({ action: 'start', agent: { id: a.id, name: a.name, spec: a.spec } });
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
r.post('/v1/agents', (ctx) => {
  auth(ctx);
  const { name, owner, spec = {}, custodyTier = 'key-on-node' } = ctx.body;
  if (!name) throw new Error('name required');
  const agent = {
    id: newId('agt'),
    name,
    owner: owner || null,
    spec,
    custodyTier,
    desired: 'stopped',
    state: STATE.PENDING,
    nodeId: null,
    health: null,
    createdAt: now(),
  };
  store.putAgent(agent);
  log(`agent created ${agent.id} (${name})`);
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

r.delete('/v1/agents/:id', (ctx) => {
  auth(ctx);
  const a = store.getAgent(ctx.params.id);
  if (!a) throw new Error('no such agent');
  // Mark stopped so the host drains it; orphan-stop cleans the node next beat.
  store.deleteAgent(a.id);
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
