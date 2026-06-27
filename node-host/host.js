#!/usr/bin/env node
// Circuit Agent Cloud — node-host runner.
// Opt-in. The operator declares a resource budget; this registers with the
// control plane, runs the agents it's assigned (curated env + resource budget;
// fuller sandboxing is staged — see docs/AGENT_BUNDLES.md), and forwards health
// + logs. It only ever POLLS out — no inbound port needed.
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildAgentEnv } from './env.js';
import { verifyBundle, unpackTo } from '../lib/bundle.js';
import { pullBytes } from '../lib/bundle-store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..');

// ── Operator budget (the opt-in controls) ────────────────────────────────────
const CFG = {
  controlPlane: process.env.CONTROL_PLANE || 'http://127.0.0.1:18980',
  nodeId: process.env.NODE_ID || `node-${os.hostname()}`,
  maxAgents: Number(process.env.MAX_AGENTS || 5),
  maxCpu: Number(process.env.MAX_CPU || 1.0),
  maxMemoryMb: Number(process.env.MAX_MEMORY_MB || 512),
  dataDir: process.env.HOST_DATA_DIR || path.join(os.homedir(), '.circuit-host'),
  key: process.env.CIRCUIT_CLOUD_KEY || '',
  heartbeatMs: Number(process.env.HEARTBEAT_MS || 8000),
  circuitAgentDir: process.env.CIRCUIT_AGENT_DIR || path.join(os.homedir(), 'circuit-agent'),
  // B1+: where verified bundles are unpacked (cached by sha256), and what isolation this node can
  // enforce — 'node' = curated-env + cgroup + RO-bind (trusted bundles), 'oci' = container (B2),
  // 'none' = built-in workloads only. The scheduler won't place a bundle a node can't sandbox.
  bundleCacheDir: process.env.BUNDLE_CACHE_DIR || path.join(process.env.HOST_DATA_DIR || path.join(os.homedir(), '.circuit-host'), 'bundles'),
  sandbox: process.env.SANDBOX || 'node',
};

const log = (...a) => console.log(`[${new Date().toISOString()}] [host]`, ...a);
const agents = new Map(); // agentId -> { proc, name, dir, logBuf, lastSent }

const api = async (method, p, body) => {
  const r = await fetch(CFG.controlPlane + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...(CFG.key ? { Authorization: `Bearer ${CFG.key}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) { const e = new Error(`${p} -> ${r.status}`); e.status = r.status; throw e; }
  return r.json();
};

async function resolveWorkload(a, dir) {
  const spec = a.spec || {};
  if (a.bundle || spec.bundle) return resolveBundle(a);           // B1+: a user-published bundle
  const w = spec.workload || 'agentd';
  if (w === 'circuit-agent') return { command: process.execPath, args: [path.join(CFG.circuitAgentDir, 'agent.js'), 'start'], cwd: dir };
  return { command: process.execPath, args: [path.join(REPO, 'agentd', 'agentd.js')], cwd: dir }; // reference workload
}

// B1 — pull → verify (sha256 + manifest sig + owner binding) → unpack (cache by sha256) → run with
// node. No unverified bytes ever execute; the unpacked tree is made read-only (best-effort) so the
// agent writes only to its CIRCUIT_AGENT_DATA_DIR. Real isolation (ns/seccomp) is B2.
async function resolveBundle(a) {
  const b = a.bundle;
  if (!b) throw new Error('spec.bundle set but no bundle block in the assignment');
  if (b.runtime !== 'node') throw new Error(`this node runs 'node' bundles only (got '${b.runtime}')`);
  const cacheDir = path.join(CFG.bundleCacheDir, b.sha256);
  const okMarker = path.join(cacheDir, '.circuit-ok');
  if (!fs.existsSync(okMarker)) {
    const bytes = await pullBytes(b.url);
    const v = verifyBundle(bytes, b.manifest, { expectedOwner: a.owner || undefined });
    if (!v.ok) throw new Error(`bundle verify failed (${v.code}) for ${b.sha256.slice(0, 12)}`);
    fs.rmSync(cacheDir, { recursive: true, force: true });
    unpackTo(bytes, cacheDir);
    fs.writeFileSync(okMarker, b.sha256);
    try { execFileSync('chmod', ['-R', 'a-w', cacheDir]); } catch {} // RO rootfs (best-effort, trusted node)
    log(`bundle ${b.sha256.slice(0, 12)} pulled + verified → ${cacheDir}`);
  }
  const entryPath = path.join(cacheDir, b.manifest.entry);
  if (!fs.existsSync(entryPath)) throw new Error(`bundle entry '${b.manifest.entry}' missing after unpack`);
  return { command: process.execPath, args: [entryPath], cwd: cacheDir };
}

// Best-effort cgroup v2 cap (replaces the RSS poll where it can). Needs a writable cgroup delegation;
// where that's unavailable (shared hosts, containers) we fall back to enforceMemory(). Returns true if
// the cgroup was applied.
function applyCgroup(pid, a) {
  try {
    const base = '/sys/fs/cgroup';
    if (!fs.existsSync(path.join(base, 'cgroup.controllers'))) return false; // not cgroup v2
    const cg = path.join(base, 'circuit-host', String(a.id));
    fs.mkdirSync(cg, { recursive: true });
    const memMb = a.spec?.resources?.maxMemoryMb || CFG.maxMemoryMb;
    fs.writeFileSync(path.join(cg, 'memory.max'), String(memMb * 1024 * 1024));
    fs.writeFileSync(path.join(cg, 'cgroup.procs'), String(pid));
    return true;
  } catch {
    return false; // enforceMemory() remains the safety net
  }
}

async function startAgent(a) {
  if (agents.has(a.id)) return;
  if (agents.size >= CFG.maxAgents) { log(`refusing ${a.id} — at budget (${CFG.maxAgents})`); return; }
  const dir = path.join(CFG.dataDir, 'agents', a.id);
  fs.mkdirSync(dir, { recursive: true });
  fs.mkdirSync(path.join(dir, 'tmp'), { recursive: true });
  try { fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(a.spec?.config || {})); } catch {}

  let resolved;
  try { resolved = await resolveWorkload(a, dir); }
  catch (e) { log(`agent ${a.id} workload resolve failed: ${e.message}`); return; }
  const { command, args, cwd } = resolved;

  // SECURITY: never hand the workload the operator's whole process.env (it may hold the operator's
  // own keys/tokens). buildAgentEnv returns a curated allowlist — process minimum + the off-box
  // session token (never the signing key) + only what this trust level needs. See node-host/env.js.
  const env = buildAgentEnv(a, dir);
  const proc = spawn(command, args, { cwd: cwd || dir, env, stdio: ['ignore', 'pipe', 'pipe'] });
  const cgrouped = applyCgroup(proc.pid, a);
  const rec = { proc, name: a.name, workload: a.spec?.bundle ? 'bundle' : (a.spec?.workload || 'agentd'), dir, cgrouped, logBuf: [], lastSent: 0, startedAt: Date.now() };
  agents.set(a.id, rec);

  const onData = (buf) => {
    for (const line of buf.toString().split('\n')) {
      if (!line.trim()) continue;
      rec.logBuf.push({ ts: Date.now(), line });
      if (rec.logBuf.length > 300) rec.logBuf.shift();
    }
  };
  proc.stdout.on('data', onData);
  proc.stderr.on('data', onData);
  proc.on('exit', (code, sig) => {
    log(`agent ${a.id} exited code=${code} sig=${sig}`);
    agents.delete(a.id); // reconcile loop will restart if still desired (built-in backoff = next beat)
  });
  log(`started ${a.id} (${a.name}) workload=${rec.workload}${cgrouped ? ' [cgroup]' : ''} dir=${dir}`);
}

function stopAgent(id) {
  const rec = agents.get(id);
  if (!rec) return;
  log(`stopping ${id}`);
  try { rec.proc.kill('SIGTERM'); } catch {}
  const t = setTimeout(() => { try { rec.proc.kill('SIGKILL'); } catch {} }, 8000);
  rec.proc.once('exit', () => clearTimeout(t));
  agents.delete(id);
}

// Best-effort memory cap (Linux): kill an agent that blows past maxMemoryMb.
function enforceMemory() {
  for (const [id, rec] of agents) {
    try {
      const status = fs.readFileSync(`/proc/${rec.proc.pid}/status`, 'utf8');
      const m = status.match(/VmRSS:\s+(\d+)\s+kB/);
      if (m && Number(m[1]) / 1024 > CFG.maxMemoryMb) {
        log(`agent ${id} over memory budget (${Math.round(m[1] / 1024)}MB > ${CFG.maxMemoryMb}) — killing`);
        stopAgent(id);
      }
    } catch {}
  }
}

function readHealth(rec) {
  try { return JSON.parse(fs.readFileSync(path.join(rec.dir, 'heartbeat.json'), 'utf8')); } catch { return null; }
}

// Write a local snapshot so a co-located dashboard (e.g. circuit-node-client) can
// show this node's agent-cloud contribution without reaching the control plane.
function writeStatus() {
  try {
    const snapshot = {
      nodeId: CFG.nodeId,
      controlPlane: CFG.controlPlane,
      budget: { maxAgents: CFG.maxAgents, maxMemoryMb: CFG.maxMemoryMb },
      agents: [...agents.entries()].map(([id, rec]) => ({
        id, name: rec.name, workload: rec.workload, startedAt: rec.startedAt, health: readHealth(rec),
      })),
      updatedAt: Date.now(),
    };
    const f = path.join(CFG.dataDir, 'status.json');
    fs.writeFileSync(f + '.tmp', JSON.stringify(snapshot));
    fs.renameSync(f + '.tmp', f);
  } catch {}
}

async function register() {
  await api('POST', '/v1/nodes/register', {
    nodeId: CFG.nodeId,
    caps: { cpu: CFG.maxCpu, sandbox: CFG.sandbox },
    budget: { maxAgents: CFG.maxAgents, maxCpu: CFG.maxCpu, maxMemoryMb: CFG.maxMemoryMb },
  });
  log(`registered as ${CFG.nodeId} (budget ${CFG.maxAgents} agents, ${CFG.maxMemoryMb}MB)`);
}

async function beat() {
  let res;
  try {
    res = await api('POST', '/v1/nodes/heartbeat', { nodeId: CFG.nodeId, running: [...agents.keys()], usage: { agents: agents.size } });
  } catch (e) {
    if (e.status === 409) { await register().catch(() => {}); return; } // plane forgot us
    log(`heartbeat failed: ${e.message}`); return;
  }
  for (const as of res.assignments || []) {
    if (as.action === 'start') startAgent(as.agent).catch((e) => log(`startAgent ${as.agent?.id} failed: ${e.message}`));
    else if (as.action === 'stop') stopAgent(as.agentId);
  }
  enforceMemory();
  // forward health + new logs per running agent
  for (const [id, rec] of agents) {
    const health = readHealth(rec);
    const lines = rec.logBuf.filter((l) => l.ts > rec.lastSent);
    rec.lastSent = Date.now();
    api('POST', `/v1/agents/${id}/report`, { health, lines }).catch(() => {});
  }
  writeStatus();
}

async function shutdown() {
  log('draining agents…');
  for (const id of [...agents.keys()]) stopAgent(id);
  writeStatus(); // reflect the drained state for a co-located dashboard
  setTimeout(() => process.exit(0), 2000);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

(async () => {
  fs.mkdirSync(CFG.dataDir, { recursive: true });
  log(`node-host starting → control plane ${CFG.controlPlane}`);
  while (true) {
    try { await register(); break; } catch (e) { log(`register failed (${e.message}); retrying in 5s`); await new Promise((r) => setTimeout(r, 5000)); }
  }
  await beat();
  setInterval(beat, CFG.heartbeatMs);
})();
