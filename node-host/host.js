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
import { resolveEgressHosts } from './egress-proxy.js';
import { detectOciRuntime, buildContainerSpec, DEFAULT_OCI_IMAGE } from './oci.js';
import { loadOrCreateNodeKey, signNodeHeaders } from '../lib/node-auth.js';
import { isFirstPartyNodeRuntime } from '../lib/proto.js';

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
  // The TRUSTED bundle store this node pulls from. The node derives the pull location from this base
  // + the content sha256 — it never fetches a publisher-supplied URL (SSRF). https CDN or a local dir.
  bundleStoreBase: process.env.CIRCUIT_BUNDLE_STORE_URL || path.join(os.homedir(), '.circuit', 'bundles'),
  sandbox: process.env.SANDBOX || '', // '' → auto-detect at register() (oci if a container runtime is usable)
  // B2: the egress classes this node enables → concrete upstream hosts the proxy will allow. An
  // untrusted bundle can only reach these; everything else (and all private IPs) is denied.
  egressEndpoints: {
    signer: process.env.CIRCUIT_SIGNER_PUBLIC_URL || '',
    data: process.env.CIRCUIT_DATA_URL || '',
    inference: process.env.CIRCUIT_INFERENCE_URL || '',
    rpc: process.env.CIRCUIT_RPC_URL || '',
    jupiter: process.env.CIRCUIT_JUPITER_URL || 'https://api.jup.ag',
  },
  // The ISOLATED (--internal) docker network untrusted oci bundles run on — no route out except the
  // egress-proxy SIDECAR container. Unset → the node fails closed and refuses oci bundles.
  egressNetwork: process.env.CIRCUIT_EGRESS_NETWORK || '',
  // The external network the egress-proxy sidecar ALSO joins so IT (and only it) can reach the allowed
  // hosts. The agent never joins this — its single path out is the proxy container.
  proxyExternalNetwork: process.env.CIRCUIT_PROXY_EXTERNAL_NETWORK || 'bridge',
  // Pinned container image (digest) for the agent + the proxy sidecar.
  ociImage: process.env.CIRCUIT_OCI_IMAGE || DEFAULT_OCI_IMAGE,
  // seccomp profile path for untrusted containers ('default' = docker's default; pin a tight one in prod).
  seccompProfile: process.env.CIRCUIT_SECCOMP_PROFILE || 'default',
  // Publishers allowed to use the unsandboxed 'node' runtime. Empty = own-fleet (allow all); when set,
  // only these may run node-runtime bundles — every other publisher must ship 'oci'.
  firstPartyKeys: (process.env.CIRCUIT_FIRST_PARTY_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean),
};
let RESOLVED_SANDBOX = null; // computed once at register()

// Derive the pull location for a content hash from the node's own trusted store base. The publisher
// controls only the sha256 (hex, verified against the bytes) — never the host we connect to.
function bundleStoreUrl(sha) {
  const base = CFG.bundleStoreBase;
  return /^https?:\/\//.test(base) ? `${base.replace(/\/$/, '')}/${sha}.tgz` : path.join(base, `${sha}.tgz`);
}

const log = (...a) => console.log(`[${new Date().toISOString()}] [host]`, ...a);
const agents = new Map(); // agentId -> { proc, name, dir, logBuf, lastSent }

// Persistent node identity — signs every control-plane request so the CP can bind this nodeId to this
// key (and reject anyone else claiming it / reporting for our agents).
fs.mkdirSync(CFG.dataDir, { recursive: true });
const NODE_KEY = loadOrCreateNodeKey(path.join(CFG.dataDir, 'node.key'));

const api = async (method, p, body) => {
  const r = await fetch(CFG.controlPlane + p, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(CFG.key ? { Authorization: `Bearer ${CFG.key}` } : {}),
      ...signNodeHeaders(NODE_KEY, { method, path: p.split('?')[0], body: body ?? {} }),
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) { const e = new Error(`${p} -> ${r.status}`); e.status = r.status; throw e; }
  return r.json();
};

async function resolveWorkload(a, dir) {
  const spec = a.spec || {};
  if (a.bundle || spec.bundle) return resolveBundle(a, dir);      // B1+: a user-published bundle
  const w = spec.workload || 'agentd';
  if (w === 'circuit-agent') return { command: process.execPath, args: [path.join(CFG.circuitAgentDir, 'agent.js'), 'start'], cwd: dir };
  return { command: process.execPath, args: [path.join(REPO, 'agentd', 'agentd.js')], cwd: dir }; // reference workload
}

// B1/B2 — pull → verify (sha256 + manifest sig + owner binding) → unpack (cache by sha256) → run.
// Start the egress-proxy SIDECAR for an untrusted agent: a container on the agent's --internal network
// (so the agent reaches it by name) that ALSO joins an external bridge (so it, and ONLY it, can reach
// the allowed hosts). Runs our first-party proxy code from the repo, read-only + hardened. The agent
// never joins the external network, so its single route out is this proxy + its allowlist.
function startEgressSidecar(rt, name, allowedHosts) {
  try { execFileSync(rt, ['rm', '-f', name], { stdio: 'ignore' }); } catch {} // clear a stale sidecar
  execFileSync(rt, [
    'run', '-d', '--name', name, '--network', CFG.egressNetwork,
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp',
    '-v', `${REPO}:/proxy:ro`,
    '-e', `CIRCUIT_EGRESS_ALLOW=${allowedHosts.join(',')}`, '-e', 'CIRCUIT_PROXY_PORT=8888',
    CFG.ociImage, 'node', '/proxy/node-host/egress-proxy-main.js',
  ], { stdio: 'ignore' });
  execFileSync(rt, ['network', 'connect', CFG.proxyExternalNetwork, name], { stdio: 'ignore' }); // proxy → allowed hosts
}

// No unverified bytes ever execute. runtime 'node' (trusted): run with node under the curated env +
// cgroup + a read-only tree. runtime 'oci' (untrusted): run the SAME tree inside a hardened container
// whose ONLY egress is a dedicated egress-proxy sidecar container (above).
async function resolveBundle(a, dir) {
  const b = a.bundle;
  if (!b) throw new Error('spec.bundle set but no bundle block in the assignment');
  const runtime = b.runtime || b.manifest?.runtime || 'node';
  if (runtime !== 'node' && runtime !== 'oci') throw new Error(`unknown bundle runtime '${runtime}'`);
  if (!/^[0-9a-f]{64}$/.test(b.sha256 || '')) throw new Error('bundle sha256 is not a 64-char hex hash');
  // DEFENSE IN DEPTH: the 'node' runtime is an unsandboxed same-uid process — only safe for first-party
  // code. When the operator pins CIRCUIT_FIRST_PARTY_KEYS, refuse a node-runtime bundle from any other
  // publisher (they must use 'oci'). Don't rely solely on the scheduler having placed it correctly.
  if (runtime === 'node' && !isFirstPartyNodeRuntime(b.manifest?.publisherPubkey, CFG.firstPartyKeys)) {
    throw new Error('node-runtime bundle from a non-first-party publisher — untrusted publishers must use oci');
  }
  const cacheDir = path.join(CFG.bundleCacheDir, b.sha256);
  const okMarker = path.join(cacheDir, '.circuit-ok');
  if (!fs.existsSync(okMarker)) {
    // SSRF-safe: pull from the node's OWN trusted store base + the content hash, NOT b.url (which a
    // malicious publisher could point at an internal service or the cloud metadata endpoint).
    const isHttp = /^https?:\/\//.test(CFG.bundleStoreBase);
    const bytes = await pullBytes(bundleStoreUrl(b.sha256), { storeRoot: isHttp ? undefined : CFG.bundleStoreBase });
    const v = verifyBundle(bytes, b.manifest, { expectedOwner: a.owner || undefined, expectedAgentId: a.id });
    if (!v.ok) throw new Error(`bundle verify failed (${v.code}) for ${b.sha256.slice(0, 12)}`);
    fs.rmSync(cacheDir, { recursive: true, force: true });
    unpackTo(bytes, cacheDir);
    fs.writeFileSync(okMarker, b.sha256);
    try { execFileSync('chmod', ['-R', 'a-w', cacheDir]); } catch {} // RO rootfs (best-effort, trusted node)
    log(`bundle ${b.sha256.slice(0, 12)} pulled + verified → ${cacheDir}`);
  }
  const entryPath = path.join(cacheDir, b.manifest.entry);
  if (!fs.existsSync(entryPath)) throw new Error(`bundle entry '${b.manifest.entry}' missing after unpack`);

  if (runtime === 'oci') {
    // UNTRUSTED: run the verified tree inside a hardened container whose ONLY route out is the egress
    // proxy SIDECAR (another container). The agent joins ONLY the --internal egress network; the proxy
    // joins that network AND an external bridge, so it (and only it) reaches the allowed hosts.
    const rt = detectOciRuntime();
    if (!rt) throw new Error('node cannot run an oci (untrusted) bundle — no usable container runtime');
    // FAIL CLOSED: without the isolated network there is no boundary — refuse rather than pretend.
    if (!CFG.egressNetwork) throw new Error('refusing oci bundle — CIRCUIT_EGRESS_NETWORK (isolated, proxy-only) not configured');
    const allowedHosts = resolveEgressHosts(b.manifest.egress, CFG.egressEndpoints);
    const proxyName = `circuit-proxy-${a.id}`;
    startEgressSidecar(rt, proxyName, allowedHosts); // throws if it can't establish the controlled path
    const env = buildAgentEnv(a, '/data'); // curated (untrusted → no secrets); /data is the in-container path
    const { command, args } = buildContainerSpec({
      runtime: rt, name: `circuit-${a.id}`, bundleDir: cacheDir, dataDir: dir, entry: b.manifest.entry,
      env, network: CFG.egressNetwork, image: CFG.ociImage, proxyUrl: `http://${proxyName}:8888`,
      seccompProfile: CFG.seccompProfile, memMb: capMemMb(a),
    });
    log(`oci bundle ${b.sha256.slice(0, 12)} → ${rt}; net=${CFG.egressNetwork} sidecar=${proxyName} allow=[${allowedHosts.join(',') || 'none'}]`);
    // proxy.close() tears the sidecar container down when the agent exits.
    return { command, args, proxy: { close: () => { try { execFileSync(rt, ['rm', '-f', proxyName], { stdio: 'ignore' }); } catch {} } } };
  }
  return { command: process.execPath, args: [entryPath], cwd: cacheDir };
}

// A bundle's requested memory is a REQUEST; the operator's budget is the authority — never exceed it.
const capMemMb = (a) => Math.min(Number(a.spec?.resources?.maxMemoryMb) || CFG.maxMemoryMb, CFG.maxMemoryMb);

// Best-effort cgroup v2 cap (replaces the RSS poll where it can). Needs a writable cgroup delegation;
// where that's unavailable (shared hosts, containers) we fall back to enforceMemory(). Returns true if
// the cgroup was applied.
function applyCgroup(pid, a) {
  try {
    const base = '/sys/fs/cgroup';
    if (!fs.existsSync(path.join(base, 'cgroup.controllers'))) return false; // not cgroup v2
    const cg = path.join(base, 'circuit-host', String(a.id));
    fs.mkdirSync(cg, { recursive: true });
    fs.writeFileSync(path.join(cg, 'memory.max'), String(capMemMb(a) * 1024 * 1024)); // capped to operator budget

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
  const { command, args, cwd, proxy } = resolved; // proxy: the per-agent egress proxy for an oci bundle

  // SECURITY: never hand the workload the operator's whole process.env (it may hold the operator's
  // own keys/tokens). buildAgentEnv returns a curated allowlist — process minimum + the off-box
  // session token (never the signing key) + only what this trust level needs. See node-host/env.js.
  // (For an oci bundle the env is built inside the container spec; here it's only used by node runtimes.)
  const env = buildAgentEnv(a, dir);
  const proc = spawn(command, args, { cwd: cwd || dir, env, stdio: ['ignore', 'pipe', 'pipe'] });
  const cgrouped = applyCgroup(proc.pid, a);
  const rec = { proc, proxy, name: a.name, workload: (a.bundle || a.spec?.bundle) ? `bundle:${resolved.proxy ? 'oci' : 'node'}` : (a.spec?.workload || 'agentd'), dir, cgrouped, logBuf: [], lastSent: 0, startedAt: Date.now() };
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
    try { rec.proxy?.close(); } catch {} // tear down the per-agent egress proxy
    agents.delete(a.id); // reconcile loop will restart if still desired (built-in backoff = next beat)
  });
  log(`started ${a.id} (${a.name}) workload=${rec.workload}${cgrouped ? ' [cgroup]' : ''} dir=${dir}`);
}

function stopAgent(id) {
  const rec = agents.get(id);
  if (!rec) return;
  log(`stopping ${id}`);
  try { rec.proc.kill('SIGTERM'); } catch {}
  try { rec.proxy?.close(); } catch {} // tear down the per-agent egress proxy
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

// What isolation can this node actually enforce? Honest auto-detect: 'oci' only if a container runtime
// is usable (so the scheduler never hands us an untrusted bundle we can't contain); else 'node'. The
// operator can pin it via SANDBOX=none|node|oci.
function resolveSandbox() {
  if (RESOLVED_SANDBOX) return RESOLVED_SANDBOX;
  RESOLVED_SANDBOX = CFG.sandbox || (detectOciRuntime() ? 'oci' : 'node');
  return RESOLVED_SANDBOX;
}

async function register() {
  const sandbox = resolveSandbox();
  await api('POST', '/v1/nodes/register', {
    nodeId: CFG.nodeId,
    caps: { cpu: CFG.maxCpu, sandbox },
    budget: { maxAgents: CFG.maxAgents, maxCpu: CFG.maxCpu, maxMemoryMb: CFG.maxMemoryMb },
  });
  log(`registered as ${CFG.nodeId} (budget ${CFG.maxAgents} agents, ${CFG.maxMemoryMb}MB, sandbox=${sandbox})`);
}

async function beat() {
  let res;
  try {
    res = await api('POST', '/v1/nodes/heartbeat', { nodeId: CFG.nodeId, running: [...agents.keys()], usage: { agents: agents.size } });
  } catch (e) {
    if (e.status === 409) { await register().catch(() => {}); return; } // plane forgot us
    log(`heartbeat failed: ${e.message}`); return;
  }
  // Start assignments SEQUENTIALLY: startAgent checks the budget then registers the agent after an
  // await, so firing them concurrently lets several pass the check before any claims a slot — the node
  // then runs over budget (e.g. 4 agents on a budget-2 node). Awaiting each makes the budget authoritative.
  for (const as of res.assignments || []) {
    if (as.action === 'start') await startAgent(as.agent).catch((e) => log(`startAgent ${as.agent?.id} failed: ${e.message}`));
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
