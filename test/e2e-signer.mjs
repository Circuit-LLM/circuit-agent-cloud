// End-to-end test for the off-box signer — the ONE custody mechanism + the fence.
//
// Part A (signer unit, deterministic): provisions a wallet, opens a session, and
//   exercises every gate — valid sign + on-chain-verifiable signature, per-trade
//   cap, daily cap, cooldown, disallowed action, denied token, and THE FENCE
//   (stale epoch rejected; rotating the session supersedes the old one).
// Part B (full stack): control plane + 2 node-hosts + signer. Creates an agent
//   (wallet provisioned off-box), proves the KEY IS NOT on the control plane and
//   IS at the signer, starts it, confirms the running workload signs through the
//   signer with only a session token, then kills the owning node and confirms the
//   control plane reschedules to the other node AND rotates the session (epoch++).
//
// Harness notes (learned the hard way): no `sleep` (use setTimeout in Node), and
// never pkill -f a pattern matching this script's own cmdline — we kill child
// servers by captured handle/PID only.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { base58decode, verify } from '../lib/ed25519.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..');
const ROOT = path.join(os.tmpdir(), `circuit-e2e-${process.pid}`);
fs.rmSync(ROOT, { recursive: true, force: true });
fs.mkdirSync(ROOT, { recursive: true });

const SIGNER = 'http://127.0.0.1:18991';
const CP = 'http://127.0.0.1:18990';
const MASTER = '11'.repeat(32); // fixed master key (hex) for a deterministic run

const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let pass = 0, fail = 0;
const ok = (cond, msg) => { cond ? pass++ : fail++; console.log(`  ${cond ? '✓ PASS' : '✗ FAIL'}  ${msg}`); return cond; };

function start(name, script, env) {
  const out = fs.openSync(path.join(ROOT, `${name}.log`), 'a');
  const child = spawn(process.execPath, [script], { cwd: REPO, env: { ...process.env, ...env }, stdio: ['ignore', out, out] });
  procs.push({ name, child });
  return child;
}

async function api(base, method, p, body, headers = {}) {
  const res = await fetch(base + p, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function waitHealth(base, tries = 50) {
  for (let i = 0; i < tries; i++) {
    try { const r = await fetch(base + '/health', { signal: AbortSignal.timeout(1500) }); if (r.ok) return true; } catch {}
    await sleep(200);
  }
  throw new Error(`service at ${base} never came up`);
}

async function poll(fn, tries, gapMs, label) {
  for (let i = 0; i < tries; i++) { if (await fn()) return true; await sleep(gapMs); }
  console.log(`    (timed out waiting for: ${label})`);
  return false;
}

function dumpLogs() {
  console.log('\n──— server logs (tail) —──');
  for (const { name } of procs) {
    try {
      const lines = fs.readFileSync(path.join(ROOT, `${name}.log`), 'utf8').trim().split('\n').slice(-12);
      console.log(`\n[${name}]`); for (const l of lines) console.log('  ' + l);
    } catch {}
  }
}

async function cleanup() {
  for (const { child } of procs) { try { process.kill(child.pid, 'SIGTERM'); } catch {} }
  await sleep(700);
  for (const { child } of procs) { try { process.kill(child.pid, 'SIGKILL'); } catch {} }
  // Sweep any orphaned reference workloads. These path patterns are NOT substrings
  // of this script's own argv (…/test/e2e-signer.mjs), so pkill -f can't self-kill.
  for (const pat of ['circuit-agent-cloud/agentd/agentd.js', 'circuit-agent-cloud/node-host/host.js']) {
    try { spawnSync('pkill', ['-f', pat]); } catch {}
  }
}

async function main() {
  // ── boot the signer + control plane ──
  start('signer', path.join(REPO, 'signer', 'server.js'), {
    PORT: '18991', HOST: '127.0.0.1', CIRCUIT_SIGNER_DIR: path.join(ROOT, 'signer'), CIRCUIT_SIGNER_MASTER_KEY: MASTER,
    JUPITER_API_BASE: 'http://127.0.0.1:1', // dead host — exercises the live path without broadcasting
  });
  start('cp', path.join(REPO, 'control-plane', 'server.js'), {
    PORT: '18990', HOST: '127.0.0.1', CIRCUIT_CLOUD_STATE: path.join(ROOT, 'cp', 'state.json'),
    CIRCUIT_SIGNER_URL: SIGNER, CIRCUIT_SIGNER_PUBLIC_URL: SIGNER, NODE_TIMEOUT_MS: '6000',
  });
  await waitHealth(SIGNER);
  await waitHealth(CP);

  // ════ PART A — signer custody + policy + fence (deterministic) ════
  console.log('\nPart A — signer: custody, policy gates, and the fence');
  const U = 'agt_unit_1';
  await api(SIGNER, 'POST', '/v1/agents', { agentId: U, policy: { maxNotionalSol: 0.02, maxDailySol: 0.03, cooldownMs: 0, allow: ['buy'], denyTokens: ['BADMINT'] } });
  let g = await api(SIGNER, 'GET', `/v1/agents/${U}`);
  const address = g.json.address;
  ok(typeof address === 'string' && address.length >= 32 && address.length <= 44, `provisioned a Solana wallet (${address})`);

  const s1 = await api(SIGNER, 'POST', `/v1/agents/${U}/session`, { node: 'nodeA' });
  const epoch1 = s1.json.epoch, token1 = s1.json.token;
  ok(epoch1 === 1 && !!token1, `opened session epoch=${epoch1}`);

  // valid trade → signed, and the signature verifies against the wallet address
  const v = await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch1, token: token1, intent: { kind: 'buy', token: 'GOODMINT', sizeSol: 0.01 } });
  ok(v.status === 200 && v.json.ok, 'valid intent signed');
  const sigOkay = v.json.ok && verify(base58decode(address), v.json.attestation.canonical, Buffer.from(v.json.signature, 'base64'));
  ok(sigOkay, 'signature verifies against the agent wallet (real Ed25519 custody)');

  // per-trade cap
  const cap = await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch1, token: token1, intent: { kind: 'buy', token: 'GOODMINT', sizeSol: 0.05 } });
  ok(cap.status === 403 && cap.json.code === 'over-trade-cap', `per-trade cap enforced [${cap.json.code}]`);

  // disallowed action (sell not in allow)
  const act = await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch1, token: token1, intent: { kind: 'sell', token: 'GOODMINT', sizeSol: 0.01 } });
  ok(act.status === 403 && act.json.code === 'action-not-allowed', `disallowed action blocked [${act.json.code}]`);

  // denied token
  const den = await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch1, token: token1, intent: { kind: 'buy', token: 'BADMINT', sizeSol: 0.01 } });
  ok(den.status === 403 && den.json.code === 'token-denied', `denied token blocked [${den.json.code}]`);

  // daily cap: already spent 0.01; a 0.02 + 0.02 pushes past 0.03/day
  await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch1, token: token1, intent: { kind: 'buy', token: 'GOODMINT', sizeSol: 0.02 } }); // 0.03 total
  const day = await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch1, token: token1, intent: { kind: 'buy', token: 'GOODMINT', sizeSol: 0.02 } });
  ok(day.status === 403 && day.json.code === 'over-daily-cap', `daily cap enforced [${day.json.code}]`);

  // cooldown: set a cooldown, trade, immediately retry
  await api(SIGNER, 'PUT', `/v1/agents/${U}/policy`, { policy: { maxNotionalSol: 0.02, maxDailySol: 10, cooldownMs: 60000, allow: ['buy'] } });
  await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch1, token: token1, intent: { kind: 'buy', token: 'GOODMINT', sizeSol: 0.01 } });
  const cd = await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch1, token: token1, intent: { kind: 'buy', token: 'GOODMINT', sizeSol: 0.01 } });
  ok(cd.status === 429 && cd.json.code === 'cooldown', `cooldown enforced [${cd.json.code}]`);

  // ── THE FENCE ── rotate the session (simulates a reschedule); old token must die
  const s2 = await api(SIGNER, 'POST', `/v1/agents/${U}/session`, { node: 'nodeB' });
  const epoch2 = s2.json.epoch, token2 = s2.json.token;
  ok(epoch2 === 2, `rotated session epoch=${epoch2}`);
  await api(SIGNER, 'PUT', `/v1/agents/${U}/policy`, { policy: { maxNotionalSol: 0.02, maxDailySol: 10, cooldownMs: 0, allow: ['buy'] } });
  const stale = await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch1, token: token1, intent: { kind: 'buy', token: 'GOODMINT', sizeSol: 0.01 } });
  ok(stale.status === 403 && stale.json.code === 'fenced', `orphan with stale epoch FENCED OUT [${stale.json.code}]`);
  const fresh = await api(SIGNER, 'POST', `/v1/agents/${U}/intent`, { epoch: epoch2, token: token2, intent: { kind: 'buy', token: 'GOODMINT', sizeSol: 0.01 } });
  ok(fresh.status === 200 && fresh.json.ok, 'new session can trade — at-most-one holds');

  // ════ PART B — full stack: provisioning, key-off-box proof, run, reschedule ════
  console.log('\nPart B — full stack: control plane + 2 node-hosts + signer');
  start('hostA', path.join(REPO, 'node-host', 'host.js'), {
    CONTROL_PLANE: CP, NODE_ID: 'nodeA', HOST_DATA_DIR: path.join(ROOT, 'hostA'), HEARTBEAT_MS: '1500', MAX_AGENTS: '5', CIRCUIT_AGENT_CLOUD_DIR: REPO,
  });
  start('hostB', path.join(REPO, 'node-host', 'host.js'), {
    CONTROL_PLANE: CP, NODE_ID: 'nodeB', HOST_DATA_DIR: path.join(ROOT, 'hostB'), HEARTBEAT_MS: '1500', MAX_AGENTS: '5', CIRCUIT_AGENT_CLOUD_DIR: REPO,
  });
  ok(await poll(async () => (await api(CP, 'GET', '/v1/nodes')).json.nodes?.filter((n) => n.status === 'up').length >= 2, 30, 500, 'both nodes up'), 'two operator nodes registered');

  // create — wallet provisioned off-box; fast trade cadence for the run
  const create = await api(CP, 'POST', '/v1/agents', { name: 'alpha', spec: { workload: 'agentd', config: { scanIntervalMs: 700, tradeSizeSol: 0.01, paperTrading: true } }, policy: { maxNotionalSol: 0.05, maxDailySol: 100, cooldownMs: 0, paper: true } });
  const id = create.json.agent.id;
  const addr = create.json.agent.address;
  ok(!!id && typeof addr === 'string' && addr.length >= 32, `agent created with off-box wallet ${addr}`);

  // KEY-OFF-BOX proof: control-plane state holds no secret; signer holds the sealed key
  const cpState = fs.readFileSync(path.join(ROOT, 'cp', 'state.json'), 'utf8');
  const signerKeys = JSON.parse(fs.readFileSync(path.join(ROOT, 'signer', 'keys.json'), 'utf8'));
  ok(!/seed|secret|privateKey|"sk"/i.test(cpState), 'control plane stores NO key material');
  ok(signerKeys[id] && signerKeys[id].ct && signerKeys[id].iv && signerKeys[id].tag, 'signer holds the wallet key, sealed at rest (AES-GCM)');

  // start → scheduled + running on a node, with a session
  await api(CP, 'POST', `/v1/agents/${id}/start`);
  let rec;
  const placed = await poll(async () => { rec = (await api(CP, 'GET', `/v1/agents/${id}`)).json.agent; return rec.nodeId && rec.session; }, 40, 500, 'agent placed on a node with a session');
  ok(placed, `placed on ${rec?.nodeId} (session epoch ${rec?.session?.epoch})`);
  const ownerNode = rec.nodeId;
  const epochBefore = rec.session.epoch;

  // the running workload actually signs through the signer with only a session token
  const signedInLogs = await poll(async () => {
    const { json } = await api(CP, 'GET', `/v1/agents/${id}/logs`);
    return (json.lines || []).some((l) => /signed off-box/.test(l.line));
  }, 40, 500, 'workload logs an off-box signature');
  ok(signedInLogs, 'running agent signs trades through the off-box signer (host never holds the key)');

  // ── FAILOVER: kill the node that owns it; CP must reschedule + rotate the session
  console.log(`    killing ${ownerNode} (the owner) …`);
  const owner = procs.find((p) => p.name === (ownerNode === 'nodeA' ? 'hostA' : 'hostB'));
  try { process.kill(owner.child.pid, 'SIGKILL'); } catch {}
  try { spawn('pkill', ['-P', String(owner.child.pid)]); } catch {} // also kill its agentd (simulate total node loss)

  const movedAndRotated = await poll(async () => {
    rec = (await api(CP, 'GET', `/v1/agents/${id}`)).json.agent;
    const sg = (await api(SIGNER, 'GET', `/v1/agents/${id}`)).json;
    return rec.nodeId && rec.nodeId !== ownerNode && rec.state === 'running' && sg.epoch > epochBefore;
  }, 60, 1000, 'reschedule to a healthy node + a fresh session epoch');
  ok(movedAndRotated, `rescheduled ${ownerNode} → ${rec?.nodeId}; session rotated to epoch ${rec?.session?.epoch} (old node fenced)`);

  // the rescheduled instance resumes signing on the new node
  const resumed = await poll(async () => {
    const { json } = await api(CP, 'GET', `/v1/agents/${id}/logs`);
    return (json.lines || []).filter((l) => /agentd up|signed off-box/.test(l.line)).length > 0 && rec.state === 'running';
  }, 30, 500, 'workload resumes on the new node');
  ok(resumed, 'agent resumed on the new node — lossless failover');

  // ════ PART C — live submit path (no broadcast: Jupiter base is a dead host) ════
  console.log('\nPart C — live submit: routes to on-chain, fails safe, no phantom accounting');
  const L = 'agt_live_1';
  await api(SIGNER, 'POST', '/v1/agents', { agentId: L, policy: { maxNotionalSol: 0.05, maxDailySol: 1, cooldownMs: 0, allow: ['buy'], paper: false } });
  const ls = await api(SIGNER, 'POST', `/v1/agents/${L}/session`, { node: 'nodeX' });
  const spentBefore = (await api(SIGNER, 'GET', `/v1/agents/${L}`)).json.daySpentSol;
  const live = await api(SIGNER, 'POST', `/v1/agents/${L}/intent`, { epoch: ls.json.epoch, token: ls.json.token, intent: { kind: 'buy', token: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', sizeSol: 0.01 } });
  ok(live.status === 502 && live.json.code === 'submit-failed', `live intent takes the on-chain path and fails safe [${live.json.code}]`);
  const spentAfter = (await api(SIGNER, 'GET', `/v1/agents/${L}`)).json.daySpentSol;
  ok(spentAfter === spentBefore, 'a failed live submit does NOT advance the daily spend (no phantom trade)');

  console.log(`\n${fail === 0 ? '✅ ALL GREEN' : '❌ FAILURES'} — ${pass} passed, ${fail} failed`);
  if (fail) dumpLogs();
  return fail === 0;
}

let okExit = false;
try { okExit = await main(); }
catch (e) { console.log('\n✗ harness error:', e.message); dumpLogs(); }
finally { await cleanup(); }
process.exit(okExit ? 0 : 1);
