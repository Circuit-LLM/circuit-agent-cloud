import { spawn } from 'node:child_process';
import { loadOrCreateNodeKey, signNodeHeaders } from '../lib/node-auth.js';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';

const PORT = 18995, BASE = `http://127.0.0.1:${PORT}`, KEY = 'admin-secret-xyz';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mt-'));
const srv = spawn('node', ['control-plane/server.js'], {
  cwd: '/home/watchtower/circuit-agent-cloud',
  env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1',
    CIRCUIT_CLOUD_STATE: path.join(tmp, 'state.json'),
    CIRCUIT_CLOUD_KEY: KEY,
    CIRCUIT_REQUIRE_NODE_AUTH: '1', CIRCUIT_REQUIRE_OWNER_AUTH: '1' },
  stdio: ['ignore', 'ignore', 'inherit'],
});
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
let pass = 0, fail = 0;
const check = (name, cond) => { if (cond) { pass++; console.log('  ✓', name); } else { fail++; console.log('  ✗ FAIL', name); } };

try {
  // wait for listen
  for (let i = 0; i < 50; i++) { try { await fetch(BASE + '/health'); break; } catch { await sleep(100); } }

  const nodeKey = loadOrCreateNodeKey(path.join(tmp, 'node.key')); // {priv, address}
  const body = { nodeId: 'outsider-1', caps: { cpu: 1, sandbox: 'node' }, budget: { maxAgents: 1 } };

  // (a) outside node: node-auth, NO admin key  -> should REGISTER (the fix)
  const hdrs = signNodeHeaders(nodeKey, { method: 'POST', path: '/v1/nodes/register', body });
  let r = await fetch(BASE + '/v1/nodes/register', { method: 'POST', headers: { 'Content-Type': 'application/json', ...hdrs }, body: JSON.stringify(body) });
  check('outside node registers with node-auth + NO admin key -> ' + r.status, r.status === 200);

  // (b) NO node-auth, NO admin key -> 401 (signature required)
  r = await fetch(BASE + '/v1/nodes/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  check('no node-auth, no key -> 401 (' + r.status + ')', r.status === 401);

  // (c) NO node-auth but WITH admin key -> still 401 (admin key must NOT bypass node identity)
  r = await fetch(BASE + '/v1/nodes/register', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + KEY }, body: JSON.stringify(body) });
  check('admin key does NOT bypass node-auth -> 401 (' + r.status + ')', r.status === 401);

  // (d) GET /v1/nodes (admin) with NO key -> 401
  r = await fetch(BASE + '/v1/nodes');
  check('GET /v1/nodes no key -> 401 (' + r.status + ')', r.status === 401);

  // (e) GET /v1/nodes WITH admin key -> 200 and shows the registered outsider
  r = await fetch(BASE + '/v1/nodes', { headers: { Authorization: 'Bearer ' + KEY } });
  const j = await r.json().catch(() => ({}));
  check('GET /v1/nodes WITH key -> 200 + sees outsider-1', r.status === 200 && j.nodes?.some(n => n.nodeId === 'outsider-1'));

  // (f) replay the SAME signed register (same nonce) -> rejected (nonce single-use)
  r = await fetch(BASE + '/v1/nodes/register', { method: 'POST', headers: { 'Content-Type': 'application/json', ...hdrs }, body: JSON.stringify(body) });
  check('replay of signed register rejected -> ' + r.status, r.status === 401);
} finally {
  srv.kill('SIGKILL');
  console.log(`\n${fail === 0 ? '✅ ALL GREEN' : '❌ FAILED'} — ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}
