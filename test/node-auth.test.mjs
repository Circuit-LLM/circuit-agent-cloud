// MT#2 — node-identity auth. Boots the control plane with CIRCUIT_REQUIRE_NODE_AUTH=1 and proves a node
// must sign its requests, a nodeId is bound to its first key (no hijack), and only the node actually
// running an agent may report its health/logs (no cross-node poisoning).
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { newKeypair } from '../lib/ed25519.js';
import { signNodeHeaders } from '../lib/node-auth.js';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 18997;
const BASE = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'circuit-mt2-'));
const A = newKeypair();
const B = newKeypair();

const nodeReq = (kp, method, p, body) => {
  const h = signNodeHeaders({ priv: kp.priv, address: kp.address }, { method, path: p, body: body ?? {} });
  return fetch(`${BASE}${p}`, { method, headers: { 'content-type': 'application/json', ...h }, body: body ? JSON.stringify(body) : undefined })
    .then(async (r) => ({ status: r.status, body: await r.json() }));
};
const plain = (method, p, body) =>
  fetch(`${BASE}${p}`, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
    .then(async (r) => ({ status: r.status, body: await r.json() }));

const cp = spawn(process.execPath, ['control-plane/server.js'], {
  cwd: REPO,
  env: { ...process.env, PORT: String(PORT), CIRCUIT_CLOUD_STATE: path.join(tmp, 'state.json'), CIRCUIT_SIGNER_URL: '', CIRCUIT_CLOUD_KEY: '', CIRCUIT_REQUIRE_NODE_AUTH: '1' },
  stdio: 'ignore',
});

try {
  for (let i = 0; i < 50; i++) { try { await fetch(`${BASE}/v1/nodes`); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }

  // unsigned node request refused in strict mode
  assert.equal((await plain('POST', '/v1/nodes/register', { nodeId: 'node-A' })).status, 401);
  console.log('  ✓ strict mode: unsigned node request rejected (401)');

  // node A registers (binds nodeId 'node-A' to A's key)
  assert.equal((await nodeReq(A, 'POST', '/v1/nodes/register', { nodeId: 'node-A', budget: { maxAgents: 5 }, caps: { sandbox: 'node' } })).status, 200);
  console.log('  ✓ node A registered (id bound to its key)');

  // node B cannot register / heartbeat as 'node-A'
  assert.equal((await nodeReq(B, 'POST', '/v1/nodes/register', { nodeId: 'node-A' })).status, 403);
  assert.equal((await nodeReq(B, 'POST', '/v1/nodes/heartbeat', { nodeId: 'node-A', running: [] })).status, 403);
  console.log('  ✓ node B cannot claim node A\'s id (403)');

  // create + start an agent → scheduled onto node-A
  const created = await plain('POST', '/v1/agents', { name: 'bot' });
  const id = created.body.agent.id;
  await plain('POST', `/v1/agents/${id}/start`, {});
  await nodeReq(A, 'POST', '/v1/nodes/heartbeat', { nodeId: 'node-A', running: [] }); // pick up the placement

  // node B (a stranger) cannot report health/logs for node A's agent
  const bReport = await nodeReq(B, 'POST', `/v1/agents/${id}/report`, { health: { fake: true }, lines: [{ ts: 1, line: 'poison' }] });
  assert.equal(bReport.status, 403, `node B report should be 403, got ${bReport.status}`);
  // node A (the real runner) can
  assert.equal((await nodeReq(A, 'POST', `/v1/agents/${id}/report`, { health: { ok: true } })).status, 200);
  console.log('  ✓ only the node running the agent may report it (cross-node poisoning blocked)');

  console.log('node-auth (MT#2): all assertions passed');
} finally {
  cp.kill('SIGKILL');
  fs.rmSync(tmp, { recursive: true, force: true });
}
