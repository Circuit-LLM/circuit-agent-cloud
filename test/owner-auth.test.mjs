// MT#1 — per-owner authentication + authorization. Boots the control plane in STRICT mode
// (CIRCUIT_REQUIRE_OWNER_AUTH=1, no signer) and proves: requests must be wallet-signed, and a caller can
// only act on agents THEY own — owner B can't start/withdraw/export/read owner A's agent (no IDOR).
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { newKeypair } from '../lib/ed25519.js';
import { signOwnerHeaders, verifyOwnerRequest, NonceStore } from '../lib/owner-auth.js';

// ── unit: sign → verify round-trip + the rejections ──────────────────────────────────
{
  const kp = newKeypair();
  const req = { method: 'POST', path: '/v1/agents', body: { name: 'x' } };
  const headers = signOwnerHeaders({ priv: kp.priv, owner: kp.address }, req);
  const ns = new NonceStore();
  assert.equal(verifyOwnerRequest({ ...req, headers }, { nonceStore: ns }), kp.address, 'valid sig → owner');
  assert.throws(() => verifyOwnerRequest({ ...req, headers }, { nonceStore: ns }), /nonce replay/);
  assert.throws(() => verifyOwnerRequest({ ...req, body: { name: 'TAMPERED' }, headers }, { nonceStore: new NonceStore() }), /bad signature/);
  assert.equal(verifyOwnerRequest({ ...req, headers: {} }, {}), null, 'no headers → null (unsigned)');
  const stale = signOwnerHeaders({ priv: kp.priv, owner: kp.address }, req, { ts: Date.now() - 60_000 });
  assert.throws(() => verifyOwnerRequest({ ...req, headers: stale }, {}), /stale/);
  console.log('  ✓ owner-auth sign/verify: round-trip, replay, tamper, stale, unsigned');
}

// ── e2e against a strict control plane ───────────────────────────────────────────────
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 18996;
const BASE = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'circuit-mt1-'));
const A = newKeypair();
const B = newKeypair();

const signed = (kp, method, p, body) => {
  const h = body ? signOwnerHeaders({ priv: kp.priv, owner: kp.address }, { method, path: p, body }) : signOwnerHeaders({ priv: kp.priv, owner: kp.address }, { method, path: p, body: {} });
  return fetch(`${BASE}${p}`, { method, headers: { 'content-type': 'application/json', ...h }, body: body ? JSON.stringify(body) : undefined })
    .then(async (r) => ({ status: r.status, body: await r.json() }));
};
const unsigned = (method, p, body) =>
  fetch(`${BASE}${p}`, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
    .then(async (r) => ({ status: r.status, body: await r.json() }));

const cp = spawn(process.execPath, ['control-plane/server.js'], {
  cwd: REPO,
  env: { ...process.env, PORT: String(PORT), CIRCUIT_CLOUD_STATE: path.join(tmp, 'state.json'), CIRCUIT_SIGNER_URL: '', CIRCUIT_CLOUD_KEY: '', CIRCUIT_REQUIRE_OWNER_AUTH: '1', CIRCUIT_OWNER_RATE_PER_MIN: '5' },
  stdio: 'ignore',
});

try {
  for (let i = 0; i < 50; i++) { try { await fetch(`${BASE}/v1/nodes`); break; } catch { await new Promise((r) => setTimeout(r, 100)); } }

  // unsigned create is refused in strict mode
  assert.equal((await unsigned('POST', '/v1/agents', { name: 'nope' })).status, 401);
  console.log('  ✓ strict mode: unsigned request rejected (401)');

  // owner A creates an agent → owned by A
  const created = await signed(A, 'POST', '/v1/agents', { name: 'a-bot' });
  assert.equal(created.status, 200, JSON.stringify(created.body));
  const id = created.body.agent.id;
  assert.equal(created.body.agent.owner, A.address, 'agent owned by the signer');
  console.log('  ✓ owner A created an agent (owned by A)');

  // owner B cannot touch A's agent — every custody/control route is 403
  for (const [method, p, body] of [
    ['POST', `/v1/agents/${id}/start`, {}],
    ['POST', `/v1/agents/${id}/stop`, {}],
    ['PUT', `/v1/agents/${id}/owner`, { owner: B.address }],
    ['POST', `/v1/agents/${id}/withdraw`, { amountSol: 1 }],
    ['POST', `/v1/agents/${id}/export`, {}],
    ['GET', `/v1/agents/${id}`, null],
    ['DELETE', `/v1/agents/${id}`, null],
  ]) {
    const r = await signed(B, method, p, body);
    assert.equal(r.status, 403, `owner B should be 403 on ${method} ${p}, got ${r.status} ${JSON.stringify(r.body)}`);
  }
  console.log('  ✓ owner B is 403 on every one of A\'s custody/control routes (no IDOR)');

  // owner B's listing does not include A's agent
  const bList = await signed(B, 'GET', '/v1/agents', null);
  assert.equal(bList.body.agents.length, 0, 'B sees none of A\'s agents');

  // owner A can act on their own agent
  assert.equal((await signed(A, 'POST', `/v1/agents/${id}/start`, {})).status, 200);
  console.log('  ✓ owner A can act on their own agent; B\'s listing is empty');

  // per-owner rate limit (MT#4): A is capped at 5 creates/min
  let got429 = false;
  for (let i = 0; i < 8 && !got429; i++) {
    if ((await signed(A, 'POST', '/v1/agents', { name: `rl-${i}` })).status === 429) got429 = true;
  }
  assert.ok(got429, 'owner A hit the per-owner create rate limit');
  console.log('  ✓ per-owner rate limit caps a single tenant\'s create rate (429)');

  console.log('owner-auth (MT#1/#4): all assertions passed');
} finally {
  cp.kill('SIGKILL');
  fs.rmSync(tmp, { recursive: true, force: true });
}
