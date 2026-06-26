// Verified-intent gate test (docs/VERIFIED_INTENTS.md).
//
// Part A (unit): drives lib/verified-intent.js decisionGate directly — proves it
//   accepts a genuine rule-derived trade and rejects every forgery class.
// Part B (integration): boots the REAL signer, provisions an agent with a committed
//   rule + requireVerifiedIntent, opens a session, and proves the signer itself signs
//   only verified trades — a host holding a valid session STILL can't get a forged or
//   unjustified trade signed. This is the property the whole design exists to enforce.
//
// Harness notes (same as e2e-signer.mjs): no `sleep` (setTimeout), kill children by
// captured handle only, deterministic master key.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { newKeypair, sign } from '../lib/ed25519.js';
import { stableStringify, decisionGate } from '../lib/verified-intent.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..');
const SIGNER = 'http://127.0.0.1:18992';
const MASTER = '22'.repeat(32);

let pass = 0, fail = 0;
const ok = (cond, msg) => { cond ? pass++ : fail++; console.log(`  ${cond ? '✓ PASS' : '✗ FAIL'}  ${msg}`); return cond; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// One trusted data producer + one untrusted impostor, for the evidence tests.
const dataKp = newKeypair();
const DATA_KEY = dataKp.pubkey.toString('hex');
const impostorKp = newKeypair();

function quote(kp, { data, ts, nonce, qpath = '/api/token-price?mint=MINT' }) {
  const base = { kind: 'signed-quote', path: qpath, data, ts, nonce };
  const sig = sign(kp.priv, stableStringify(base)).toString('hex');
  return { ...base, key: kp.pubkey.toString('hex'), sig };
}

const RULE = {
  id: 'dip-v1',
  when: [{ input: 'price', op: '<', value: 2 }],
  then: { kind: 'buy', tokenInput: 'mint', sizeSol: 0.01 },
  requires: ['price'],
};
const ACCEPTED = { [DATA_KEY]: 'data' };

// ── Part A: unit (decisionGate) ───────────────────────────────────────────────
function unitTests() {
  console.log('\nPart A — decisionGate unit');
  const opts = () => ({ rule: RULE, acceptedKeys: ACCEPTED, now: () => 1_000_000, maxAgeMs: 60000 });
  const fresh = (over = {}) =>
    quote(dataKp, { data: { price: 1.8, mint: 'MINT' }, ts: 1_000_000, nonce: Math.random().toString(36), ...over });

  ok(
    decisionGate({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [fresh()] }, opts()).ok === true,
    'genuine rule-derived trade accepted',
  );
  ok(
    decisionGate({ intent: { kind: 'buy', token: 'EVIL', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [fresh()] }, opts()).code === 'decision-unjustified',
    'forged token (rule says MINT, host says EVIL) rejected',
  );
  ok(
    decisionGate({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.5 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [fresh()] }, opts()).code === 'decision-unjustified',
    'forged size (rule says 0.01, host says 0.5) rejected',
  );
  ok(
    decisionGate({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 2.5, mint: 'MINT' }, evidence: [fresh({ data: { price: 2.5, mint: 'MINT' } })] }, opts()).code === 'decision-unjustified',
    'market does not justify the trade (price ≥ 2) rejected',
  );
  // host lies about the input but the signed evidence still says price=2.5 → input-mismatch
  ok(
    decisionGate({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [fresh({ data: { price: 2.5, mint: 'MINT' } })] }, opts()).code === 'input-mismatch',
    'host lies about input (claims 1.8, evidence says 2.5) rejected',
  );
  const tampered = fresh();
  tampered.data = { price: 1.0, mint: 'MINT' }; // mutate after signing
  ok(
    decisionGate({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.0, mint: 'MINT' }, evidence: [tampered] }, opts()).code === 'evidence-invalid',
    'tampered evidence (signature no longer matches) rejected',
  );
  ok(
    decisionGate({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [quote(impostorKp, { data: { price: 1.8, mint: 'MINT' }, ts: 1_000_000, nonce: 'x' })] }, opts()).code === 'evidence-untrusted-key',
    'evidence signed by an untrusted key rejected',
  );
  ok(
    decisionGate({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [fresh({ ts: 1_000_000 - 120000 })] }, opts()).code === 'evidence-stale',
    'stale evidence (older than maxAge) rejected',
  );
  ok(
    decisionGate({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'other-rule', inputs: { price: 1.8, mint: 'MINT' }, evidence: [fresh()] }, opts()).code === 'unknown-rule',
    'wrong rule id rejected',
  );
}

// ── Part B: integration (real signer) ─────────────────────────────────────────
const procs = [];
function start(name, script, env, ROOT) {
  const out = fs.openSync(path.join(ROOT, `${name}.log`), 'a');
  const child = spawn(process.execPath, [script], { cwd: REPO, env: { ...process.env, ...env }, stdio: ['ignore', out, out] });
  procs.push(child);
  return child;
}
async function api(method, p, body) {
  const res = await fetch(SIGNER + p, {
    method, headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(8000),
  });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}
async function waitHealth(tries = 50) {
  for (let i = 0; i < tries; i++) {
    try { const r = await fetch(SIGNER + '/health', { signal: AbortSignal.timeout(1500) }); if (r.ok) return true; } catch {}
    await sleep(200);
  }
  return false;
}

async function integrationTests() {
  console.log('\nPart B — real signer enforces the gate');
  const ROOT = path.join(os.tmpdir(), `circuit-vi-${process.pid}`);
  fs.rmSync(ROOT, { recursive: true, force: true });
  fs.mkdirSync(ROOT, { recursive: true });
  start('signer', path.join(REPO, 'signer', 'server.js'), {
    PORT: '18992', HOST: '127.0.0.1', CIRCUIT_SIGNER_DIR: path.join(ROOT, 'signer'), CIRCUIT_SIGNER_MASTER_KEY: MASTER,
  }, ROOT);
  if (!ok(await waitHealth(), 'signer is up')) return;

  // Provision an agent with a committed rule + requireVerifiedIntent, then open a session.
  await api('POST', '/v1/agents', {
    agentId: 'verif-1',
    policy: { requireVerifiedIntent: true, cooldownMs: 0, paper: true },
    verified: { rule: RULE, acceptedKeys: ACCEPTED },
  });
  const sess = await api('POST', '/v1/agents/verif-1/session', { node: 'n1' });
  const { epoch, token } = sess.json;
  ok(epoch === 1 && !!token, 'session opened (epoch 1, token issued)');

  const ts = () => Date.now();
  const fresh = (over = {}) => quote(dataKp, { data: { price: 1.8, mint: 'MINT' }, ts: ts(), nonce: Math.random().toString(36).slice(2), ...over });
  const submit = (extra) => api('POST', '/v1/agents/verif-1/intent', { epoch, token, ...extra });

  // 1. genuine verified trade → signed
  const good = await submit({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [fresh()] });
  ok(good.status === 200 && good.json.ok === true && good.json.code === 'signed', 'genuine verified trade is signed');

  // 2. forged token (valid session, valid evidence, but the rule produces MINT)
  const forged = await submit({ intent: { kind: 'buy', token: 'EVIL', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [fresh()] });
  ok(forged.status === 403 && forged.json.code === 'decision-unjustified', 'host forging a different token is rejected (decision-unjustified)');

  // 3. no signal: host tries to buy when the rule does not fire
  const noSignal = await submit({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 2.5, mint: 'MINT' }, evidence: [fresh({ data: { price: 2.5, mint: 'MINT' } })] });
  ok(noSignal.status === 403 && noSignal.json.code === 'decision-unjustified', 'host trading against a non-firing rule is rejected');

  // 4. untrusted key
  const untrusted = await submit({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [quote(impostorKp, { data: { price: 1.8, mint: 'MINT' }, ts: ts(), nonce: 'imp' })] });
  ok(untrusted.status === 403 && untrusted.json.code === 'evidence-untrusted-key', 'evidence from an untrusted key is rejected');

  // 5. a plain intent with no rule/evidence at all (the pre-verified-intents call shape)
  const plain = await submit({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 } });
  ok(plain.status === 403 && plain.json.code === 'unknown-rule', 'plain unverified intent is rejected when verification is required');

  // 6. replay: a genuine quote, then the SAME nonce again
  const rpNonce = 'replay-1';
  const q1 = quote(dataKp, { data: { price: 1.8, mint: 'MINT' }, ts: ts(), nonce: rpNonce });
  const first = await submit({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [q1] });
  const replay = await submit({ intent: { kind: 'buy', token: 'MINT', sizeSol: 0.01 }, rule: 'dip-v1', inputs: { price: 1.8, mint: 'MINT' }, evidence: [{ ...q1 }] });
  ok(first.json.ok === true && replay.status === 403 && replay.json.code === 'evidence-replay', 'replayed evidence nonce is rejected');
}

(async () => {
  unitTests();
  try { await integrationTests(); }
  catch (e) { ok(false, `integration crashed: ${e.message}`); }
  finally { for (const c of procs) try { c.kill('SIGKILL'); } catch {} }
  console.log(`\n${fail === 0 ? '✓' : '✗'} verified-intent: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
})();
