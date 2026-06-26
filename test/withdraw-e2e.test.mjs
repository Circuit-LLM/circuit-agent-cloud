// test/withdraw-e2e.test.mjs — owner withdraw / export / safe-destroy against the real signer.
// Exercises the full routes against live RPC on EMPTY wallets, so it proves the paths run
// end-to-end without moving any funds (a fresh agent wallet holds 0 SOL). The actual transfer
// bytes are proven in withdraw.test.mjs; a funded live send is a separate one-off check.
//   node test/withdraw-e2e.test.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { fromSeed, base58decode } from '../lib/ed25519.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..');
const SIGNER = 'http://127.0.0.1:18994';
const MASTER = '66'.repeat(32);

// Borrow the real RPC URL from circuit-data-api's resolved config (reliable, keyed RPC).
let RPC = 'https://api.mainnet-beta.solana.com';
try { RPC = createRequire('/home/watchtower/circuit-data-api/package.json')('/home/watchtower/circuit-data-api/lib/config.js').CIRCUIT_RPC_URL || RPC; } catch {}

const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${m}`); return c; };
async function api(method, p, body) {
  const res = await fetch(SIGNER + p, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(20000) });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}
async function waitHealth(tries = 50) {
  for (let i = 0; i < tries; i++) { try { const r = await fetch(SIGNER + '/health', { signal: AbortSignal.timeout(1500) }); if (r.ok) return true; } catch {} await sleep(200); }
  return false;
}

(async () => {
  const ROOT = path.join(os.tmpdir(), `circuit-wd-${process.pid}`);
  fs.rmSync(ROOT, { recursive: true, force: true }); fs.mkdirSync(ROOT, { recursive: true });
  const out = fs.openSync(path.join(ROOT, 'signer.log'), 'a');
  procs.push(spawn(process.execPath, [path.join(REPO, 'signer', 'server.js')], {
    cwd: REPO, stdio: ['ignore', out, out],
    env: { ...process.env, PORT: '18994', HOST: '127.0.0.1', CIRCUIT_SIGNER_DIR: path.join(ROOT, 'signer'), CIRCUIT_SIGNER_MASTER_KEY: MASTER, CIRCUIT_SIGNER_RPC_URL: RPC },
  }));
  if (!ok(await waitHealth(), 'signer up')) { for (const p of procs) try { p.kill('SIGKILL'); } catch {} process.exitCode = 1; return; }

  const ownerAddr = '2jj34NBJpqnZwJMHSDRDG4jSwQfwSp9umyCe3xChZnjF'; // any valid base58 pubkey

  // provision WITH an owner
  const c1 = await api('POST', '/v1/agents', { agentId: 'w1', owner: ownerAddr });
  ok(c1.json.owner === ownerAddr && !!c1.json.address, 'provision records the owner withdraw address');

  // provision WITHOUT an owner
  await api('POST', '/v1/agents', { agentId: 'w2' });
  const setO = await api('PUT', '/v1/agents/w2/owner', { owner: ownerAddr });
  ok(setO.json.owner === ownerAddr, 'owner can be set after the fact');
  const badO = await api('PUT', '/v1/agents/w2/owner', { owner: 'not-a-pubkey!!' });
  ok(badO.status === 400 && badO.json.code === 'bad-owner', 'a bad owner address is rejected');

  // EXPORT returns the real key for that wallet
  const ex = await api('POST', '/v1/agents/w1/export', {});
  const derived = fromSeed(Buffer.from(ex.json.seedHex, 'hex')).address;
  ok(ex.json.address === derived, 'export returns the genuine key (derived pubkey == wallet address)');
  ok(base58decode(ex.json.secretKeyBase58).length === 64, 'export gives a 64-byte Solana secret key (wallet-importable)');

  // WITHDRAW with no owner → refused
  const c3 = await api('POST', '/v1/agents', { agentId: 'w3' });
  const wNo = await api('POST', '/v1/agents/w3/withdraw', {});
  ok(wNo.status === 409 && wNo.json.code === 'no-owner', 'withdraw refused when no owner is set');

  // WITHDRAW on an empty wallet → runs the full RPC path, moves nothing
  const wEmpty = await api('POST', '/v1/agents/w1/withdraw', {});
  ok(wEmpty.status === 400 && wEmpty.json.code === 'empty', 'withdraw on an empty wallet fails cleanly (no funds moved)');

  // SAFE DESTROY: empty wallet destroys; (non-empty refusal needs funds — covered by logic)
  const d1 = await api('DELETE', '/v1/agents/w1');
  ok(d1.json.ok === true, 'destroy succeeds on a verified-empty wallet');

  for (const p of procs) try { p.kill('SIGKILL'); } catch {}
  console.log(`\n${fail === 0 ? '✓' : '✗'} withdraw-e2e: ${pass} passed, ${fail} failed`);
  process.exitCode = fail === 0 ? 0 : 1;
})().catch((e) => { for (const p of procs) try { p.kill('SIGKILL'); } catch {} console.error('CRASH:', e?.stack || e); process.exitCode = 1; });
