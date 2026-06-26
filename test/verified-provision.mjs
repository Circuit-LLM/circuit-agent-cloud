// test/verified-provision.mjs — the control plane forwards verified-intent config to the
// signer (docs/VERIFIED_INTENTS.md §7). Boots CP + signer, creates an agent with a committed
// rule + requireVerifiedIntent, and confirms the SIGNER stored it (so the gate will fire).
//   node test/verified-provision.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..');
const SIGNER = 'http://127.0.0.1:18993';
const CP = 'http://127.0.0.1:18992';
const MASTER = '55'.repeat(32);

const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${m}`); return c; };

function start(name, script, env, ROOT) {
  const out = fs.openSync(path.join(ROOT, `${name}.log`), 'a');
  const child = spawn(process.execPath, [script], { cwd: REPO, env: { ...process.env, ...env }, stdio: ['ignore', out, out] });
  procs.push(child);
  return child;
}
async function api(base, method, p, body) {
  const res = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(8000) });
  return { status: res.status, json: await res.json().catch(() => ({})) };
}
async function waitHealth(base, tries = 50) {
  for (let i = 0; i < tries; i++) { try { const r = await fetch(base + '/health', { signal: AbortSignal.timeout(1500) }); if (r.ok) return true; } catch {} await sleep(200); }
  return false;
}

(async () => {
  const ROOT = path.join(os.tmpdir(), `circuit-vp-${process.pid}`);
  fs.rmSync(ROOT, { recursive: true, force: true });
  fs.mkdirSync(ROOT, { recursive: true });
  start('signer', path.join(REPO, 'signer', 'server.js'), { PORT: '18993', HOST: '127.0.0.1', CIRCUIT_SIGNER_DIR: path.join(ROOT, 'signer'), CIRCUIT_SIGNER_MASTER_KEY: MASTER }, ROOT);
  start('cp', path.join(REPO, 'control-plane', 'server.js'), { PORT: '18992', HOST: '127.0.0.1', CIRCUIT_CLOUD_STATE: path.join(ROOT, 'cp', 'state.json'), CIRCUIT_SIGNER_URL: SIGNER, CIRCUIT_SIGNER_PUBLIC_URL: SIGNER }, ROOT);
  if (!ok(await waitHealth(SIGNER) && await waitHealth(CP), 'signer + control plane up')) { for (const p of procs) try { p.kill('SIGKILL'); } catch {} process.exitCode = 1; return; }

  const RULE = { id: 'dip-v1', when: [{ input: 'price', op: '<', value: 2 }], then: { kind: 'buy', tokenInput: 'mint', sizeSol: 0.01 }, requires: ['price'] };
  const created = await api(CP, 'POST', '/v1/agents', {
    name: 'verif',
    policy: { requireVerifiedIntent: true, paper: true },
    verified: { rule: RULE, acceptedKeys: { ['aa'.repeat(32)]: 'data' } },
  });
  ok(created.status === 200 && created.json.agent?.address, 'agent provisioned via control plane (wallet from signer)');

  // The signer must now hold the committed rule + the require flag — proof it was forwarded.
  const id = created.json.agent.id;
  const view = await api(SIGNER, 'GET', `/v1/agents/${id}`);
  ok(view.json.verified?.ruleId === 'dip-v1', 'signer stored the committed rule (ruleId dip-v1)');
  ok(view.json.verified?.requireVerifiedIntent === true, 'signer has requireVerifiedIntent enabled');
  ok(view.json.verified?.acceptedKeys === 1, 'signer trusts the 1 provided producer key');

  for (const p of procs) try { p.kill('SIGKILL'); } catch {}
  console.log(`\n${fail === 0 ? '✓' : '✗'} verified-provision: ${pass} passed, ${fail} failed`);
  process.exitCode = fail === 0 ? 0 : 1;
})().catch((e) => { for (const p of procs) try { p.kill('SIGKILL'); } catch {} console.error('CRASH:', e?.stack || e); process.exitCode = 1; });
