// B1 — the control-plane owner-binding gate (AGENT_BUNDLES.md §7). Boots the control plane (no signer:
// the binding check runs before provisioning) and proves a bundle binds ONLY to its owner: a valid
// publisher==owner bundle is accepted; a wrong owner, a tampered manifest, and a missing owner are all
// rejected before the agent is created.
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createBundle } from '../lib/bundle.js';
import { newKeypair } from '../lib/ed25519.js';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 18995;
const BASE = `http://127.0.0.1:${PORT}`;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'circuit-b1cp-'));
const srcDir = path.join(tmp, 'src');
fs.mkdirSync(srcDir, { recursive: true });
fs.writeFileSync(path.join(srcDir, 'agent.js'), 'console.log("hi");');

const owner = newKeypair();
const stranger = newKeypair();

// a real signed bundle published by `owner`
const { sha256, manifest } = createBundle({ dir: srcDir, agentId: 'x', entry: 'agent.js', priv: owner.priv, publisherPubkey: owner.address });
const bundleSpec = (m = manifest) => ({ bundle: { ref: `bundle://${sha256}`, url: path.join(tmp, 'unused.tgz'), sha256, runtime: 'node', manifest: m } });

const post = async (body) => {
  const r = await fetch(`${BASE}/v1/agents`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};

const cp = spawn(process.execPath, ['control-plane/server.js'], {
  cwd: REPO,
  env: { ...process.env, PORT: String(PORT), CIRCUIT_CLOUD_STATE: path.join(tmp, 'state.json'), CIRCUIT_SIGNER_URL: '', CIRCUIT_CLOUD_KEY: '' },
  stdio: 'ignore',
});

try {
  // wait for the CP to come up
  for (let i = 0; i < 50; i++) {
    try { await fetch(`${BASE}/v1/nodes`); break; } catch { await new Promise((r) => setTimeout(r, 100)); }
  }

  // ✓ valid: publisher == owner → accepted (no signer configured, so it creates straight away)
  {
    const r = await post({ name: 'ok-bot', owner: owner.address, spec: bundleSpec() });
    assert.equal(r.status, 200, `valid binding should be accepted: ${JSON.stringify(r.body)}`);
    assert.ok(r.body.agent?.id, 'agent created');
    console.log('  ✓ valid bundle (publisher == owner) accepted');
  }

  // ✗ wrong owner: publisher != owner
  {
    const r = await post({ name: 'bad-owner', owner: stranger.address, spec: bundleSpec() });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /publisher is not the agent owner/, r.body.error);
    console.log('  ✓ wrong owner rejected');
  }

  // ✗ tampered manifest (sdk changed → sig breaks)
  {
    const r = await post({ name: 'tampered', owner: owner.address, spec: bundleSpec({ ...manifest, sdk: 'evil' }) });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /signature is invalid/, r.body.error);
    console.log('  ✓ tampered manifest rejected');
  }

  // ✗ no owner at all
  {
    const r = await post({ name: 'no-owner', spec: bundleSpec() });
    assert.equal(r.status, 400);
    assert.match(r.body.error, /requires an owner/, r.body.error);
    console.log('  ✓ missing owner rejected');
  }

  console.log('bundle-binding (B1): all assertions passed');
} finally {
  cp.kill('SIGKILL');
  fs.rmSync(tmp, { recursive: true, force: true });
}
