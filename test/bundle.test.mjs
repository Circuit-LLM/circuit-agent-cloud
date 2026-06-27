// B1 — agent bundles end to end: a published, signed bundle is stored, pulled, verified (sha256 +
// manifest sig + owner binding), unpacked, and actually SPAWNED with the curated env. Plus the three
// rejections that must hold before any code runs: tampered bytes, forged manifest, wrong publisher.
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createBundle, verifyBundle, unpackTo, isSafeEntry } from '../lib/bundle.js';
import { LocalBundleStore, pullBytes } from '../lib/bundle-store.js';
import { buildAgentEnv } from '../node-host/env.js';
import { newKeypair } from '../lib/ed25519.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'circuit-b1-'));
const srcDir = path.join(tmp, 'src');
const storeDir = path.join(tmp, 'store');
const cacheDir = path.join(tmp, 'cache');
const dataDir = path.join(tmp, 'data');
fs.mkdirSync(srcDir, { recursive: true });
fs.mkdirSync(dataDir, { recursive: true });

// A trivial agent: prints what it can see in its env + writes a heartbeat to its data dir.
fs.writeFileSync(path.join(srcDir, 'agent.js'), `
const fs = require('fs');
fs.writeFileSync(process.env.CIRCUIT_AGENT_DATA_DIR + '/heartbeat.json', JSON.stringify({ ok: true, at: 'agent' }));
console.log(JSON.stringify({
  session: process.env.CIRCUIT_AGENT_SESSION || null,
  dataDir: process.env.CIRCUIT_AGENT_DATA_DIR || null,
  leakedSecret: process.env.AGENT_KEYPAIR || null,        // a bundle must NEVER see this
  leakedUnrelated: process.env.OPERATOR_SSH_KEY || null,  // nor this
}));
`);

const owner = newKeypair();          // the agent's owner (the publisher of an honest bundle)
const attacker = newKeypair();       // someone else
const agentId = 'agent-b1-test';

// ── publish ──────────────────────────────────────────────────────────────────────
const { bytes, sha256, manifest } = createBundle({
  dir: srcDir, agentId, entry: 'agent.js', sdk: '@circuit/agent@0', priv: owner.priv, publisherPubkey: owner.address,
});
assert.equal(manifest.sha256, sha256, 'manifest pins the content hash');
const store = new LocalBundleStore(storeDir);
const ref = store.put(bytes, manifest);
assert.ok(ref.ref.startsWith('bundle://'), 'store returns a content-addressed ref');
console.log('  ✓ published + stored', ref.ref.slice(0, 22) + '…');

// ── verify: happy path ─────────────────────────────────────────────────────────────
assert.deepEqual(verifyBundle(bytes, manifest, { expectedOwner: owner.address }), { ok: true });
console.log('  ✓ verify ok (sha256 + sig + owner binding)');

// ── verify: tampered bytes → sha256 mismatch ───────────────────────────────────────
{
  const flipped = Buffer.from(bytes); flipped[flipped.length - 5] ^= 0xff;
  assert.equal(verifyBundle(flipped, manifest, { expectedOwner: owner.address }).code, 'sha256-mismatch');
  console.log('  ✓ tampered bytes rejected (sha256-mismatch)');
}

// ── verify: forged manifest (any signed field changed → sig no longer matches) ─────
// The bytes still hash to manifest.sha256, so the hash check passes; the signature covers
// entry/sdk/agentId/runtime, so flipping any of them is caught at the sig.
{
  assert.equal(verifyBundle(bytes, { ...manifest, entry: 'evil.js' }, { expectedOwner: owner.address }).code, 'bad-manifest-sig');
  assert.equal(verifyBundle(bytes, { ...manifest, sdk: 'tampered' }, { expectedOwner: owner.address }).code, 'bad-manifest-sig');
  console.log('  ✓ forged manifest rejected (bad-manifest-sig)');
}

// ── verify: wrong publisher (attacker re-signs with their own key) → not the owner ──
{
  const hostile = createBundle({ dir: srcDir, agentId, entry: 'agent.js', priv: attacker.priv, publisherPubkey: attacker.address });
  // attacker's manifest is internally valid (sig checks out) BUT the publisher isn't the owner:
  assert.deepEqual(verifyBundle(hostile.bytes, hostile.manifest), { ok: true }, 'sig alone is valid');
  assert.equal(verifyBundle(hostile.bytes, hostile.manifest, { expectedOwner: owner.address }).code, 'publisher-not-owner');
  console.log('  ✓ wrong publisher rejected (publisher-not-owner)');
}

// ── verify: manifest must target THIS agent (agentId binding) ───────────────────────
{
  assert.deepEqual(verifyBundle(bytes, manifest, { expectedOwner: owner.address, expectedAgentId: agentId }), { ok: true });
  assert.equal(verifyBundle(bytes, manifest, { expectedAgentId: 'some-other-agent' }).code, 'agent-id-mismatch');
  console.log('  ✓ manifest agentId is bound (wrong agent rejected)');
}

// ── entry escape: a path-traversal entry can never be published or verified ──────────
{
  assert.equal(isSafeEntry('agent.js'), true);
  for (const bad of ['..', '.', '../x', 'a/b', '/etc/passwd', '']) assert.equal(isSafeEntry(bad), false, `entry '${bad}' must be unsafe`);
  assert.throws(() => createBundle({ dir: srcDir, agentId, entry: '..', priv: owner.priv, publisherPubkey: owner.address }), /unsafe entry/);
  console.log('  ✓ path-traversal entry rejected at publish + verify');
}

// ── node-host path: pull → verify → unpack → SPAWN with the curated env ─────────────
{
  const pulled = await pullBytes(ref.url, { storeRoot: storeDir });
  assert.deepEqual(verifyBundle(pulled, manifest, { expectedOwner: owner.address }), { ok: true });
  unpackTo(pulled, cacheDir);
  const entryPath = path.join(cacheDir, manifest.entry);
  assert.ok(fs.existsSync(entryPath), 'entry unpacked');

  // the assignment the node-host would build for this bundle (untrusted → no secrets)
  const a = { name: 'b1bot', spec: { bundle: { sha256 } }, signer: { url: 'http://signer', agentId, epoch: 1, token: 'SESS-TOKEN', address: owner.address, paper: true } };
  const env = buildAgentEnv(a, dataDir, { PATH: process.env.PATH, AGENT_KEYPAIR: 'first-party-secret', OPERATOR_SSH_KEY: 'LEAK' });

  const r = spawnSync(process.execPath, [entryPath], { cwd: cacheDir, env, encoding: 'utf8' });
  assert.equal(r.status, 0, `bundle ran: ${r.stderr}`);
  const out = JSON.parse(r.stdout.trim());
  assert.equal(out.session, 'SESS-TOKEN', 'bundle saw its off-box session token');
  assert.equal(out.dataDir, dataDir, 'bundle saw its data dir');
  assert.equal(out.leakedSecret, null, 'bundle did NOT receive the first-party secret');
  assert.equal(out.leakedUnrelated, null, 'bundle did NOT receive an unrelated operator secret');
  assert.ok(fs.existsSync(path.join(dataDir, 'heartbeat.json')), 'bundle wrote its heartbeat to the data dir');
  console.log('  ✓ pulled, verified, unpacked, and ran under the curated env (no secret leak)');
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log('bundle (B1): all assertions passed');
