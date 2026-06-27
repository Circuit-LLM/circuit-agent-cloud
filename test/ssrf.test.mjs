// SSRF / egress guard — a node must never be coerced into reaching its own/private network when it
// pulls a bundle, and the B2 egress proxy reuses the same guard. Covers netguard + the hardened
// pullBytes (https-only, private-IP rejection, local store-root containment).
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isPrivateIp, assertPublicHost } from '../lib/netguard.js';
import { pullBytes } from '../lib/bundle-store.js';

// ── isPrivateIp ──────────────────────────────────────────────────────────────────
for (const ip of [
  '127.0.0.1', '10.1.2.3', '192.168.0.5', '172.16.9.9', '169.254.169.254', '100.64.0.1', '0.0.0.0',
  '255.255.255.255', '224.0.0.1', '239.1.2.3', '240.0.0.1', '192.0.0.171', '198.18.0.1', '192.0.2.5', // added ranges
  '::1', 'fe80::1', 'fc00::1', 'ff02::1',                                                              // v6
  '::ffff:169.254.169.254', '::ffff:a9fe:a9fe', '0:0:0:0:0:ffff:a9fe:a9fe', '::a9fe:a9fe',             // every v4-mapped/compat spelling of metadata
])
  assert.equal(isPrivateIp(ip), true, `${ip} must be private`);
for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111', '::ffff:8.8.8.8'])
  assert.equal(isPrivateIp(ip), false, `${ip} must be public`);
console.log('  ✓ isPrivateIp classifies loopback/RFC1918/CGNAT/link-local/ULA/multicast/reserved + every IPv6 spelling of metadata');

// ── assertPublicHost (DNS-rebinding aware via the resolver) ─────────────────────────
await assert.rejects(assertPublicHost('localhost'), /local name/);
await assert.rejects(assertPublicHost('foo.internal'), /local name/);
await assert.rejects(assertPublicHost('169.254.169.254'), /private/, 'cloud metadata IP literal blocked');
await assert.rejects(assertPublicHost('evil.example', { lookup: async () => [{ address: '169.254.169.254' }] }), /private/, 'host resolving to metadata blocked');
await assertPublicHost('example.com', { lookup: async () => [{ address: '93.184.216.34' }] }); // public → ok
console.log('  ✓ assertPublicHost blocks names/IPs that resolve into the private network');

// ── pullBytes: scheme + SSRF + path containment ─────────────────────────────────────
await assert.rejects(pullBytes('http://example.com/x.tgz'), /requires https/, 'http rejected');
await assert.rejects(pullBytes('https://169.254.169.254/x.tgz'), /private|loopback/, 'https to metadata rejected');
await assert.rejects(pullBytes('https://127.0.0.1/x.tgz'), /private|loopback/, 'https to loopback rejected');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ssrf-'));
const root = path.join(tmp, 'store');
fs.mkdirSync(root);
fs.writeFileSync(path.join(root, 'a.tgz'), 'inside');
fs.writeFileSync(path.join(tmp, 'secret.txt'), 'SECRET');
assert.equal((await pullBytes(path.join(root, 'a.tgz'), { storeRoot: root })).toString(), 'inside', 'in-root read ok');
await assert.rejects(pullBytes(path.join(tmp, 'secret.txt'), { storeRoot: root }), /escapes the store root/, 'path escape rejected');
fs.rmSync(tmp, { recursive: true, force: true });
console.log('  ✓ pullBytes is https-only, blocks private IPs, contains local reads to the store root');

console.log('ssrf: all assertions passed');
