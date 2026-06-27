// lib/bundle-store.js — the content-addressed bundle store (AGENT_BUNDLES.md §4).
//
// B1 backend: a local filesystem store keyed by sha256. The scheduler hands a node a {url, sha256};
// the node verifies the sha256 (and the manifest sig) before unpacking. Push is content-addressed —
// re-putting the same bytes is a no-op, and a sha mismatch is rejected. A real deployment swaps this
// for object storage / a CDN (oci) behind the same put/getBytes/getManifest shape.
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import net from 'node:net';
import { sha256hex } from './ed25519.js';
import { assertPublicHost } from './netguard.js';

// Hard ceiling on a bundle's compressed size — a valid-sha gzip bomb must not OOM/disk-fill the host.
export const MAX_BUNDLE_BYTES = Number(process.env.CIRCUIT_MAX_BUNDLE_BYTES || 64 * 1024 * 1024);

export class LocalBundleStore {
  constructor(root) {
    this.root = root;
    fs.mkdirSync(root, { recursive: true });
  }

  _tgz(sha) { return path.join(this.root, `${sha}.tgz`); }
  _man(sha) { return path.join(this.root, `${sha}.manifest.json`); }

  has(sha) { return fs.existsSync(this._tgz(sha)); }

  // Store bytes + manifest (verifying the sha matches). Idempotent. Returns the ref.
  put(bytes, manifest) {
    const h = sha256hex(bytes);
    if (h !== manifest.sha256) throw new Error('bundle-store.put: bytes do not match manifest.sha256');
    fs.writeFileSync(this._tgz(h), bytes);
    fs.writeFileSync(this._man(h), JSON.stringify(manifest));
    return { ref: `bundle://${h}`, url: this._tgz(h), sha256: h };
  }

  getBytes(sha) { return fs.readFileSync(this._tgz(sha)); }
  getManifest(sha) { return JSON.parse(fs.readFileSync(this._man(sha), 'utf8')); }
}

// Pull bundle bytes. SSRF-hardened: callers derive `url` from a TRUSTED store base + the content
// sha256 (never publisher-controlled input), and this still defends in depth —
//   • https only (no http, no file: scheme); the host must not be private/loopback/link-local, validated
//     ONCE and the connection PINNED to the vetted IP (custom lookup) so DNS-rebinding can't flip it;
//   • redirects refused so a 30x can't bounce to an internal address;
//   • a size cap aborts a gzip-bomb / oversized response mid-stream;
//   • a local-filesystem backend is contained to `storeRoot` via realpath (no path escape) + size cap.
export async function pullBytes(url, { storeRoot, maxBytes = MAX_BUNDLE_BYTES } = {}) {
  if (/^[a-z]+:\/\//i.test(url)) {
    const u = new URL(url);
    if (u.protocol !== 'https:') throw new Error(`bundle pull requires https (got ${u.protocol})`);
    const vetted = await assertPublicHost(u.hostname);       // resolve + validate once
    const pinnedIp = vetted[0];
    return await new Promise((resolve, reject) => {
      const req = https.get(url, {
        // pin every connection attempt to the validated IP — Node never re-resolves the hostname
        lookup: (_h, _o, cb) => cb(null, pinnedIp, net.isIP(pinnedIp) || 4),
        servername: u.hostname,                              // keep SNI/cert validation on the real name
      }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400) { res.destroy(); return reject(new Error('bundle pull: redirects are not allowed')); }
        if (res.statusCode !== 200) { res.destroy(); return reject(new Error(`bundle pull ${u.host} -> ${res.statusCode}`)); }
        const chunks = []; let len = 0;
        res.on('data', (c) => {
          len += c.length;
          if (len > maxBytes) { res.destroy(); reject(new Error(`bundle exceeds ${maxBytes} bytes`)); }
          else chunks.push(c);
        });
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      });
      req.on('error', reject);
      req.setTimeout(30_000, () => req.destroy(new Error('bundle pull timeout')));
    });
  }
  // local-filesystem backend (own-fleet): resolve and confine to the trusted store root, with a size cap
  const p = fs.realpathSync(url);
  if (storeRoot) {
    const root = fs.realpathSync(storeRoot);
    if (p !== root && !p.startsWith(root + path.sep)) throw new Error('bundle path escapes the store root');
  }
  if (fs.statSync(p).size > maxBytes) throw new Error(`bundle exceeds ${maxBytes} bytes`);
  return fs.readFileSync(p);
}
