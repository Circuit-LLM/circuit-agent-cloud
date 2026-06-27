// lib/bundle-store.js — the content-addressed bundle store (AGENT_BUNDLES.md §4).
//
// B1 backend: a local filesystem store keyed by sha256. The scheduler hands a node a {url, sha256};
// the node verifies the sha256 (and the manifest sig) before unpacking. Push is content-addressed —
// re-putting the same bytes is a no-op, and a sha mismatch is rejected. A real deployment swaps this
// for object storage / a CDN (oci) behind the same put/getBytes/getManifest shape.
import fs from 'node:fs';
import path from 'node:path';
import { sha256hex } from './ed25519.js';
import { assertPublicHost } from './netguard.js';

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
//   • https only (no http, no file: scheme), and the host must not be private/loopback/link-local
//     (assertPublicHost), with redirects refused so a 30x can't bounce to an internal address;
//   • a local-filesystem backend is contained to `storeRoot` via realpath (no path escape).
export async function pullBytes(url, { fetchImpl = fetch, storeRoot } = {}) {
  if (/^[a-z]+:\/\//i.test(url)) {
    const u = new URL(url);
    if (u.protocol !== 'https:') throw new Error(`bundle pull requires https (got ${u.protocol})`);
    await assertPublicHost(u.hostname);
    const r = await fetchImpl(url, { redirect: 'manual' });
    if (r.status >= 300 && r.status < 400) throw new Error('bundle pull: redirects are not allowed');
    if (!r.ok) throw new Error(`bundle pull ${u.host} -> ${r.status}`);
    return Buffer.from(await r.arrayBuffer());
  }
  // local-filesystem backend (own-fleet): resolve and confine to the trusted store root
  const p = fs.realpathSync(url);
  if (storeRoot) {
    const root = fs.realpathSync(storeRoot);
    if (p !== root && !p.startsWith(root + path.sep)) throw new Error('bundle path escapes the store root');
  }
  return fs.readFileSync(p);
}
