// lib/bundle-store.js — the content-addressed bundle store (AGENT_BUNDLES.md §4).
//
// B1 backend: a local filesystem store keyed by sha256. The scheduler hands a node a {url, sha256};
// the node verifies the sha256 (and the manifest sig) before unpacking. Push is content-addressed —
// re-putting the same bytes is a no-op, and a sha mismatch is rejected. A real deployment swaps this
// for object storage / a CDN (oci) behind the same put/getBytes/getManifest shape.
import fs from 'node:fs';
import path from 'node:path';
import { sha256hex } from './ed25519.js';

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

// Pull bundle bytes from a url the node-host was handed. Supports a local path / file: URL (B1) and
// http(s) (a real CDN). Returns a Buffer.
export async function pullBytes(url, fetchImpl = fetch) {
  if (/^https?:\/\//.test(url)) {
    const r = await fetchImpl(url);
    if (!r.ok) throw new Error(`bundle pull ${url} -> ${r.status}`);
    return Buffer.from(await r.arrayBuffer());
  }
  const p = url.startsWith('file:') ? new URL(url).pathname : url;
  return fs.readFileSync(p);
}
