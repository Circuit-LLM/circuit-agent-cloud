// lib/node-auth.js — node-identity authentication for register / heartbeat / report.
//
// Each node has its own Ed25519 identity. It signs every control-plane request; the CP binds the nodeId
// to that pubkey on first register (TOFU) and thereafter rejects a request for that nodeId signed by any
// other key. This stops a rogue operator from heartbeating AS another node, or reporting health/logs for
// agents it doesn't run (the CP checks `agent.nodeId === the authenticated node`). Mirrors owner-auth
// with a distinct domain so the two signature types are never interchangeable.
import { sign, verify, base58, base58decode, sha256hex, fromSeed } from './ed25519.js';
import fs from 'node:fs';
import crypto from 'node:crypto';

function stableStringify(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(',')}}`;
}

export function nodeAuthMessage({ method, path, body, ts, nonce }) {
  const bodyHash = sha256hex(stableStringify(body ?? {}));
  return `circuit-node-auth\nv1\n${String(method).toUpperCase()}\n${path}\n${bodyHash}\n${ts}\n${nonce}`;
}

// Load or create a persistent node identity (32-byte seed at `keyPath`).
export function loadOrCreateNodeKey(keyPath) {
  let seed;
  try { seed = Buffer.from(fs.readFileSync(keyPath, 'utf8').trim(), 'hex'); } catch { seed = null; }
  if (!seed || seed.length !== 32) {
    seed = crypto.randomBytes(32);
    fs.writeFileSync(keyPath, seed.toString('hex'), { mode: 0o600 });
  }
  return fromSeed(seed); // { priv, pubkey, address }
}

export function signNodeHeaders({ priv, address }, { method, path, body }, { ts = Date.now(), nonce } = {}) {
  const n = nonce ?? base58(crypto.randomBytes(12));
  const sig = sign(priv, nodeAuthMessage({ method, path, body, ts, nonce: n }));
  return {
    'X-Circuit-Node': address,
    'X-Circuit-Node-Ts': String(ts),
    'X-Circuit-Node-Nonce': n,
    'X-Circuit-Node-Sig': base58(sig),
  };
}

// Returns the authenticated node pubkey (base58), or null if unsigned. Throws (401) on a bad/stale sig.
export function verifyNodeRequest({ method, path, body, headers }, { maxAgeMs = 30_000, nonceStore, now = Date.now } = {}) {
  const h = (k) => headers[k] || headers[k.toLowerCase()];
  const node = h('X-Circuit-Node');
  const ts = h('X-Circuit-Node-Ts');
  const nonce = h('X-Circuit-Node-Nonce');
  const sig = h('X-Circuit-Node-Sig');
  if (!node && !ts && !nonce && !sig) return null;
  const fail = (m) => { const e = new Error(`node auth: ${m}`); e.status = 401; throw e; };
  if (!node || !ts || !nonce || !sig) fail('incomplete signature headers');
  const tsn = Number(ts);
  if (!Number.isFinite(tsn) || Math.abs(now() - tsn) > maxAgeMs) fail('stale or invalid timestamp');
  if (nonceStore) { if (nonceStore.has(nonce)) fail('nonce replay'); nonceStore.add(nonce, tsn + maxAgeMs); }
  let ok = false;
  try { ok = verify(base58decode(node), nodeAuthMessage({ method, path, body, ts: tsn, nonce }), base58decode(sig)); }
  catch { fail('malformed signature'); }
  if (!ok) fail('bad signature');
  return node;
}
