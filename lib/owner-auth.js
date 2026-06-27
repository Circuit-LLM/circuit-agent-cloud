// lib/owner-auth.js — per-owner request authentication for a MULTI-TENANT control plane.
//
// Each mutating request is signed by the agent OWNER's wallet (Ed25519, the same key that is the sole
// withdraw authority). The control plane verifies the signature, freshness, and a one-time nonce, then
// authorizes per-agent: a caller may only act on agents they own. This replaces "one shared bearer can
// do anything to any agent" (an IDOR) with real per-owner authorization. Non-custodial: the server holds
// no per-user secret — identity IS the wallet pubkey.
//
// Header set (all base58 / decimal strings):
//   X-Circuit-Owner  owner pubkey (Solana address)
//   X-Circuit-Ts     unix ms
//   X-Circuit-Nonce  random per-request nonce
//   X-Circuit-Sig    Ed25519 signature over the canonical message below
import { sign, verify, base58, base58decode, sha256hex } from './ed25519.js';

// Deterministic JSON (sorted keys, recursive) so the client and server hash the SAME bytes for a body.
// MUST match circuit-cli/src/services/owner-auth.js.
export function stableStringify(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(',')}}`;
}

// The exact bytes signed: method, path, a hash of the canonical body, the timestamp, and the nonce.
export function ownerAuthMessage({ method, path, body, ts, nonce }) {
  const bodyHash = sha256hex(stableStringify(body ?? {}));
  return `circuit-owner-auth\nv1\n${String(method).toUpperCase()}\n${path}\n${bodyHash}\n${ts}\n${nonce}`;
}

// Sign with a raw Ed25519 private KeyObject (the cloud's ed25519.fromSeed output). The CLI has its own
// signer using a Solana keypair — both produce a signature over the identical message bytes.
export function signOwnerHeaders({ priv, owner }, { method, path, body }, { ts = Date.now(), nonce } = {}) {
  const n = nonce ?? base58(Buffer.from(`${ts}-${Math.trunc(performance.now() * 1000)}`)); // deterministic-free nonce
  const msg = ownerAuthMessage({ method, path, body, ts, nonce: n });
  return {
    'X-Circuit-Owner': owner,
    'X-Circuit-Ts': String(ts),
    'X-Circuit-Nonce': n,
    'X-Circuit-Sig': base58(sign(priv, msg)),
  };
}

// Verify a signed request. Returns the authenticated owner pubkey (base58) or null if NO owner headers
// are present (caller decides whether that's allowed). Throws (status 401) on a present-but-invalid sig,
// stale timestamp, or replayed nonce.
export function verifyOwnerRequest({ method, path, body, headers }, { maxAgeMs = 30_000, nonceStore, now = Date.now } = {}) {
  const h = (k) => headers[k] || headers[k.toLowerCase()];
  const owner = h('X-Circuit-Owner');
  const ts = h('X-Circuit-Ts');
  const nonce = h('X-Circuit-Nonce');
  const sig = h('X-Circuit-Sig');
  if (!owner && !ts && !nonce && !sig) return null; // unsigned request
  const fail = (m) => { const e = new Error(`owner auth: ${m}`); e.status = 401; throw e; };
  if (!owner || !ts || !nonce || !sig) fail('incomplete signature headers');
  const tsn = Number(ts);
  if (!Number.isFinite(tsn) || Math.abs(now() - tsn) > maxAgeMs) fail('stale or invalid timestamp');
  if (nonceStore) {
    if (nonceStore.has(nonce)) fail('nonce replay');
    nonceStore.add(nonce, tsn + maxAgeMs);
  }
  let ok = false;
  try { ok = verify(base58decode(owner), ownerAuthMessage({ method, path, body, ts: tsn, nonce }), base58decode(sig)); }
  catch { fail('malformed signature'); }
  if (!ok) fail('bad signature');
  return owner;
}

// Tiny TTL nonce cache (single-process). A multi-process CP needs a shared store, but the freshness
// window already bounds replay to maxAgeMs even without it.
export class NonceStore {
  constructor() { this.m = new Map(); }
  has(n) { const e = this.m.get(n); if (e && e > Date.now()) return true; if (e) this.m.delete(n); return false; }
  add(n, expiry) {
    this.m.set(n, expiry);
    if (this.m.size > 5000) for (const [k, v] of this.m) if (v <= Date.now()) this.m.delete(k);
  }
}
