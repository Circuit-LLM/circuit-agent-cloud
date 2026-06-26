// lib/verified-intent.js — the signer-side decision gate (docs/VERIFIED_INTENTS.md).
//
// A zero-dependency plain-JS port of @circuit/attest, byte-compatible with it (same
// canonical encoding + ed25519 scheme via lib/ed25519.js), so an intent the SDK builds
// verifies here unchanged. The signer runs decisionGate() before signing a trade: it
// proves the trade is the genuine output of the owner's committed rule on AUTHENTICATED
// inputs — so a host that controls the agent still can't get a forged trade signed.
import { verify } from './ed25519.js';

// Canonical JSON — recursively key-sorted + compact. MUST match @circuit/core
// stableStringify byte-for-byte (the signature is over these exact bytes).
function stableStringify(obj) {
  if (typeof obj !== 'object' || obj === null) return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(stableStringify).join(',') + ']';
  return (
    '{' +
    Object.keys(obj)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k]))
      .join(',') +
    '}'
  );
}

function verifyPayload(pubkeyHex, payload, sigHex) {
  try {
    return verify(Buffer.from(pubkeyHex, 'hex'), stableStringify(payload), Buffer.from(sigHex, 'hex'));
  } catch {
    return false;
  }
}

// ── the signed portions (must match @circuit/attest evidence.ts) ──────────────
const quotePayload = (q) => ({ kind: q.kind, path: q.path, data: q.data, ts: q.ts, nonce: q.nonce });
const receiptPayload = (r) => ({
  kind: r.kind,
  inputHash: r.inputHash,
  outputHash: r.outputHash,
  verdict: r.verdict == null ? null : r.verdict,
  modelFp: r.modelFp,
  ts: r.ts,
  nonce: r.nonce,
});

const rej = (code) => ({ ok: false, code });
const PASS = { ok: true, code: 'ok' };

function verifyEvidence(ev, opts) {
  const now = (opts.now || Date.now)();
  const maxAge = opts.maxAgeMs || 60000;
  if (!ev || typeof ev !== 'object') return rej('evidence-unknown');

  if (ev.kind === 'signed-quote') {
    if (opts.acceptedKeys[ev.key] !== 'data') return rej('evidence-untrusted-key');
    if (!verifyPayload(ev.key, quotePayload(ev), ev.sig)) return rej('evidence-invalid');
    if (now - ev.ts > maxAge) return rej('evidence-stale');
    if (opts.replay && opts.replay.has(ev.nonce)) return rej('evidence-replay');
    if (opts.replay) opts.replay.add(ev.nonce);
    return PASS;
  }
  if (ev.kind === 'inference-receipt') {
    if (opts.acceptedKeys[ev.key] !== 'inference') return rej('evidence-untrusted-key');
    if (!verifyPayload(ev.key, receiptPayload(ev), ev.sig)) return rej('evidence-invalid');
    if (now - ev.ts > maxAge) return rej('evidence-stale');
    if (opts.replay && opts.replay.has(ev.nonce)) return rej('evidence-replay');
    if (opts.replay) opts.replay.add(ev.nonce);
    return PASS;
  }
  if (ev.kind === 'zktls') {
    if (!(opts.acceptedNotaries || []).includes(ev.notary)) return rej('evidence-untrusted-notary');
    if (opts.verifyZkTls) {
      if (!opts.verifyZkTls(ev)) return rej('evidence-invalid');
    } else if (opts.requireZkTlsProof) {
      return rej('evidence-zktls-unverified');
    }
    if (now - ev.sessionTime > maxAge) return rej('evidence-stale');
    if (opts.replay && opts.replay.has(ev.nonce)) return rej('evidence-replay');
    if (opts.replay) opts.replay.add(ev.nonce);
    return PASS;
  }
  return rej('evidence-unknown');
}

function evidenceBacks(evidence, input, value) {
  for (const ev of evidence) {
    if (ev.kind === 'signed-quote' && input in ev.data && ev.data[input] === value) return true;
    if (ev.kind === 'zktls' && input in ev.claim && ev.claim[input] === value) return true;
    if (ev.kind === 'inference-receipt' && ev.verdict !== undefined && ev.verdict === value) return true;
  }
  return false;
}

function cmp(a, op, b) {
  switch (op) {
    case '==': return a === b;
    case '!=': return a !== b;
    case '<': return typeof a === 'number' && typeof b === 'number' && a < b;
    case '<=': return typeof a === 'number' && typeof b === 'number' && a <= b;
    case '>': return typeof a === 'number' && typeof b === 'number' && a > b;
    case '>=': return typeof a === 'number' && typeof b === 'number' && a >= b;
    default: return false;
  }
}

function evaluateRule(rule, inputs) {
  for (const c of rule.when) if (!cmp(inputs[c.input], c.op, c.value)) return null;
  const t = rule.then;
  const token = t.token != null ? t.token : t.tokenInput != null ? String(inputs[t.tokenInput]) : undefined;
  const sizeSol = t.sizeSol != null ? t.sizeSol : t.sizeInput != null ? Number(inputs[t.sizeInput]) : undefined;
  const intent = { kind: t.kind };
  if (token != null) intent.token = token;
  if (sizeSol != null) intent.sizeSol = sizeSol;
  return intent;
}

const nn = (x) => (x == null ? null : x);
const sameIntent = (a, b) => a.kind === b.kind && nn(a.token) === nn(b.token) && nn(a.sizeSol) === nn(b.sizeSol);

/**
 * The decision gate. opts = { rule, acceptedKeys, acceptedNotaries?, now?, maxAgeMs?, replay? }.
 * Returns { ok, code }. code: verified | unknown-rule | evidence-* | input-mismatch | decision-unjustified.
 */
function decisionGate(vi, opts) {
  if (!vi || vi.rule !== opts.rule.id) return rej('unknown-rule');
  const evidence = Array.isArray(vi.evidence) ? vi.evidence : [];
  for (const ev of evidence) {
    const r = verifyEvidence(ev, opts);
    if (!r.ok) return r;
  }
  for (const key of opts.rule.requires || []) {
    if (!evidenceBacks(evidence, key, (vi.inputs || {})[key])) return rej('input-mismatch');
  }
  const expected = evaluateRule(opts.rule, vi.inputs || {});
  if (!expected || !sameIntent(expected, vi.intent || {})) return rej('decision-unjustified');
  return { ok: true, code: 'verified' };
}

export { stableStringify, verifyPayload, verifyEvidence, evidenceBacks, evaluateRule, sameIntent, decisionGate };
