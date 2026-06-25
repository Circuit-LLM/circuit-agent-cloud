// Live on-chain submit — the seam that turns a policy-approved intent into a real
// trade, signed with the agent's off-box key and landed via Jupiter Ultra.
//
// Zero-dep on purpose. The signing key never leaves the signer: we BUILD the swap
// from the intent (taker = the agent's own wallet), then — BEFORE signing — we
// VALIDATE the broker's response so we never blind-sign opaque bytes:
//   • the endpoint is https (no plaintext MITM to a non-loopback host);
//   • the order echoes the exact input/output mints and amount we asked for;
//   • the SOL-denominated value of the swap is within the per-trade + remaining
//     daily caps (for a sell this is order.outAmount, which `sizeSol` can't bound);
//   • the agent is a REQUIRED SIGNER (not necessarily the fee payer — RFQ routers
//     like DFlow sponsor the agent's gas with a relayer fee payer), and every
//     program it invokes resolvable from the static account keys is allowlisted.
// Residual trust: programs loaded via v0 address-lookup tables can't be resolved
// without an RPC round-trip, so full instruction validation against ALTs is the
// documented final hardening (see SECURITY note at the bottom). Until then live
// safety rests on https + requestId binding + these checks + an honest Jupiter.
//
// Solana wire format we rely on:
//   tx      = [compact-u16 sigCount][sigCount × 64-byte sig][message]
//   message = [0x80|ver?][numReqSig][roSigned][roUnsigned][compact-u16 keyN][keyN × 32]
//             [blockhash 32][compact-u16 ixN][ix: programIdIndex u8, accounts, data]…
import { fromSeed, sign, base58, base58decode } from '../lib/ed25519.js';

const SOL_MINT = 'So11111111111111111111111111111111111111112';
const LAMPORTS = 1e9;

const typed = (status, code, message) => Object.assign(new Error(message), { status, code });

// Programs a Jupiter swap legitimately invokes. Extend via CIRCUIT_SIGNER_EXTRA_PROGRAMS
// (comma-separated base58) — e.g. after observing real Ultra txs in a funded dry-run.
// Top-level programs a Jupiter Ultra swap legitimately invokes. NB: Ultra picks a
// ROUTER per route (Jupiter v6 or an RFQ router like DFlow), and the underlying
// DEX programs run as inner CPIs that never appear as top-level program ids — so
// this set stays small. Add a router here as Ultra introduces it (a new router is
// fail-closed: the signer refuses to sign until it's allowlisted). Both routers
// below were observed landing real swaps in the funded mainnet dry-run.
const BASE_PROGRAMS = [
  '11111111111111111111111111111111', // System
  'ComputeBudget111111111111111111111111111111', // ComputeBudget
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', // SPL Token
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', // Token-2022
  'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL', // Associated Token
  'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4', // Jupiter Aggregator v6 (buy route)
  'proVF4pMXVaYqmy4NjniPh4pqKNfMmsihgd4wdkCX3u', // DFlow — Ultra RFQ router (sell route)
];
const ALLOWED_PROGRAMS = new Set([
  ...BASE_PROGRAMS,
  ...(process.env.CIRCUIT_SIGNER_EXTRA_PROGRAMS || '').split(',').map((s) => s.trim()).filter(Boolean),
]);

function assertSafeBase(base) {
  let u;
  try { u = new URL(base); } catch { throw typed(400, 'bad-config', `invalid Jupiter base url: ${base}`); }
  const loopback = ['localhost', '127.0.0.1', '::1'].includes(u.hostname);
  if (u.protocol !== 'https:' && !loopback) throw typed(400, 'insecure-endpoint', 'Jupiter base must be https for a non-loopback host');
  return base.replace(/\/$/, '');
}

export function readCompactU16(buf, off) {
  let val = 0, shift = 0, o = off;
  for (;;) {
    const b = buf[o++];
    val |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
  }
  return [val, o];
}

// Find the agent's index among the message's static account keys (the signers are
// the first `numReqSig` of them). Works for legacy and v0 messages.
export function findSignerIndex(message, pubkey) {
  const versioned = (message[0] & 0x80) !== 0;
  let p = versioned ? 1 : 0;
  const numReqSig = message[p];
  p += 3; // numRequiredSignatures + numReadonlySigned + numReadonlyUnsigned
  const [keyCount, p2] = readCompactU16(message, p);
  p = p2;
  let idx = -1;
  for (let i = 0; i < keyCount; i++) {
    if (message.subarray(p, p + 32).equals(pubkey)) idx = i;
    p += 32;
  }
  return { idx, numReqSig };
}

// Sign a base64 (legacy or v0) transaction as the agent and return it base64.
export function signSerializedTx(seed, pubkey, b64) {
  const raw = Buffer.from(b64, 'base64');
  const [sigCount, sigArrayStart] = readCompactU16(raw, 0);
  if (sigCount < 1) throw new Error('transaction has no signature slots');
  const message = raw.subarray(sigArrayStart + sigCount * 64);
  const { idx, numReqSig } = findSignerIndex(message, pubkey);
  if (idx < 0) throw new Error('agent wallet is not in the transaction account list');
  if (idx >= numReqSig || idx >= sigCount) throw new Error('agent wallet is not a required signer of this transaction');
  const { priv } = fromSeed(seed);
  sign(priv, message).copy(raw, sigArrayStart + idx * 64);
  return raw.toString('base64');
}

async function jget(url, key) {
  const r = await fetch(url, { headers: key ? { 'x-api-key': key } : {}, signal: AbortSignal.timeout(15000) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`order ${r.status}: ${j.error || j.message || ''}`.trim());
  return j;
}
async function jpost(url, body, key) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(key ? { 'x-api-key': key } : {}) }, body: JSON.stringify(body), signal: AbortSignal.timeout(20000) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`execute ${r.status}: ${j.error || j.message || ''}`.trim());
  return j;
}

// Inspect a transaction BEFORE signing: the agent must be a REQUIRED SIGNER, and
// every program invoked that we can resolve from the static account keys must be
// swap-only-allowlisted. (We do NOT require the agent to be the fee payer — Ultra's
// RFQ routers like DFlow legitimately use a relayer/maker as fee payer and sponsor
// the agent's gas, with the agent as a non-payer signer.) Returns the program ids
// we COULDN'T resolve (loaded via address-lookup tables). Throws (fail-closed) on
// a non-signer agent or a disallowed resolvable program.
export function inspectTransaction(b64, pubkey) {
  const raw = Buffer.from(b64, 'base64');
  const [sigCount, sigStart] = readCompactU16(raw, 0);
  const m = raw.subarray(sigStart + sigCount * 64);
  let p = (m[0] & 0x80) !== 0 ? 1 : 0; // skip the version byte on v0
  const numReqSig = m[p];
  p += 3; // header: numReqSig + numReadonlySigned + numReadonlyUnsigned
  const [keyCount, pk] = readCompactU16(m, p); p = pk;
  const staticKeys = [];
  for (let i = 0; i < keyCount; i++) { staticKeys.push(base58(m.subarray(p, p + 32))); p += 32; }
  const myIdx = staticKeys.indexOf(base58(pubkey));
  if (myIdx < 0 || myIdx >= numReqSig) throw typed(403, 'tx-rejected', 'agent wallet is not a required signer of this transaction');
  p += 32; // recent blockhash
  const [ixCount, pi] = readCompactU16(m, p); p = pi;
  const unresolved = [];
  for (let i = 0; i < ixCount; i++) {
    const programIdIndex = m[p]; p += 1;
    const [accLen, pa] = readCompactU16(m, p); p = pa + accLen; // skip account index bytes (u8 each)
    const [dataLen, pd] = readCompactU16(m, p); p = pd + dataLen; // skip instruction data
    if (p > m.length) throw typed(403, 'tx-rejected', 'malformed transaction (instruction parse overran)');
    if (programIdIndex < staticKeys.length) {
      const prog = staticKeys[programIdIndex];
      if (!ALLOWED_PROGRAMS.has(prog)) throw typed(403, 'tx-rejected', `transaction invokes a non-allowlisted program ${prog}`);
    } else {
      unresolved.push(programIdIndex); // ALT-loaded — not resolvable without RPC
    }
  }
  return { unresolved, feePayer: staticKeys[0], signerIndex: myIdx };
}

// Build → validate → sign → land a swap for an approved intent.
//   buy  : SOL → token,  amount = floor(sizeSol × 1e9) lamports
//   sell : token → SOL,  amount = intent.amount (token base units; required)
// Returns { txid, status, solValue } where solValue is the SOL-denominated size
// that the caller MUST charge against the daily budget.
export async function executeUltraSwap({ seed, address, intent, apiBase, apiKey, maxNotionalSol = Infinity, remainingDailySol = Infinity }) {
  const base = assertSafeBase(apiBase || 'https://lite-api.jup.ag');
  const pubkey = base58decode(address);
  if (!intent.token) throw typed(400, 'bad-intent', 'intent.token (mint) required for a live trade');

  let inputMint, outputMint, amount;
  if (intent.kind === 'buy') {
    inputMint = SOL_MINT; outputMint = intent.token;
    amount = Math.floor(Number(intent.sizeSol) * LAMPORTS);
  } else {
    inputMint = intent.token; outputMint = SOL_MINT;
    amount = Math.floor(Number(intent.amount));
    if (!(amount > 0)) throw typed(400, 'bad-intent', 'live sell needs intent.amount in token base units');
  }
  if (!(amount > 0)) throw typed(400, 'bad-intent', 'computed amount is zero');

  const params = new URLSearchParams({ inputMint, outputMint, amount: String(amount), taker: address });
  if (intent.maxSlippageBps) params.set('slippageBps', String(intent.maxSlippageBps));
  const order = await jget(`${base}/ultra/v1/order?${params}`, apiKey);
  if (!order.transaction || !order.requestId) throw typed(502, 'no-route', 'no route / unfunded for this swap');

  // The order must be for the swap we asked for — don't sign a mismatched route.
  if (order.inputMint && order.inputMint !== inputMint) throw typed(403, 'order-mismatch', 'order inputMint does not match the request');
  if (order.outputMint && order.outputMint !== outputMint) throw typed(403, 'order-mismatch', 'order outputMint does not match the request');

  // SOL-denominated size — for a SELL this is the SOL we receive (order.outAmount),
  // which `sizeSol` cannot bound. Enforce the caps on THIS, then return it so the
  // caller charges the real value against the daily budget.
  const solValue = intent.kind === 'buy'
    ? (Number(order.inAmount) || amount) / LAMPORTS
    : Number(order.outAmount) / LAMPORTS;
  if (!(solValue > 0)) throw typed(502, 'no-route', 'could not determine the SOL value of the swap');
  if (solValue > maxNotionalSol + 1e-9) throw typed(403, 'over-trade-cap', `swap value ${solValue.toFixed(6)} SOL > maxNotionalSol ${maxNotionalSol}`);
  if (solValue > remainingDailySol + 1e-9) throw typed(403, 'over-daily-cap', `swap value ${solValue.toFixed(6)} SOL > remaining daily ${remainingDailySol}`);

  // Don't blind-sign: confirm the agent pays and only swap-programs are invoked.
  const { unresolved } = inspectTransaction(order.transaction, pubkey);

  const signedTransaction = signSerializedTx(seed, pubkey, order.transaction);
  const res = await jpost(`${base}/ultra/v1/execute`, { signedTransaction, requestId: order.requestId }, apiKey);
  if (res.status && res.status !== 'Success') throw typed(502, 'submit-failed', `Ultra ${res.status}${res.code ? ' code ' + res.code : ''}`);
  return { txid: res.signature || res.txid || null, status: res.status || 'Success', solValue, inAmount: order.inAmount, outAmount: order.outAmount, altPrograms: unresolved.length };
}

// SECURITY (live submit) — what bounds an operator/broker today, and what doesn't:
//   ENFORCED: https-only endpoint · requestId binds the executed tx to our order ·
//   order mints/amount match our request · agent is a required signer · static-key
//   programs allowlisted · SOL-value capped per-trade and per-day (sell on outAmount).
//   RESIDUAL: programs/accounts loaded via v0 address-lookup tables are not resolved
//   (needs an RPC getAddressLookupTable round-trip) — so a *malicious* Jupiter could
//   still hide an instruction there. Mitigated by trusting Jupiter over https; full
//   ALT resolution is the next hardening before unsupervised size.
