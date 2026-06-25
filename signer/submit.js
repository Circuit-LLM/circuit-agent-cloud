// Live on-chain submit — the seam that turns a policy-approved intent into a real
// trade, signed with the agent's off-box key and landed via Jupiter Ultra.
//
// Zero-dep on purpose. The signing key never leaves the signer: we BUILD the swap
// from the intent (taker = the agent's own wallet), sign the returned transaction
// with native Ed25519, and hand it back to Ultra to broadcast. Because the signer
// constructs the order itself (rather than signing opaque bytes handed in by a
// caller), it can only ever sign a swap of the agent's own funds — never a
// transfer out. That is what makes off-box custody safe.
//
// Solana wire format we rely on:
//   tx      = [compact-u16 sigCount][sigCount × 64-byte sig][message]
//   message = [0x80|ver?][numReqSig][roSigned][roUnsigned][compact-u16 keyN][keyN × 32]…
// We locate the message, find the agent's index in the account keys, confirm it's
// a required signer, sign the *whole message*, and drop the sig into its slot.
import { fromSeed, sign, base58decode } from '../lib/ed25519.js';

const SOL_MINT = 'So11111111111111111111111111111111111111112';
const LAMPORTS = 1e9;

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

// Build → sign → land a swap for an approved intent. Returns { txid, status }.
//   buy  : SOL → token,  amount = floor(sizeSol × 1e9) lamports
//   sell : token → SOL,  amount = intent.amount (token base units; required)
export async function executeUltraSwap({ seed, address, intent, apiBase, apiKey }) {
  const base = (apiBase || 'https://lite-api.jup.ag').replace(/\/$/, '');
  const pubkey = base58decode(address);
  if (!intent.token) throw new Error('intent.token (mint) required for a live trade');

  let inputMint, outputMint, amount;
  if (intent.kind === 'buy') {
    inputMint = SOL_MINT; outputMint = intent.token;
    amount = Math.floor(Number(intent.sizeSol) * LAMPORTS);
  } else {
    inputMint = intent.token; outputMint = SOL_MINT;
    amount = Math.floor(Number(intent.amount));
    if (!(amount > 0)) throw new Error('live sell needs intent.amount in token base units');
  }
  if (!(amount > 0)) throw new Error('computed amount is zero');

  const params = new URLSearchParams({ inputMint, outputMint, amount: String(amount), taker: address });
  if (intent.maxSlippageBps) params.set('slippageBps', String(intent.maxSlippageBps));
  const order = await jget(`${base}/ultra/v1/order?${params}`, apiKey);
  if (!order.transaction || !order.requestId) throw new Error('no route / unfunded for this swap');

  const signedTransaction = signSerializedTx(seed, pubkey, order.transaction);
  const res = await jpost(`${base}/ultra/v1/execute`, { signedTransaction, requestId: order.requestId }, apiKey);
  if (res.status && res.status !== 'Success') throw new Error(`Ultra ${res.status}${res.code ? ' code ' + res.code : ''}`);
  return { txid: res.signature || res.txid || null, status: res.status || 'Success', inAmount: order.inAmount, outAmount: order.outAmount };
}
