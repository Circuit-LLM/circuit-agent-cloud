// signer/withdraw.js — owner-recovery transfers (zero-dependency).
//
// The autonomous trade path is buy/sell-only and can never move funds out. THIS path is
// the OWNER's escape hatch: it sends the agent wallet's SOL back to the agent's committed
// OWNER ADDRESS — and only that address, never an arbitrary destination — so it does not
// reintroduce a drain vector. A leaked session token still can't reach this (it's gated by
// the operator bearer + the fixed owner destination), and the host never has the key.
//
// A SOL transfer is the simplest Solana transaction (one System-transfer instruction), so
// we build the legacy message by hand rather than pull in @solana/web3.js (the signer holds
// keys — keeping its supply chain at zero is a security property). The byte layout is
// verified against web3.js in test/withdraw.test.mjs.
import { fromSeed, sign, base58decode } from '../lib/ed25519.js';

const SYS_PROGRAM = base58decode('11111111111111111111111111111111'); // 32 zero bytes
const TOKEN_PID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN2022_PID = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const LAMPORTS = 1_000_000_000;
const FEE_RESERVE = 5000n; // 1-signature base fee, kept back so the from account covers it

// Solana compact-u16 (ShortVec) length prefix.
function compactU16(n) {
  const out = [];
  let v = n;
  for (;;) { const b = v & 0x7f; v >>>= 7; if (v) out.push(b | 0x80); else { out.push(b); break; } }
  return Buffer.from(out);
}

/**
 * Build a legacy System-transfer message: `from` → `to`, `lamports`, for `blockhashB58`.
 * Account order obeys Solana's rule (writable-signer, writable-nonsigner, readonly-nonsigner):
 *   [0] from  (signer, writable)   [1] to (writable)   [2] System program (readonly)
 */
export function buildSolTransferMessage(fromPub, toPub, lamports, blockhashB58) {
  const from = Buffer.from(fromPub), to = Buffer.from(toPub), bh = base58decode(blockhashB58);
  if (from.length !== 32 || to.length !== 32 || bh.length !== 32) throw new Error('bad pubkey/blockhash length');
  const header = Buffer.from([1, 0, 1]); // 1 req sig, 0 readonly-signed, 1 readonly-unsigned
  const keys = Buffer.concat([compactU16(3), from, to, SYS_PROGRAM]);
  const data = Buffer.alloc(12);
  data.writeUInt32LE(2, 0);                       // System instruction 2 = Transfer
  data.writeBigUInt64LE(BigInt(lamports), 4);
  const ix = Buffer.concat([Buffer.from([2]), compactU16(2), Buffer.from([0, 1]), compactU16(data.length), data]);
  const ixs = Buffer.concat([compactU16(1), ix]);
  return Buffer.concat([header, keys, bh, ixs]);
}

/** Sign the message with the agent seed and serialize the full legacy transaction (base64). */
export function signTransferTx(seed, message) {
  const { priv } = fromSeed(seed);
  const sig = sign(priv, message); // 64 bytes
  return Buffer.concat([compactU16(1), sig, message]).toString('base64');
}

async function rpc(url, method, params) {
  const r = await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(20000),
  });
  const j = await r.json().catch(() => ({}));
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}

export async function getBalanceLamports(url, addressB58) {
  return BigInt((await rpc(url, 'getBalance', [addressB58, { commitment: 'confirmed' }])).value);
}

/** True if the wallet still holds any SPL / Token-2022 balance (used by safe-destroy). */
export async function hasTokenBalance(url, addressB58) {
  for (const programId of [TOKEN_PID, TOKEN2022_PID]) {
    const r = await rpc(url, 'getTokenAccountsByOwner', [addressB58, { programId }, { encoding: 'jsonParsed', commitment: 'confirmed' }]);
    for (const acc of r.value || []) {
      const amt = acc.account?.data?.parsed?.info?.tokenAmount?.amount;
      if (amt && BigInt(amt) > 0n) return true;
    }
  }
  return false;
}

/**
 * Send SOL from the agent wallet to its OWNER. `lamports` null → full sweep (balance − fee).
 * Returns { signature, lamports, remaining }. Throws (fail-closed) on any RPC/validation error.
 */
export async function withdrawSol({ url, seed, fromB58, ownerB58, lamports }) {
  if (!ownerB58) throw Object.assign(new Error('no owner address on file — cannot withdraw'), { status: 409, code: 'no-owner' });
  const fromPub = base58decode(fromB58), ownerPub = base58decode(ownerB58);
  const bal = await getBalanceLamports(url, fromB58);
  const spendable = bal - FEE_RESERVE;
  const send = lamports != null ? BigInt(lamports) : spendable;
  if (send <= 0n) throw Object.assign(new Error(`nothing to withdraw (balance ${bal} ≤ fee reserve)`), { status: 400, code: 'empty' });
  if (send > spendable) throw Object.assign(new Error(`insufficient: balance ${bal}, requested ${send} + ${FEE_RESERVE} fee`), { status: 400, code: 'insufficient' });

  const { blockhash } = (await rpc(url, 'getLatestBlockhash', [{ commitment: 'confirmed' }])).value;
  const msg = buildSolTransferMessage(fromPub, ownerPub, send, blockhash);
  const txB64 = signTransferTx(seed, msg);
  const signature = await rpc(url, 'sendTransaction', [txB64, { encoding: 'base64', skipPreflight: false, preflightCommitment: 'confirmed' }]);

  // Confirm (poll up to ~30s). A landed-but-unconfirmed sig is still returned; the caller logs it.
  for (let i = 0; i < 15; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const st = (await rpc(url, 'getSignatureStatuses', [[signature]])).value?.[0];
    if (st && (st.confirmationStatus === 'confirmed' || st.confirmationStatus === 'finalized')) {
      if (st.err) throw Object.assign(new Error(`transfer failed on-chain: ${JSON.stringify(st.err)}`), { status: 502, code: 'tx-failed', signature });
      break;
    }
  }
  return { signature, lamports: send.toString(), remaining: (bal - send - FEE_RESERVE).toString() };
}
