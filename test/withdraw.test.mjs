// test/withdraw.test.mjs — proves the hand-rolled System-transfer (signer/withdraw.js) is
// byte-identical to @solana/web3.js and that the signature verifies. This is fund-moving code
// in a zero-dep service, so we validate the bytes against the reference lib (dev-only; web3.js
// is borrowed from circuit-data-api's node_modules and never shipped in the signer).
//   node test/withdraw.test.mjs
import { createRequire } from 'module';
import { existsSync } from 'fs';
import { newKeypair, base58 } from '../lib/ed25519.js';
import { buildSolTransferMessage, signTransferTx } from '../signer/withdraw.js';
import crypto from 'node:crypto';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${m}`); return c; };

const W3_PATH = '/home/watchtower/circuit-data-api/package.json';
let web3 = null;
if (existsSync(W3_PATH)) {
  try { web3 = createRequire(W3_PATH)('@solana/web3.js'); } catch (e) { console.log('  (web3.js unavailable:', e.message, ')'); }
}

const from = newKeypair();
const to = newKeypair();
const lamports = 123_456_789;
const blockhash = base58(crypto.randomBytes(32)); // any 32-byte base58 stands in for a real blockhash

// 1. byte-for-byte vs web3.js compiled message
if (web3) {
  const { Transaction, SystemProgram, PublicKey } = web3;
  const tx = new Transaction();
  tx.add(SystemProgram.transfer({ fromPubkey: new PublicKey(from.address), toPubkey: new PublicKey(to.address), lamports }));
  tx.recentBlockhash = blockhash;
  tx.feePayer = new PublicKey(from.address);
  const w3msg = tx.compileMessage().serialize();
  const mine = buildSolTransferMessage(from.pubkey, to.pubkey, lamports, blockhash);
  ok(Buffer.compare(mine, w3msg) === 0, `transfer message is byte-identical to @solana/web3.js (${mine.length} bytes)`);

  // 2. full signed tx parses + signature verifies under web3.js
  const msg = buildSolTransferMessage(from.pubkey, to.pubkey, lamports, blockhash);
  const b64 = signTransferTx(from.seed, msg);
  const parsed = Transaction.from(Buffer.from(b64, 'base64'));
  ok(parsed.verifySignatures(), 'signature verifies under web3.js (agent is the valid signer)');
  ok(parsed.instructions.length === 1 && parsed.instructions[0].programId.equals(SystemProgram.programId), 'one System-transfer instruction');
  const amt = parsed.instructions[0].data.readBigUInt64LE(4);
  ok(amt === BigInt(lamports), `instruction carries the exact lamports (${amt})`);
  ok(parsed.instructions[0].keys[1].pubkey.toBase58() === to.address, 'destination is exactly the owner address');
} else {
  ok(false, 'web3.js reference not available — cannot validate fund-moving bytes (do NOT ship without this)');
}

console.log(`\n${fail === 0 ? '✓' : '✗'} withdraw: ${pass} passed, ${fail} failed`);
process.exitCode = fail === 0 ? 0 : 1;
