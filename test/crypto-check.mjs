// Quick standalone check of the zero-dep crypto primitives.
import { newKeypair, fromSeed, sign, verify, base58, seal, open, sha256hex } from '../lib/ed25519.js';
import crypto from 'node:crypto';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); };

// 1. Keypair + address shape (Solana base58 pubkey, 32-44 chars).
const kp = newKeypair();
ok(kp.pubkey.length === 32, `pubkey is 32 bytes (${kp.pubkey.length})`);
ok(kp.address.length >= 32 && kp.address.length <= 44, `address looks like Solana base58 (${kp.address})`);

// 2. Deterministic from seed.
const kp2 = fromSeed(kp.seed);
ok(kp2.address === kp.address, 'fromSeed is deterministic');

// 3. Sign + verify round-trip, and reject a tampered message.
const msg = JSON.stringify({ kind: 'buy', sizeSol: 0.01, ts: 123 });
const sig = sign(kp.priv, msg);
ok(sig.length === 64, `signature is 64 bytes (${sig.length})`);
ok(verify(kp.pubkey, msg, sig) === true, 'verify accepts a valid signature');
ok(verify(kp.pubkey, msg + 'x', sig) === false, 'verify rejects a tampered message');
const other = newKeypair();
ok(verify(other.pubkey, msg, sig) === false, 'verify rejects a wrong key');

// 4. base58 known vector (all-zero 32 bytes -> 32 '1's).
ok(base58(Buffer.alloc(32)) === '1'.repeat(32), 'base58 leading-zero handling');

// 5. AES-256-GCM seal/open round-trip; tamper detection.
const master = crypto.randomBytes(32);
const sealed = seal(master, kp.seed);
const opened = open(master, sealed);
ok(Buffer.compare(opened, kp.seed) === 0, 'seal/open round-trips the seed');
let tampered = false;
try { const bad = { ...sealed, ct: sealed.ct.replace(/.$/, (x) => (x === '0' ? '1' : '0')) }; open(master, bad); } catch { tampered = true; }
ok(tampered, 'GCM auth tag rejects tampered ciphertext');

// 6. sha256hex stable.
ok(sha256hex('abc') === crypto.createHash('sha256').update('abc').digest('hex'), 'sha256hex matches');

console.log(`\n${fail === 0 ? 'ALL GREEN' : 'FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
