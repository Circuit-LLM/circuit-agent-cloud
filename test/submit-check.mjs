// Offline checks for the live-submit tx signing (no network, no funds).
// Validates the byte-level surgery: locate the message, find the agent's signer
// slot, sign the whole message, drop the sig in the right place.
import { newKeypair, verify, base58decode } from '../lib/ed25519.js';
import { signSerializedTx, readCompactU16, findSignerIndex, inspectTransaction } from '../signer/submit.js';

const SYSTEM = '11111111111111111111111111111111';
const JUP = 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log(`  ${c ? '✓ PASS' : '✗ FAIL'}  ${m}`); };

// Build a minimal Solana tx: [sigCount][sigCount×64 zeros][message].
function buildTx({ versioned, numReqSig, keys, sigCount }) {
  const header = versioned ? Buffer.from([0x80, numReqSig, 0, 1]) : Buffer.from([numReqSig, 0, 1]);
  const keyCount = Buffer.from([keys.length]); // compact-u16 (small)
  const keyBytes = Buffer.concat(keys);
  const body = Buffer.concat([Buffer.alloc(32, 9), Buffer.from([0])]); // fake blockhash + 0 ixs
  const message = Buffer.concat([header, keyCount, keyBytes, body]);
  const tx = Buffer.concat([Buffer.from([sigCount]), Buffer.alloc(sigCount * 64), message]);
  return { tx, message };
}
function extract(signedB64) {
  const buf = Buffer.from(signedB64, 'base64');
  const [sigCount, sigStart] = readCompactU16(buf, 0);
  const message = buf.subarray(sigStart + sigCount * 64);
  const sigAt = (i) => buf.subarray(sigStart + i * 64, sigStart + (i + 1) * 64);
  return { sigCount, message, sigAt };
}

// 1. v0 single-signer at index 0
{
  const agent = newKeypair(), prog = newKeypair();
  const { tx, message } = buildTx({ versioned: true, numReqSig: 1, keys: [agent.pubkey, prog.pubkey], sigCount: 1 });
  const out = extract(signSerializedTx(agent.seed, agent.pubkey, tx.toString('base64')));
  ok(out.message.equals(message), 'v0: message preserved byte-for-byte');
  ok(verify(agent.pubkey, out.message, out.sigAt(0)), 'v0: inserted signature verifies against the wallet');
}

// 2. legacy single-signer at index 0
{
  const agent = newKeypair(), prog = newKeypair();
  const { tx, message } = buildTx({ versioned: false, numReqSig: 1, keys: [agent.pubkey, prog.pubkey], sigCount: 1 });
  const out = extract(signSerializedTx(agent.seed, agent.pubkey, tx.toString('base64')));
  ok(verify(agent.pubkey, out.message, out.sigAt(0)), 'legacy: inserted signature verifies');
}

// 3. agent is the SECOND required signer (idx 1) — sig must land in slot 1, slot 0 untouched
{
  const other = newKeypair(), agent = newKeypair();
  const { tx } = buildTx({ versioned: true, numReqSig: 2, keys: [other.pubkey, agent.pubkey], sigCount: 2 });
  const fi = findSignerIndex(extract(tx.toString('base64')).message, agent.pubkey);
  ok(fi.idx === 1 && fi.numReqSig === 2, 'finds the agent at signer index 1');
  const out = extract(signSerializedTx(agent.seed, agent.pubkey, tx.toString('base64')));
  ok(verify(agent.pubkey, out.message, out.sigAt(1)), 'multi-signer: sig lands in the agent slot');
  ok(out.sigAt(0).equals(Buffer.alloc(64)), 'multi-signer: the other signer slot is left untouched');
}

// 4. refuse to sign if the agent isn't in the account list (can't sign arbitrary bytes)
{
  const agent = newKeypair(), stranger = newKeypair(), prog = newKeypair();
  const { tx } = buildTx({ versioned: true, numReqSig: 1, keys: [stranger.pubkey, prog.pubkey], sigCount: 1 });
  let threw = false;
  try { signSerializedTx(agent.seed, agent.pubkey, tx.toString('base64')); } catch { threw = true; }
  ok(threw, 'refuses a transaction the agent does not sign');
}

// ── inspectTransaction (the don't-blind-sign gauntlet) ──
function buildFullTx({ numReqSig = 1, keys, instructions }) {
  const header = Buffer.from([0x80, numReqSig, 0, 1]); // v0
  const keyCount = Buffer.from([keys.length]);
  const blockhash = Buffer.alloc(32, 3);
  const ixCount = Buffer.from([instructions.length]);
  const ixBufs = instructions.map((ix) => Buffer.concat([
    Buffer.from([ix.programIdIndex]),
    Buffer.from([ix.accounts.length]), Buffer.from(ix.accounts),
    Buffer.from([ix.data.length]), ix.data,
  ]));
  const message = Buffer.concat([header, keyCount, Buffer.concat(keys), blockhash, ixCount, ...ixBufs]);
  return Buffer.concat([Buffer.from([Math.max(1, numReqSig)]), Buffer.alloc(Math.max(1, numReqSig) * 64), message]).toString('base64');
}

// 5. agent is a signer, only allowlisted programs → accepted
{
  const agent = newKeypair();
  const tx = buildFullTx({ keys: [agent.pubkey, base58decode(SYSTEM), base58decode(JUP)], instructions: [{ programIdIndex: 2, accounts: [0, 1], data: Buffer.from([9, 9]) }] });
  let okRun = false; try { const r = inspectTransaction(tx, agent.pubkey); okRun = r.unresolved.length === 0; } catch {}
  ok(okRun, 'inspect: accepts a swap whose programs are all allowlisted');
}
// 6. SPONSORED swap — agent is a non-fee-payer signer (relayer pays), allowlisted → accepted
{
  const relayer = newKeypair(), agent = newKeypair();
  const tx = buildFullTx({ numReqSig: 2, keys: [relayer.pubkey, agent.pubkey, base58decode(JUP)], instructions: [{ programIdIndex: 2, accounts: [0, 1], data: Buffer.alloc(0) }] });
  let okRun = false; try { const r = inspectTransaction(tx, agent.pubkey); okRun = r.signerIndex === 1 && r.feePayer === relayer.address; } catch (e) { okRun = false; }
  ok(okRun, 'inspect: accepts a sponsored swap (relayer fee payer, agent is a signer)');
}
// 7. agent is present but NOT a required signer → rejected
{
  const payer = newKeypair(), agent = newKeypair();
  const tx = buildFullTx({ numReqSig: 1, keys: [payer.pubkey, agent.pubkey, base58decode(JUP)], instructions: [{ programIdIndex: 2, accounts: [0], data: Buffer.alloc(0) }] });
  let threw = false; try { inspectTransaction(tx, agent.pubkey); } catch (e) { threw = /required signer/.test(e.message); }
  ok(threw, 'inspect: rejects a transaction where the agent is not a required signer');
}
// 8. invokes a non-allowlisted program in the static keys → rejected (no blind sign)
{
  const agent = newKeypair(), evil = newKeypair();
  const tx = buildFullTx({ keys: [agent.pubkey, evil.pubkey], instructions: [{ programIdIndex: 1, accounts: [0], data: Buffer.from([1]) }] });
  let threw = false; try { inspectTransaction(tx, agent.pubkey); } catch (e) { threw = /non-allowlisted/.test(e.message); }
  ok(threw, 'inspect: refuses a transaction that calls an unknown program');
}
// 9. program loaded via an ALT (index past static keys) → surfaced as unresolved, not signed blindly
{
  const agent = newKeypair();
  const tx = buildFullTx({ keys: [agent.pubkey], instructions: [{ programIdIndex: 5, accounts: [0], data: Buffer.alloc(0) }] });
  const r = inspectTransaction(tx, agent.pubkey);
  ok(r.unresolved.length === 1 && r.unresolved[0] === 5, 'inspect: reports ALT-loaded programs as unresolved (residual flagged)');
}

console.log(`\n${fail === 0 ? 'ALL GREEN' : 'FAILURES'} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
