// test/canonical-conformance.test.mjs — pins this repo's canonical serializers to the SHARED golden
// vectors (source of truth: circuit-sdk, docs/canonical-serialization.md). Drift here silently breaks
// cross-repo ed25519 signatures, so lock it in CI. Copy canonical-vectors.json alongside on update.
//   node test/canonical-conformance.test.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { stableStringify as ownerCanon } from '../lib/owner-auth.js';
import { stableStringify as nodeCanon } from '../lib/node-auth.js';
import { stableStringify as viCanon } from '../lib/verified-intent.js';

const here = dirname(fileURLToPath(import.meta.url));
const { undefinedSentinel, vectors } = JSON.parse(readFileSync(join(here, 'canonical-vectors.json'), 'utf8'));
const revive = (v) => v === undefinedSentinel ? undefined
  : (v === null || typeof v !== 'object') ? v
  : Array.isArray(v) ? v.map(revive)
  : Object.fromEntries(Object.keys(v).map((k) => [k, revive(v[k])]));

let pass = 0, fail = 0;
const check = (got, want, m) => {
  if (got === want) pass++;
  else { fail++; console.log(`  ✗ ${m}\n     want ${JSON.stringify(want)}\n     got  ${JSON.stringify(got)}`); }
};

// owner-auth + node-auth DROP undefined → they must match the SDK canonical on EVERY vector.
for (const v of vectors) {
  check(ownerCanon(revive(v.input)), v.canonical, `owner-auth: ${v.note}`);
  check(nodeCanon(revive(v.input)), v.canonical, `node-auth: ${v.note}`);
}
// verified-intent KEEPS undefined → only the undefined-free subset agrees until it converges to drop.
for (const v of vectors.filter((v) => !v.undefinedInput)) {
  check(viCanon(revive(v.input)), v.canonical, `verified-intent: ${v.note}`);
}

console.log(`\n${fail === 0 ? '✓' : '✗'} canonical-conformance: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
