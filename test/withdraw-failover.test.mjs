// test/withdraw-failover.test.mjs — the signer's RPC layer fails over past a blocked or
// rate-limited endpoint to a working one, so a single provider's 403 (IP/provider block) or 429
// (exhausted quota) can't take owner-withdraw offline. This is the exact failure that surfaced as
// `control plane 502: withdraw failed: getBalance: {403 ...}`. Mocks fetch; no network.
//   node test/withdraw-failover.test.mjs
import { getBalanceLamports } from '../signer/withdraw.js';

let pass = 0, fail = 0;
const ok = (c, m) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${m}`); return c; };
const ADDR = 'So11111111111111111111111111111111111111112';
const jr = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

async function run() {
  const realFetch = globalThis.fetch;

  // 1) A 403-blocked primary falls over to a working secondary (the reported bug).
  {
    const seen = [];
    globalThis.fetch = async (u) => {
      seen.push(u);
      return u.includes('blocked')
        ? jr(403, { jsonrpc: '2.0', id: 1, error: { code: 403, message: 'Your IP or provider is blocked from this endpoint' } })
        : jr(200, { jsonrpc: '2.0', id: 1, result: { context: { slot: 1 }, value: 4242 } });
    };
    const bal = await getBalanceLamports(['https://blocked.example', 'https://good.example'], ADDR);
    ok(bal === 4242n, `fails over the 403 endpoint and returns the next one's balance (got ${bal})`);
    ok(seen.length === 2 && seen[1].includes('good'), 'tries the blocked endpoint first, then the working one');
  }

  // 2) Every endpoint blocked/limited → one clear rpc-unavailable error (not a raw 403/429).
  {
    globalThis.fetch = async () => jr(429, { jsonrpc: '2.0', id: 1, error: { code: -32429, message: 'max usage reached' } });
    let err;
    try { await getBalanceLamports(['https://a.example', 'https://b.example'], ADDR); }
    catch (e) { err = e; }
    ok(err && err.code === 'rpc-unavailable' && err.status === 503, 'all-endpoints-down surfaces code=rpc-unavailable status=503');
  }

  // 3) A genuine method error is surfaced immediately, NOT masked by trying other endpoints.
  {
    let calls = 0;
    globalThis.fetch = async () => { calls++; return jr(200, { jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'Invalid params' } }); };
    let err;
    try { await getBalanceLamports(['https://a.example', 'https://b.example'], ADDR); }
    catch (e) { err = e; }
    ok(err && /Invalid params/.test(err.message) && err.code !== 'rpc-unavailable', 'a hard RPC error is thrown as-is');
    ok(calls === 1, 'a non-transient error does not fan out to the other endpoints');
  }

  globalThis.fetch = realFetch;
  console.log(`\n${fail === 0 ? '✓' : '✗'} withdraw-failover: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}
run();
