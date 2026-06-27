// B2 — the egress proxy: an untrusted bundle reaches ONLY its resolved allowlist, never the host's own
// network. Covers class→host resolution, the pure decision, and a LIVE proxy denying a CONNECT.
import assert from 'node:assert';
import http from 'node:http';
import net from 'node:net';
import { egressDecision, resolveEgressHosts, createEgressProxy } from '../node-host/egress-proxy.js';

// ── class → host resolution (deny by default for disabled/unknown classes) ─────────
{
  const endpoints = { data: 'https://data.circuit.tld', rpc: 'https://rpc.circuit.tld:443', jupiter: 'https://api.jup.ag' };
  const hosts = resolveEgressHosts(['data', 'rpc', 'inference', 'bogus'], endpoints);
  assert.deepEqual(hosts.sort(), ['data.circuit.tld', 'rpc.circuit.tld'], 'only enabled classes resolve; unknown/disabled drop');
  console.log('  ✓ egress classes resolve to enabled hosts only');
}

// ── decision: returns the VALIDATED IP (so the caller connects to it, not a re-resolved name) ──
{
  const allowedHosts = ['data.circuit.tld', 'api.jup.ag'];
  const pub = async () => [{ address: '93.184.216.34' }];
  const ok = await egressDecision('data.circuit.tld', { allowedHosts, lookup: pub });
  assert.equal(ok.allow, true);
  assert.equal(ok.ip, '93.184.216.34', 'decision returns the validated IP to connect to (no re-resolve)');
  assert.equal((await egressDecision('evil.com', { allowedHosts, lookup: pub })).reason, 'not-allowlisted');
  assert.equal((await egressDecision('DATA.circuit.tld.', { allowedHosts, lookup: pub })).allow, true, 'host normalization (case + trailing dot)');
  // a host resolving into the private network is refused (DNS-rebind / metadata)
  const priv = async () => [{ address: '169.254.169.254' }];
  const d = await egressDecision('data.circuit.tld', { allowedHosts, lookup: priv });
  assert.equal(d.allow, false);
  assert.match(d.reason, /private/);
  console.log('  ✓ decision: returns validated IP; normalized; DNS-rebind to metadata refused');
}

// ── live proxy: non-allowlisted host AND non-443 port are both refused with 403 ─────
const connectExpect = (allowedHosts, target, label) => new Promise((resolve, reject) => {
  const proxy = createEgressProxy({ allowedHosts });
  proxy.listen(0, '127.0.0.1', () => {
    const port = proxy.address().port;
    const sock = net.connect(port, '127.0.0.1', () => sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('\r\n\r\n')) {
        try { assert.match(buf, /^HTTP\/1\.1 403/, `${label}: expected 403, got ${buf.split('\r\n')[0]}`); sock.destroy(); proxy.close(); resolve(); }
        catch (e) { sock.destroy(); proxy.close(); reject(e); }
      }
    });
    sock.on('error', reject);
  });
});
await connectExpect(['allowed.example'], 'evil.example:443', 'non-allowlisted host');
console.log('  ✓ live proxy refuses CONNECT to a non-allowlisted host (403)');
await connectExpect(['allowed.example'], 'allowed.example:22', 'non-443 port');
console.log('  ✓ live proxy refuses CONNECT to a non-443 port on an allowlisted host (403)');

console.log('egress-proxy (B2): all assertions passed');
