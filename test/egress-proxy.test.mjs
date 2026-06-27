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

// ── decision: allowlisted+public allowed; not-listed denied; listed-but-private denied ──
{
  const allowedHosts = ['data.circuit.tld', 'api.jup.ag'];
  const pub = async () => [{ address: '93.184.216.34' }];
  assert.equal((await egressDecision('data.circuit.tld', { allowedHosts, lookup: pub })).allow, true);
  assert.equal((await egressDecision('evil.com', { allowedHosts, lookup: pub })).reason, 'not-allowlisted');
  // even if somehow allowlisted, a host resolving into the private network is refused (DNS-rebind)
  const priv = async () => [{ address: '169.254.169.254' }];
  const d = await egressDecision('data.circuit.tld', { allowedHosts, lookup: priv });
  assert.equal(d.allow, false);
  assert.match(d.reason, /private/);
  console.log('  ✓ decision: allowlist + public-only (DNS-rebind to metadata refused)');
}

// ── live proxy: a CONNECT to a non-allowlisted host is refused with 403 ─────────────
await new Promise((resolve, reject) => {
  const proxy = createEgressProxy({ allowedHosts: ['allowed.example'] });
  proxy.listen(0, '127.0.0.1', () => {
    const port = proxy.address().port;
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write('CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n');
    });
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString();
      if (buf.includes('\r\n\r\n')) {
        try {
          assert.match(buf, /^HTTP\/1\.1 403/, `expected 403, got: ${buf.split('\r\n')[0]}`);
          console.log('  ✓ live proxy refuses CONNECT to a non-allowlisted host (403)');
          sock.destroy(); proxy.close(); resolve();
        } catch (e) { sock.destroy(); proxy.close(); reject(e); }
      }
    });
    sock.on('error', reject);
  });
});

console.log('egress-proxy (B2): all assertions passed');
