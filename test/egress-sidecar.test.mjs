// Integration test for the controlled-egress sidecar (docs/SANDBOX_STATUS.md). Proves that an agent on
// the --internal network can reach ONLY its allowlisted hosts, via the proxy sidecar — never directly,
// never a denied host. Skips cleanly where docker isn't usable (CI / own-fleet without a runtime).
import { test } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dockerUsable = () => { try { execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 5000 }); return true; } catch { return false; } };

test('egress sidecar: agent reaches ONLY allowlisted hosts', { skip: dockerUsable() ? false : 'docker not usable' }, async () => {
  const NET = 'circuit-egress-test';
  const PROXY = 'circuit-egress-proxy-test';
  const dq = (...a) => { try { return execFileSync('docker', a, { encoding: 'utf8', timeout: 90000 }); } catch (e) { return (e.stdout || '').toString(); } };
  const quiet = (...a) => { try { execFileSync('docker', a, { stdio: 'ignore', timeout: 90000 }); } catch {} };

  quiet('network', 'rm', NET);
  quiet('network', 'create', '--internal', NET);
  quiet('rm', '-f', PROXY);
  try {
    quiet('run', '-d', '--name', PROXY, '--network', NET, '-v', `${REPO}:/proxy:ro`,
      '-e', 'CIRCUIT_EGRESS_ALLOW=api.circuitllm.xyz', '-e', 'CIRCUIT_PROXY_PORT=8888',
      'node:20-bookworm-slim', 'node', '/proxy/node-host/egress-proxy-main.js');
    quiet('network', 'connect', 'bridge', PROXY); // give ONLY the proxy an external route
    await new Promise((r) => setTimeout(r, 2500));
    const curl = (proxy, url) => dq('run', '--rm', '--network', NET, ...(proxy ? ['-e', `HTTPS_PROXY=${proxy}`] : []),
      'curlimages/curl:latest', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '12', url).trim();
    const allowed = curl(`http://${PROXY}:8888`, 'https://api.circuitllm.xyz/health');
    const denied  = curl(`http://${PROXY}:8888`, 'https://www.google.com');
    const direct  = curl(null, 'https://1.1.1.1');
    assert.equal(allowed, '200', `allowlisted host should be reachable via proxy (got ${allowed})`);
    assert.notEqual(denied, '200', `non-allowlisted host must be blocked (got ${denied})`);
    assert.notEqual(direct, '200', `direct egress must be blocked — no route (got ${direct})`);
  } finally {
    quiet('rm', '-f', PROXY);
    quiet('network', 'rm', NET);
  }
});
