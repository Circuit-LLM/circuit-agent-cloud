// B2 — scheduler gating + the container spec. A bundle is only placed on a node that can sandbox it,
// and an untrusted (oci) bundle's container is built locked-down (RO rootfs, dropped caps, proxy egress).
import assert from 'node:assert';
import { nodeSatisfies, SANDBOX_RANK, isFirstPartyNodeRuntime } from '../lib/proto.js';
import { buildContainerSpec, detectOciRuntime } from '../node-host/oci.js';

// ── placement gating (AGENT_BUNDLES.md §5.6) ────────────────────────────────────────
const node = (sandbox, trusted = false) => ({ caps: { sandbox }, trusted });
const bundleAgent = (runtime) => ({ spec: { bundle: { runtime, manifest: { runtime } } } });
const builtin = { spec: { workload: 'agentd' } };

assert.equal(SANDBOX_RANK.none < SANDBOX_RANK.node && SANDBOX_RANK.node < SANDBOX_RANK.oci, true);

// built-in workloads run anywhere (today's behavior preserved)
for (const s of ['none', 'node', 'oci', undefined]) assert.equal(nodeSatisfies(node(s), builtin), true);

// a 'node' (trusted/own-fleet) bundle needs the node sandbox — trust flag NOT required
assert.equal(nodeSatisfies(node('none'), bundleAgent('node')), false, "none node can't take a bundle");
assert.equal(nodeSatisfies(node('node'), bundleAgent('node')), true);
assert.equal(nodeSatisfies(node('oci'), bundleAgent('node')), true, 'an oci node can also run node bundles');

// an 'oci' (untrusted) bundle needs an oci node AND an attested/trusted one
assert.equal(nodeSatisfies(node('none'), bundleAgent('oci')), false);
assert.equal(nodeSatisfies(node('node'), bundleAgent('oci')), false, "a node-only host won't host an untrusted bundle");
assert.equal(nodeSatisfies(node('oci', false), bundleAgent('oci')), false, 'an oci node that is NOT attested is refused an untrusted bundle');
assert.equal(nodeSatisfies(node('oci', true), bundleAgent('oci')), true, 'only an attested oci node hosts an untrusted bundle');
console.log('  ✓ scheduler places bundles only on nodes that can sandbox them (oci ⇒ attested/trusted)');

// ── host-side first-party gate for the unsandboxed 'node' runtime (MT#4) ─────────────
assert.equal(isFirstPartyNodeRuntime('ANYKEY', []), true, 'empty allowlist = own-fleet, any publisher');
assert.equal(isFirstPartyNodeRuntime('FIRST_PARTY', ['FIRST_PARTY']), true, 'listed publisher allowed');
assert.equal(isFirstPartyNodeRuntime('STRANGER', ['FIRST_PARTY']), false, 'a stranger cannot use the node runtime — must use oci');
console.log('  ✓ node-runtime gated to first-party publishers when an allowlist is set');

// ── container spec hardening ────────────────────────────────────────────────────────
{
  // an isolated network is now REQUIRED (HTTPS_PROXY is not containment) — building without it throws
  assert.throws(() => buildContainerSpec({ name: 'x', bundleDir: '/c', dataDir: '/d', entry: 'a.js' }), /isolated egress network is required/);

  const { command, args } = buildContainerSpec({
    runtime: 'docker', name: 'circuit-agt-1', bundleDir: '/cache/abc', dataDir: '/data/agt-1',
    entry: 'agent.js', env: { CIRCUIT_AGENT_SESSION: 'tok', AGENT_KEYPAIR: 'should-be-dropped-upstream', PATH: '/host/bin' },
    proxyUrl: 'http://172.17.0.1:54321', network: 'circuit-egress', memMb: 256,
  });
  const s = args.join(' ');
  assert.equal(command, 'docker');
  for (const flag of ['--network circuit-egress', '--read-only', '--cap-drop ALL', '--security-opt no-new-privileges', '--security-opt seccomp=', '--user 65534:65534', '--pids-limit', '--memory 256m']) {
    assert.ok(s.includes(flag), `container must set ${flag}`);
  }
  assert.ok(s.includes('/cache/abc:/app:ro'), 'bundle mounted read-only');
  assert.ok(s.includes('/data/agt-1:/data:rw'), 'data dir is the only writable mount');
  assert.ok(s.includes('HTTPS_PROXY=http://172.17.0.1:54321'), 'egress forced through the proxy');
  assert.ok(args[args.length - 1] === '/app/agent.js' && args[args.length - 2] === 'node', 'runs node /app/<entry>');
  assert.ok(!s.includes('PATH=/host/bin'), 'host PATH not leaked into the container');
  assert.ok(s.includes('CIRCUIT_AGENT_DATA_DIR=/data'), 'in-container data dir set to /data');
  assert.ok(s.includes('CIRCUIT_AGENT_SESSION=tok'), 'session token forwarded');
  console.log('  ✓ oci container spec is locked down (isolated --network, RO rootfs, dropped caps, seccomp, proxy egress, RO bundle)');
}

// detection is honest — returns a runtime string or null, never throws
const rt = detectOciRuntime();
assert.ok(rt === null || typeof rt === 'string');
console.log(`  ✓ detectOciRuntime() = ${rt === null ? 'null (no usable runtime → node won\'t advertise oci)' : rt}`);

console.log('sandbox-gating (B2): all assertions passed');
