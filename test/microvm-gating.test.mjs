// B3 — microVM isolation tier (AGENT_BUNDLES.md §5.7). microVM is the TOP rung of the caps.sandbox
// ladder: the SAME hardened oci container, run inside a lightweight VM (its own guest kernel), so an
// escape needs a hypervisor break instead of a host-kernel 0-day. It is NOT a new bundle `runtime` —
// the artifact stays 'oci' (the signed manifest is untouched); a microvm NODE just runs it VM-backed.
import assert from 'node:assert';
import { nodeSatisfies, SANDBOX_RANK } from '../lib/proto.js';
import { buildContainerSpec, detectMicroVm } from '../node-host/oci.js';

const node = (sandbox, trusted = false) => ({ caps: { sandbox }, trusted });
const bundleAgent = (runtime, requireSandbox) => ({ spec: { bundle: { runtime, manifest: { runtime } }, ...(requireSandbox ? { requireSandbox } : {}) } });

// ── ladder: microvm is strictly stronger than oci ───────────────────────────────────
assert.equal(SANDBOX_RANK.oci < SANDBOX_RANK.microvm, true, 'microvm ranks above oci (separate kernel)');
assert.equal(SANDBOX_RANK.none < SANDBOX_RANK.node && SANDBOX_RANK.node < SANDBOX_RANK.oci, true);
console.log('  ✓ SANDBOX_RANK: none < node < oci < microvm');

// ── a microvm node transparently satisfies oci/node bundles (it's a superset) ────────
assert.equal(nodeSatisfies(node('microvm', true), bundleAgent('oci')), true, 'a (trusted) microvm node runs an oci bundle, VM-backed');
assert.equal(nodeSatisfies(node('microvm'), bundleAgent('node')), true, 'a microvm node also runs node-runtime bundles');
assert.equal(nodeSatisfies(node('microvm', false), bundleAgent('oci')), false, 'an UNTRUSTED microvm node is still refused an oci bundle (attestation gate unchanged)');
console.log('  ✓ microvm node satisfies oci/node requirements (attestation gate for oci preserved)');

// ── spec.requireSandbox: an owner can INSIST on microVM isolation for a plain oci bundle ─────────────
assert.equal(nodeSatisfies(node('oci', true), bundleAgent('oci', 'microvm')), false, 'oci node cannot satisfy requireSandbox=microvm');
assert.equal(nodeSatisfies(node('microvm', true), bundleAgent('oci', 'microvm')), true, 'a microvm node satisfies requireSandbox=microvm');
// requireSandbox also lifts a node-runtime bundle's floor
assert.equal(nodeSatisfies(node('node'), bundleAgent('node', 'microvm')), false, 'requireSandbox lifts the floor above the runtime default');
assert.equal(nodeSatisfies(node('microvm'), bundleAgent('node', 'microvm')), true);
// an unknown requireSandbox is ignored (ranks 0) — placement falls back to the runtime floor
assert.equal(nodeSatisfies(node('oci', true), bundleAgent('oci', 'bogus-tier')), true, 'unknown requireSandbox is ignored, not fail-closed at placement');
console.log('  ✓ spec.requireSandbox forces a stronger tier without touching the signed manifest');

// ── detection is honest: a runtime id or null, never throws (no /dev/kvm or no Kata here → null) ─────
const mv = detectMicroVm();
assert.ok(mv === null || typeof mv === 'string');
console.log(`  ✓ detectMicroVm() = ${mv === null ? "null (no /dev/kvm + Kata → node won't advertise microvm; fail-closed)" : mv}`);

// ── the microVM is the SAME hardened container + one extra flag (--runtime) ──────────
{
  const base = {
    runtime: 'docker', name: 'circuit-agt-1', bundleDir: '/cache/abc', dataDir: '/data/agt-1',
    entry: 'agent.js', env: { CIRCUIT_AGENT_SESSION: 'tok' }, proxyUrl: 'http://p:8888', network: 'circuit-egress', memMb: 256,
  };
  const plain = buildContainerSpec(base).args.join(' ');
  assert.ok(!plain.includes('--runtime'), 'an ordinary oci node uses the default (host-kernel) runtime');

  const { args } = buildContainerSpec({ ...base, vmRuntime: 'io.containerd.kata.v2' });
  const s = args.join(' ');
  assert.ok(s.includes('--runtime io.containerd.kata.v2'), 'microvm injects the VM-backed runtime');
  // the --runtime flag sits in the run options, before the image/command
  assert.ok(args.indexOf('--runtime') < args.indexOf('--network'), '--runtime is a run option');
  // ALL the B2 hardening is still present, byte-for-byte — microVM is purely additive
  for (const flag of ['--read-only', '--cap-drop ALL', '--security-opt no-new-privileges', '--security-opt seccomp=', '--user 65534:65534', '--pids-limit', '--memory 256m']) {
    assert.ok(s.includes(flag), `microvm spec keeps ${flag}`);
  }
  assert.ok(s.includes('/cache/abc:/app:ro') && s.includes('HTTPS_PROXY=http://p:8888'), 'RO bundle + proxy egress unchanged');
  console.log('  ✓ buildContainerSpec(vmRuntime) = the B2 hardened spec + one --runtime flag (everything else identical)');
}

console.log('microvm-gating (B3): all assertions passed');
