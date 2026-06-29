// node-host/oci.js — running an UNTRUSTED bundle inside a hardened container (AGENT_BUNDLES.md §5.4, B2).
//
// B2 reuses the B1 node tarball but executes it inside a locked-down container so the guest can't harm
// the host: read-only rootfs, all capabilities dropped, no-new-privileges, non-root, pids/memory caps,
// the verified bundle mounted READ-ONLY, and the data dir the ONLY writable mount. Network is forced
// through the per-node egress proxy (HTTPS_PROXY) — no direct route out. The publisher ships a node
// tarball; the runtime ('oci') just means "must run containerized."
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

// Detect a usable OCI runtime. We require not just the binary but a working daemon/permissions, so an
// absent or unusable runtime degrades honestly (the node won't advertise 'oci' and won't be handed
// untrusted bundles) rather than silently running untrusted code without isolation.
export function detectOciRuntime() {
  for (const [cmd, probe] of [['docker', ['info']], ['podman', ['info']]]) {
    try {
      execFileSync(cmd, probe, { stdio: 'ignore', timeout: 5000 });
      return cmd;
    } catch { /* not usable */ }
  }
  return null;
}

// Detect a usable microVM backend (B3 — AGENT_BUNDLES.md §5.7). A microVM gives each agent its OWN
// guest kernel, so a container escape needs a hypervisor break (a tiny VMM surface) instead of a
// host-kernel 0-day. It needs only KVM (`/dev/kvm` — hardware virtualization, present on ~all consumer
// CPUs; NO TEE required) plus a Kata runtime registered with the container engine — then the SAME
// hardened oci container (buildContainerSpec) runs VM-backed via `--runtime`. Honest like
// detectOciRuntime: no usable /dev/kvm or no Kata runtime → null → the node won't advertise 'microvm'
// and the scheduler won't hand it a microvm-required bundle (fail-closed).
//
// Firecracker-direct (a VM-image artifact + a hand-managed tap device, no container engine) is the
// leaner future path with its own run path — NOT this one; this scaffolding gates on the Kata path.
export function detectMicroVm() {
  try { fs.accessSync('/dev/kvm', fs.constants.R_OK | fs.constants.W_OK); }
  catch { return null; } // no usable KVM → can't run a microVM at all
  for (const cmd of ['kata-runtime', 'containerd-shim-kata-v2']) {
    try { execFileSync(cmd, ['--version'], { stdio: 'ignore', timeout: 5000 }); return cmd; }
    catch { /* not installed/usable */ }
  }
  return null;
}

// Build the container run argv for a verified, unpacked node bundle. Pure + testable: no side effects.
//
// SECURITY: `network` MUST be an isolated network with NO route except the per-node egress proxy.
// HTTPS_PROXY is only an in-process convention a hostile agent can ignore — it is NOT containment. The
// node-host refuses to run an untrusted bundle unless such a network is configured (fail-closed); the
// operator wires it as a `--internal` bridge carrying only the proxy (+ a DOCKER-USER drop rule).
// Pinned base image (digest, not a tag) so the rootfs is reproducible + can't be swapped under us.
// Override with CIRCUIT_OCI_IMAGE (also a digest) to track a newer base.
export const DEFAULT_OCI_IMAGE = 'node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0';

export function buildContainerSpec({
  runtime = 'docker', image = DEFAULT_OCI_IMAGE, name,
  bundleDir, dataDir, entry, env = {}, proxyUrl, network, seccompProfile = 'default', memMb = 512, pids = 256,
  // B3 (§5.7): when set (e.g. 'io.containerd.kata.v2' / 'kata-runtime'), run this SAME hardened container
  // inside a microVM — its own guest kernel, so escape needs a hypervisor break, not a host-kernel 0-day.
  // Everything else (RO rootfs, dropped caps, seccomp, non-root, egress proxy, resource caps) is byte-for
  // byte identical; the microVM is strictly an isolation upgrade. Null → default host-kernel runtime (runc).
  vmRuntime = null,
}) {
  if (!name || !bundleDir || !dataDir || !entry) throw new Error('buildContainerSpec: name/bundleDir/dataDir/entry required');
  if (!network) throw new Error('buildContainerSpec: an isolated egress network is required (HTTPS_PROXY is not containment)');
  // Host-only vars make no sense in the container — drop them so the container's own values stand.
  const DROP = new Set(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'CIRCUIT_AGENT_DATA_DIR']);
  const envFlags = [];
  for (const [k, v] of Object.entries(env)) if (!DROP.has(k)) envFlags.push('-e', `${k}=${v}`);
  const proxyFlags = proxyUrl
    ? ['-e', `HTTPS_PROXY=${proxyUrl}`, '-e', `https_proxy=${proxyUrl}`, '-e', 'NO_PROXY=', '-e', 'no_proxy=']
    : [];
  const args = [
    'run', '--rm', '--name', name,
    ...(vmRuntime ? ['--runtime', vmRuntime] : []), // B3: microVM-backed runtime (own kernel); else host kernel
    '--network', network,                   // isolated net — only the egress proxy is reachable
    '--read-only',                         // RO rootfs
    '--cap-drop', 'ALL',                   // no Linux capabilities
    '--security-opt', 'no-new-privileges',
    '--security-opt', `seccomp=${seccompProfile}`, // explicit seccomp (pin a tight profile in prod)
    '--user', '65534:65534',               // nobody:nogroup
    '--pids-limit', String(pids),
    '--memory', `${memMb}m`, '--memory-swap', `${memMb}m`,
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
    '-v', `${bundleDir}:/app:ro`,          // the verified bundle, read-only
    '-v', `${dataDir}:/data:rw`,           // the ONLY writable mount
    '-w', '/data',
    ...envFlags,
    // container-correct values LAST so they win over anything passed in
    '-e', 'CIRCUIT_AGENT_DATA_DIR=/data',
    '-e', 'HOME=/data',
    ...proxyFlags,
    image,
    'node', `/app/${entry}`,
  ];
  return { command: runtime, args };
}
