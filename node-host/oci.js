// node-host/oci.js — running an UNTRUSTED bundle inside a hardened container (AGENT_BUNDLES.md §5.4, B2).
//
// B2 reuses the B1 node tarball but executes it inside a locked-down container so the guest can't harm
// the host: read-only rootfs, all capabilities dropped, no-new-privileges, non-root, pids/memory caps,
// the verified bundle mounted READ-ONLY, and the data dir the ONLY writable mount. Network is forced
// through the per-node egress proxy (HTTPS_PROXY) — no direct route out. The publisher ships a node
// tarball; the runtime ('oci') just means "must run containerized."
import { execFileSync } from 'node:child_process';

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

// Build the container run argv for a verified, unpacked node bundle. Pure + testable: no side effects.
export function buildContainerSpec({
  runtime = 'docker', image = 'node:20-bookworm-slim', name,
  bundleDir, dataDir, entry, env = {}, proxyUrl, memMb = 512, pids = 256,
}) {
  if (!name || !bundleDir || !dataDir || !entry) throw new Error('buildContainerSpec: name/bundleDir/dataDir/entry required');
  // Host-only vars make no sense in the container — drop them so the container's own values stand.
  const DROP = new Set(['PATH', 'HOME', 'TMPDIR', 'LANG', 'TZ', 'CIRCUIT_AGENT_DATA_DIR']);
  const envFlags = [];
  for (const [k, v] of Object.entries(env)) if (!DROP.has(k)) envFlags.push('-e', `${k}=${v}`);
  const proxyFlags = proxyUrl
    ? ['-e', `HTTPS_PROXY=${proxyUrl}`, '-e', `https_proxy=${proxyUrl}`, '-e', 'NO_PROXY=', '-e', 'no_proxy=']
    : [];
  const args = [
    'run', '--rm', '--name', name,
    '--read-only',                         // RO rootfs
    '--cap-drop', 'ALL',                   // no Linux capabilities
    '--security-opt', 'no-new-privileges',
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
