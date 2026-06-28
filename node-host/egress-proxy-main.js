// Container entrypoint for the egress proxy SIDECAR (docs/SANDBOX_STATUS.md).
//
// The untrusted agent runs on an --internal network with NO route out. This proxy runs as its own
// container on BOTH that internal network (so the agent can reach it by name) AND a normal bridge (so
// the proxy — and ONLY the proxy — can reach the internet). The agent's HTTPS_PROXY points here; this
// is its single, allowlisted egress path. The agent never shares a network interface with the host.
//
//   env CIRCUIT_EGRESS_ALLOW  comma-separated allowed hostnames (the resolved egress classes)
//   env CIRCUIT_PROXY_PORT    listen port (default 8888)
import { createEgressProxy } from './egress-proxy.js';

const allowedHosts = (process.env.CIRCUIT_EGRESS_ALLOW || '').split(',').map((s) => s.trim()).filter(Boolean);
const port = parseInt(process.env.CIRCUIT_PROXY_PORT || '8888', 10);

const proxy = createEgressProxy({
  allowedHosts,
  onEvent: (ev, host, reason) => console.log(`[egress] ${ev} ${host}${reason ? ' (' + reason + ')' : ''}`),
});
proxy.listen(port, '0.0.0.0', () => console.log(`[egress] sidecar proxy on :${port} allow=[${allowedHosts.join(',') || 'none'}]`));
