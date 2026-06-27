// node-host/egress-proxy.js — the per-node egress proxy (AGENT_BUNDLES.md §6, phase B2).
//
// An untrusted bundle has NO default route; its only way out is this proxy. The proxy permits a
// connection only when (a) the host is on the agent's resolved egress allowlist AND (b) the host does
// not resolve into the operator's own/private network (assertPublicHost) — so a hostile agent can't
// portscan the LAN, hit other local services, or reach the cloud metadata endpoint. Per-agent, so
// rate-limits and logs are per-agent. Fail-closed: anything not explicitly allowed is denied.
import http from 'node:http';
import net from 'node:net';
import { assertPublicHost } from '../lib/netguard.js';

// Resolve the manifest's egress CLASSES to concrete upstream hosts. The agent never names hosts; the
// node maps the classes it has enabled. An unknown/disabled class contributes nothing (deny by default).
export function resolveEgressHosts(classes, endpoints) {
  const out = new Set();
  for (const c of classes || []) {
    const url = endpoints?.[c];
    if (!url) continue; // class not enabled on this node
    try { out.add(new URL(url).hostname); } catch { /* ignore malformed */ }
  }
  return [...out];
}

// Pure, testable decision: may this agent reach `host`?
export async function egressDecision(host, { allowedHosts, lookup } = {}) {
  if (!host) return { allow: false, reason: 'no-host' };
  if (!allowedHosts || !allowedHosts.includes(host)) return { allow: false, reason: 'not-allowlisted' };
  try {
    await assertPublicHost(host, lookup ? { lookup } : {});
  } catch (e) {
    return { allow: false, reason: e.message };
  }
  return { allow: true };
}

// A forward proxy bound to loopback; the agent's container is wired so this is its only egress.
// HTTPS (CONNECT) is tunneled to allowed hosts; plain HTTP forwarding is disabled (agents use TLS).
export function createEgressProxy({ allowedHosts, onEvent } = {}) {
  const emit = (ev, host, reason) => { try { onEvent?.(ev, host, reason); } catch {} };

  const server = http.createServer((req, res) => {
    emit('deny', req.headers.host, 'http-forward-disabled');
    res.writeHead(403, { 'content-type': 'text/plain' });
    res.end('egress: plain HTTP disabled — use https');
  });

  server.on('connect', async (req, clientSocket, head) => {
    const [host, portStr] = (req.url || '').split(':');
    const port = parseInt(portStr || '443', 10);
    const d = await egressDecision(host, { allowedHosts });
    if (!d.allow) {
      emit('deny', host, d.reason);
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      clientSocket.destroy();
      return;
    }
    const upstream = net.connect(port, host, () => {
      emit('allow', host);
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });

  return server;
}
