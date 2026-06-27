// node-host/egress-proxy.js — the per-node egress proxy (AGENT_BUNDLES.md §6, phase B2).
//
// An untrusted bundle has NO default route; its only way out is this proxy. The proxy permits a
// connection only when (a) the destination is on the agent's resolved egress allowlist, (b) the port is
// 443 (TLS), and (c) the host does not resolve into the operator's own/private network. Crucially it
// resolves ONCE and connects to the VALIDATED IP literal (never re-resolving the hostname), so a
// DNS-rebinding record can't flip a vetted public name onto 169.254.169.254 between check and connect.
// Per-agent, fail-closed: anything not explicitly allowed is denied.
import http from 'node:http';
import net from 'node:net';
import { assertPublicHost } from '../lib/netguard.js';

const ALLOWED_PORT = 443;

// Normalize a hostname for allowlist comparison: lowercase, strip a single trailing dot, strip brackets.
const normHost = (h) => (h || '').toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');

// Resolve the manifest's egress CLASSES to concrete upstream hosts. The agent never names hosts; the
// node maps the classes it has enabled. An unknown/disabled class contributes nothing (deny by default).
export function resolveEgressHosts(classes, endpoints) {
  const out = new Set();
  for (const c of classes || []) {
    const url = endpoints?.[c];
    if (!url) continue; // class not enabled on this node
    try { out.add(normHost(new URL(url).hostname)); } catch { /* ignore malformed */ }
  }
  return [...out];
}

// Pure, testable decision: may this agent reach `host`? Returns the VALIDATED IP to connect to so the
// caller never re-resolves the name.
export async function egressDecision(host, { allowedHosts, lookup } = {}) {
  const h = normHost(host);
  if (!h) return { allow: false, reason: 'no-host' };
  const allow = (allowedHosts || []).map(normHost);
  if (!allow.includes(h)) return { allow: false, reason: 'not-allowlisted' };
  try {
    const addrs = await assertPublicHost(h, lookup ? { lookup } : {});
    return { allow: true, ip: addrs[0] };
  } catch (e) {
    return { allow: false, reason: e.message };
  }
}

// A forward proxy; the agent's container is wired so this is its only egress. HTTPS (CONNECT) is tunneled
// to allowed hosts on 443; plain HTTP forwarding is disabled (agents use TLS).
export function createEgressProxy({ allowedHosts, onEvent } = {}) {
  const emit = (ev, host, reason) => { try { onEvent?.(ev, host, reason); } catch {} };

  const server = http.createServer((req, res) => {
    emit('deny', req.headers.host, 'http-forward-disabled');
    res.writeHead(403, { 'content-type': 'text/plain' });
    res.end('egress: plain HTTP disabled — use https');
  });

  server.on('connect', async (req, clientSocket, head) => {
    // Parse the CONNECT authority robustly (handles [v6]:port) instead of split(':').
    let host, port;
    try {
      const u = new URL(`https://${req.url}`);
      host = u.hostname;
      port = u.port ? parseInt(u.port, 10) : 443;
    } catch {
      clientSocket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); clientSocket.destroy(); return;
    }
    if (port !== ALLOWED_PORT) {
      emit('deny', host, `port-${port}`);
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); clientSocket.destroy(); return;
    }
    const d = await egressDecision(host, { allowedHosts });
    if (!d.allow) {
      emit('deny', host, d.reason);
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); clientSocket.destroy(); return;
    }
    // Connect to the VALIDATED IP literal — not the hostname — so no second DNS resolution happens.
    const upstream = net.connect(port, d.ip, () => {
      emit('allow', host, d.ip);
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.setTimeout(30_000, () => upstream.destroy());
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });

  return server;
}
