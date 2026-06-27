// lib/netguard.js — reject connections to the host's own network (SSRF / egress guard).
//
// Used by the bundle pull (a node must never be coerced into fetching an internal URL) and by the B2
// egress proxy (an untrusted agent must never reach the operator's LAN or the cloud metadata endpoint).
// Blocks loopback, RFC-1918, CGNAT, link-local (incl. 169.254.169.254 metadata), ULA, and unspecified.
import dns from 'node:dns/promises';

const ipToLong = (ip) => ip.split('.').reduce((a, o) => ((a << 8) + (+o)) >>> 0, 0);
const v4InCidr = (ip, base, bits) => {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipToLong(ip) & mask) === (ipToLong(base) & mask);
};

export function isPrivateV4(ip) {
  return (
    v4InCidr(ip, '0.0.0.0', 8) ||        // "this" network / unspecified
    v4InCidr(ip, '10.0.0.0', 8) ||       // RFC1918
    v4InCidr(ip, '100.64.0.0', 10) ||    // CGNAT
    v4InCidr(ip, '127.0.0.0', 8) ||      // loopback
    v4InCidr(ip, '169.254.0.0', 16) ||   // link-local (incl. 169.254.169.254 metadata)
    v4InCidr(ip, '172.16.0.0', 12) ||    // RFC1918
    v4InCidr(ip, '192.168.0.0', 16)      // RFC1918
  );
}

export function isPrivateV6(ip) {
  const x = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (x === '::1' || x === '::') return true;             // loopback / unspecified
  if (x.startsWith('fe80')) return true;                  // link-local
  if (x.startsWith('fc') || x.startsWith('fd')) return true; // unique-local (ULA)
  if (x.startsWith('::ffff:')) return isPrivateV4(x.split(':').pop()); // v4-mapped
  return false;
}

export function isPrivateIp(ip) {
  return ip.includes(':') ? isPrivateV6(ip) : isPrivateV4(ip);
}

const isIpLiteral = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');

// Throw if `host` is — or resolves to — an address on the operator's own/private network.
export async function assertPublicHost(host, { lookup = dns.lookup } = {}) {
  const h = (host || '').replace(/^\[|\]$/g, '');
  if (!h || h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local')) {
    throw new Error(`blocked host (local name): ${host}`);
  }
  if (isIpLiteral(h)) {
    if (isPrivateIp(h)) throw new Error(`blocked host (private/loopback IP): ${host}`);
    return;
  }
  const addrs = await lookup(h, { all: true });
  if (!addrs.length) throw new Error(`blocked host (no DNS): ${host}`);
  for (const { address } of addrs) {
    if (isPrivateIp(address)) throw new Error(`blocked host (${host} → private ${address})`);
  }
}
