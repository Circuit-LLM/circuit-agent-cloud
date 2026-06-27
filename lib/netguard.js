// lib/netguard.js — reject connections to the host's own network (SSRF / egress guard).
//
// Used by the bundle pull (a node must never be coerced into fetching an internal URL) and by the B2
// egress proxy (an untrusted agent must never reach the operator's LAN or the cloud metadata endpoint).
// Blocks loopback, RFC-1918, CGNAT, link-local (incl. 169.254.169.254 metadata), ULA, broadcast,
// multicast, reserved, benchmarking/TEST-NET, and unspecified — across IPv4 AND every IPv6 spelling of
// an embedded v4 (v4-mapped/compat, compressed or fully expanded).
import dns from 'node:dns/promises';
import net from 'node:net';

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
    v4InCidr(ip, '192.0.0.0', 24) ||     // IETF protocol assignments (NAT64/DS-Lite etc.)
    v4InCidr(ip, '192.0.2.0', 24) ||     // TEST-NET-1
    v4InCidr(ip, '192.168.0.0', 16) ||   // RFC1918
    v4InCidr(ip, '198.18.0.0', 15) ||    // benchmarking (often routed internally)
    v4InCidr(ip, '198.51.100.0', 24) ||  // TEST-NET-2
    v4InCidr(ip, '203.0.113.0', 24) ||   // TEST-NET-3
    v4InCidr(ip, '224.0.0.0', 4) ||      // multicast
    v4InCidr(ip, '240.0.0.0', 4)         // reserved (covers 255.255.255.255 broadcast)
  );
}

// Expand any IPv6 string to its 8 hextet numbers, or null if unparseable. Handles `::` compression and
// a dotted IPv4 tail. This is what lets us catch every spelling of an embedded v4 (the metadata bypass).
function expandV6(ip) {
  let x = ip.toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  const dm = x.match(/:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/); // dotted v4 tail → two hextets
  if (dm) {
    const o = dm[1].split('.').map(Number);
    if (o.some((n) => n > 255)) return null;
    x = x.slice(0, x.length - dm[1].length) + ((o[0] << 8) | o[1]).toString(16) + ':' + (((o[2] << 8) | o[3]) >>> 0).toString(16);
  }
  const halves = x.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null;
  let hextets;
  if (tail === null) hextets = head;
  else {
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    hextets = [...head, ...Array(fill).fill('0'), ...tail];
  }
  if (hextets.length !== 8) return null;
  const nums = hextets.map((h) => (h === '' ? 0 : parseInt(h, 16)));
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
  return nums;
}

export function isPrivateV6(ip) {
  const h = expandV6(ip);
  if (!h) {
    const x = ip.toLowerCase(); // unparseable → conservative prefix check
    return x === '::1' || x === '::' || x.startsWith('fe80') || x.startsWith('fc') || x.startsWith('fd');
  }
  if (h.every((n, i) => (i < 7 ? n === 0 : n === 1))) return true; // ::1 loopback
  if (h.every((n) => n === 0)) return true;                        // :: unspecified
  if ((h[0] & 0xffc0) === 0xfe80) return true;                     // fe80::/10 link-local
  if ((h[0] & 0xfe00) === 0xfc00) return true;                     // fc00::/7 ULA
  if (h[0] >= 0xff00) return true;                                 // ff00::/8 multicast
  // v4-mapped (::ffff:0:0/96) or v4-compat (::/96) → range-check the embedded v4
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && (h[5] === 0xffff || h[5] === 0)) {
    return isPrivateV4(`${h[6] >> 8}.${h[6] & 0xff}.${h[7] >> 8}.${h[7] & 0xff}`);
  }
  return false;
}

export function isPrivateIp(ip) {
  const kind = net.isIP(ip);
  if (kind === 4) return isPrivateV4(ip);
  if (kind === 6) return isPrivateV6(ip);
  // not a clean literal — if it contains ':' treat as v6-ish, else v4-ish (best effort)
  return ip.includes(':') ? isPrivateV6(ip) : isPrivateV4(ip);
}

const isIpLiteral = (h) => net.isIP(h) !== 0;

/**
 * Validate that `host` is — and resolves to — a public address, and RETURN the vetted address list so
 * the caller can connect to a validated IP literal instead of re-resolving the hostname (closes the
 * DNS-rebinding TOCTOU). Throws on any private/loopback/link-local result.
 * @returns {Promise<string[]>} the vetted addresses (the literal itself, or all resolved A/AAAA)
 */
export async function assertPublicHost(host, { lookup = dns.lookup } = {}) {
  const h = (host || '').replace(/^\[|\]$/g, '');
  if (!h || h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local')) {
    throw new Error(`blocked host (local name): ${host}`);
  }
  if (isIpLiteral(h)) {
    if (isPrivateIp(h)) throw new Error(`blocked host (private/loopback IP): ${host}`);
    return [h];
  }
  const addrs = await lookup(h, { all: true });
  if (!addrs.length) throw new Error(`blocked host (no DNS): ${host}`);
  for (const { address } of addrs) {
    if (isPrivateIp(address)) throw new Error(`blocked host (${host} → private ${address})`);
  }
  return addrs.map((a) => a.address);
}
