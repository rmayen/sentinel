import net from 'node:net';
import { lookup } from 'node:dns/promises';

// Guards against Server-Side Request Forgery. Because Sentinel fetches
// user-supplied URLs, an attacker could otherwise point it at internal
// services (localhost, cloud metadata at 169.254.169.254, private LANs).
// We reject non-http(s) schemes and any host that resolves to a private,
// loopback, link-local, or otherwise reserved address.

export async function assertSafeUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('invalid url');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('only http and https urls are allowed');
  }

  const host = url.hostname;
  const addresses = net.isIP(host)
    ? [host]
    : (await lookup(host, { all: true })).map((a) => a.address);

  if (addresses.length === 0) throw new Error('host could not be resolved');
  for (const address of addresses) {
    if (isPrivateAddress(address)) {
      throw new Error('target resolves to a private or reserved address');
    }
  }
}

export function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) return isPrivateV4(ip);
  if (net.isIPv6(ip)) return isPrivateV6(ip.toLowerCase());
  return true; // unrecognized -> treat as unsafe
}

function isPrivateV4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b, c] = parts;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local (incl. cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24
  if (a >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateV6(ip) {
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); // IPv4-mapped
  if (mapped) return isPrivateV4(mapped[1]);
  if (ip === '::' || ip === '::1') return true; // unspecified + loopback
  if (/^fe[89ab]/.test(ip)) return true; // fe80::/10 link-local
  if (/^f[cd]/.test(ip)) return true; // fc00::/7 unique local
  return false;
}
