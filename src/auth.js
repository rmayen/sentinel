import { createHmac, timingSafeEqual } from 'node:crypto';

const SECRET = process.env.SENTINEL_SECRET || 'dev-insecure-secret-change-me';
const PASSWORD = process.env.SENTINEL_PASSWORD || 'admin';
const TTL_MS = 12 * 60 * 60 * 1000; // tokens last 12 hours

function sign(payload) {
  return createHmac('sha256', SECRET).update(payload).digest('base64url');
}

// Returns a signed token on success, or null if the password is wrong.
export function login(password) {
  if (!constantTimeEqual(password, PASSWORD)) return null;
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + TTL_MS })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

export function verify(token) {
  if (typeof token !== 'string' || !token.includes('.')) return false;
  const [payload, sig] = token.split('.');
  if (sign(payload) !== sig) return false;
  try {
    const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return typeof exp === 'number' && Date.now() < exp;
  } catch {
    return false;
  }
}

function constantTimeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
