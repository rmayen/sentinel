import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';

// Creates an auth helper bound to a password and signing secret. There are no
// insecure fallback defaults: a password must be supplied. If no secret is
// given, a random one is generated for the process (tokens then reset on
// restart, which is a safe default).
export function createAuth({ password, secret, ttlMs = 12 * 60 * 60 * 1000 } = {}) {
  if (!password) throw new Error('createAuth: a password is required');
  const key = secret || randomBytes(32).toString('hex');

  const sign = (payload) => createHmac('sha256', key).update(payload).digest('base64url');

  function login(attempt) {
    if (!constantTimeEqual(attempt, password)) return null;
    const payload = Buffer.from(JSON.stringify({ exp: Date.now() + ttlMs })).toString('base64url');
    return `${payload}.${sign(payload)}`;
  }

  function verify(token) {
    if (typeof token !== 'string' || !token.includes('.')) return false;
    const [payload, sig] = token.split('.');
    const expected = sign(payload);
    if (!constantTimeEqual(sig, expected)) return false;
    try {
      const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
      return typeof exp === 'number' && Date.now() < exp;
    } catch {
      return false;
    }
  }

  return { login, verify };
}

function constantTimeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
