import { assertSafeUrl } from './ssrf.js';

// Recognized Referrer-Policy tokens (any one present earns credit).
const REFERRER_POLICIES = new Set([
  'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
  'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
]);

const HSTS_MIN_AGE = 15552000; // 180 days, the commonly recommended floor

// Validators receive the raw header value plus context (other header values and
// whether the connection is HTTPS), so cross-header and scheme-aware rules work.
const SECURITY_HEADERS = [
  {
    key: 'strict-transport-security',
    label: 'Strict-Transport-Security',
    weight: 2,
    // HSTS is only meaningful over HTTPS and should specify a long max-age.
    validate: (v, { https }) => {
      if (!https) return false;
      const m = /max-age\s*=\s*(\d+)/i.exec(v || '');
      return Boolean(m) && Number(m[1]) >= HSTS_MIN_AGE;
    },
  },
  {
    key: 'content-security-policy',
    label: 'Content-Security-Policy',
    weight: 2,
    // Present, and not obviously self-defeating (unsafe-eval or a wildcard default).
    validate: (v) => {
      const csp = (v || '').trim().toLowerCase();
      if (!csp) return false;
      if (csp.includes('unsafe-eval')) return false;
      if (/(^|;)\s*(default-src|script-src)\s+[^;]*\*/.test(csp)) return false;
      return true;
    },
  },
  {
    key: 'x-frame-options',
    label: 'Clickjacking protection',
    weight: 1,
    // Satisfied by X-Frame-Options OR a CSP frame-ancestors directive.
    validate: (v, { csp }) => {
      if (['deny', 'sameorigin'].includes((v || '').trim().toLowerCase())) return true;
      return /(^|;)\s*frame-ancestors\s+/i.test(csp || '');
    },
  },
  {
    key: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    weight: 1,
    validate: (v) => (v || '').trim().toLowerCase() === 'nosniff',
  },
  {
    key: 'referrer-policy',
    label: 'Referrer-Policy',
    weight: 1,
    validate: (v) =>
      (v || '')
        .split(',')
        .some((token) => REFERRER_POLICIES.has(token.trim().toLowerCase())),
  },
  {
    key: 'permissions-policy',
    label: 'Permissions-Policy',
    weight: 1,
    // Require at least one real directive (feature=allowlist), not just any text.
    validate: (v) => /[a-z-]+\s*=/.test((v || '').toLowerCase()),
  },
];

// Accepts a Headers object, a Map, or a plain object with lowercased keys.
function headerValue(headers, key) {
  if (typeof headers?.get === 'function') return headers.get(key);
  if (headers instanceof Map) return headers.get(key);
  return headers?.[key];
}

export function auditHeaders(headers, { https = true } = {}) {
  const ctx = { https, csp: headerValue(headers, 'content-security-policy') || '' };
  const findings = SECURITY_HEADERS.map((h) => {
    const value = headerValue(headers, h.key);
    return {
      header: h.label,
      present: value != null && value !== '',
      valid: h.validate(value, ctx),
      weight: h.weight,
    };
  });
  const max = SECURITY_HEADERS.reduce((sum, h) => sum + h.weight, 0);
  const score = findings.reduce((sum, f) => sum + (f.valid ? f.weight : 0), 0);
  return { findings, score, max, grade: gradeFromScore(score, max) };
}

export function gradeFromScore(score, max) {
  const pct = max === 0 ? 0 : score / max;
  if (pct >= 0.9) return 'A';
  if (pct >= 0.75) return 'B';
  if (pct >= 0.5) return 'C';
  if (pct >= 0.25) return 'D';
  return 'F';
}

// Follows redirects manually, re-validating every hop against the SSRF guard so
// a public URL cannot bounce the request to an internal address. fetchImpl is
// injectable for testing.
export async function safeFetch(initialUrl, { signal, maxRedirects = 5, fetchImpl = fetch } = {}) {
  let currentUrl = initialUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertSafeUrl(currentUrl);
    const response = await fetchImpl(currentUrl, { method: 'GET', redirect: 'manual', signal });
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location = response.headers.get('location');
    if (!location) return response;
    currentUrl = new URL(location, currentUrl).href;
  }
  throw new Error('too many redirects');
}

export async function checkSite(url, { timeoutMs = 8000 } = {}) {
  const started = performance.now();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await safeFetch(url, { signal: controller.signal });
    const audit = auditHeaders(res.headers, { https: new URL(res.url || url).protocol === 'https:' });
    return {
      ok: res.ok,
      statusCode: res.status,
      responseMs: Math.round(performance.now() - started),
      grade: audit.grade,
      findings: audit.findings,
    };
  } catch (err) {
    return {
      ok: false,
      statusCode: null,
      responseMs: Math.round(performance.now() - started),
      grade: null,
      findings: [],
      error: err.name === 'AbortError' ? 'timeout' : err.message,
    };
  } finally {
    clearTimeout(timer);
  }
}
