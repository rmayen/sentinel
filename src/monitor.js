// Uptime check + HTTP security-header audit for a single URL.

const SECURITY_HEADERS = [
  { key: 'strict-transport-security', label: 'Strict-Transport-Security', weight: 2 },
  { key: 'content-security-policy', label: 'Content-Security-Policy', weight: 2 },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 1 },
  { key: 'x-frame-options', label: 'X-Frame-Options', weight: 1 },
  { key: 'referrer-policy', label: 'Referrer-Policy', weight: 1 },
  { key: 'permissions-policy', label: 'Permissions-Policy', weight: 1 },
];

// Accepts a Headers object, a Map, or a plain object with lowercased keys.
function headerValue(headers, key) {
  if (typeof headers?.get === 'function') return headers.get(key);
  return headers?.[key];
}

export function auditHeaders(headers) {
  const findings = SECURITY_HEADERS.map((h) => ({
    header: h.label,
    present: Boolean(headerValue(headers, h.key)),
    weight: h.weight,
  }));
  const max = SECURITY_HEADERS.reduce((sum, h) => sum + h.weight, 0);
  const score = findings.reduce((sum, f) => sum + (f.present ? f.weight : 0), 0);
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

export async function checkSite(url, { timeoutMs = 8000 } = {}) {
  const started = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: 'GET', redirect: 'follow', signal: controller.signal });
    const audit = auditHeaders(res.headers);
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
