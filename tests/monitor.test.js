import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditHeaders, gradeFromScore, safeFetch } from '../src/monitor.js';

const STRONG = () =>
  new Map([
    ['strict-transport-security', 'max-age=31536000; includeSubDomains'],
    ['content-security-policy', "default-src 'self'"],
    ['x-content-type-options', 'nosniff'],
    ['x-frame-options', 'DENY'],
    ['referrer-policy', 'no-referrer'],
    ['permissions-policy', 'geolocation=()'],
  ]);

test('gradeFromScore maps score ratios to letter grades', () => {
  assert.equal(gradeFromScore(8, 8), 'A');
  assert.equal(gradeFromScore(7, 8), 'B');
  assert.equal(gradeFromScore(4, 8), 'C');
  assert.equal(gradeFromScore(2, 8), 'D');
  assert.equal(gradeFromScore(0, 8), 'F');
});

test('a fully hardened HTTPS response scores A', () => {
  const result = auditHeaders(STRONG(), { https: true });
  assert.equal(result.score, result.max);
  assert.equal(result.grade, 'A');
});

test('HSTS only earns credit over HTTPS', () => {
  const overHttp = auditHeaders(STRONG(), { https: false });
  const hsts = overHttp.findings.find((f) => f.header === 'Strict-Transport-Security');
  assert.equal(hsts.valid, false);
  assert.ok(overHttp.score < overHttp.max);
});

test('a short HSTS max-age is not accepted', () => {
  const headers = STRONG();
  headers.set('strict-transport-security', 'max-age=1');
  const finding = auditHeaders(headers, { https: true }).findings.find(
    (f) => f.header === 'Strict-Transport-Security'
  );
  assert.equal(finding.valid, false);
});

test('a CSP with unsafe-eval or a wildcard is penalized', () => {
  for (const csp of ["default-src 'self'; script-src 'unsafe-eval'", 'default-src *']) {
    const headers = STRONG();
    headers.set('content-security-policy', csp);
    const finding = auditHeaders(headers, { https: true }).findings.find(
      (f) => f.header === 'Content-Security-Policy'
    );
    assert.equal(finding.valid, false, `should reject: ${csp}`);
  }
});

test('CSP frame-ancestors satisfies clickjacking protection without X-Frame-Options', () => {
  const headers = STRONG();
  headers.delete('x-frame-options');
  headers.set('content-security-policy', "default-src 'self'; frame-ancestors 'none'");
  const finding = auditHeaders(headers, { https: true }).findings.find(
    (f) => f.header === 'Clickjacking protection'
  );
  assert.equal(finding.valid, true);
});

test('an unrecognized Referrer-Policy value is rejected', () => {
  const headers = STRONG();
  headers.set('referrer-policy', 'whatever');
  const finding = auditHeaders(headers, { https: true }).findings.find(
    (f) => f.header === 'Referrer-Policy'
  );
  assert.equal(finding.valid, false);
});

// --- safeFetch (redirect SSRF) ---

const fakeResponse = (status, location) => ({
  status,
  ok: status >= 200 && status < 300,
  url: 'http://93.184.216.34/',
  headers: { get: (k) => (k.toLowerCase() === 'location' ? location : null) },
});

test('safeFetch blocks a redirect to a private address', async () => {
  const fetchImpl = async () => fakeResponse(302, 'http://127.0.0.1/');
  await assert.rejects(
    safeFetch('http://93.184.216.34/', { fetchImpl }),
    /private or reserved/
  );
});

test('safeFetch follows a redirect to a public address', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return calls === 1 ? fakeResponse(302, 'http://8.8.8.8/') : fakeResponse(200, null);
  };
  const res = await safeFetch('http://93.184.216.34/', { fetchImpl });
  assert.equal(res.status, 200);
});

test('safeFetch stops after too many redirects', async () => {
  const fetchImpl = async () => fakeResponse(302, 'http://8.8.8.8/');
  await assert.rejects(
    safeFetch('http://93.184.216.34/', { fetchImpl, maxRedirects: 3 }),
    /too many redirects/
  );
});
