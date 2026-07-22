import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditHeaders, gradeFromScore } from '../src/monitor.js';

test('gradeFromScore maps score ratios to letter grades', () => {
  assert.equal(gradeFromScore(8, 8), 'A'); // 100%
  assert.equal(gradeFromScore(7, 8), 'B'); // 87.5%
  assert.equal(gradeFromScore(6, 8), 'B'); // 75%
  assert.equal(gradeFromScore(4, 8), 'C'); // 50%
  assert.equal(gradeFromScore(2, 8), 'D'); // 25%
  assert.equal(gradeFromScore(0, 8), 'F'); // 0%
});

test('auditHeaders reports present and missing security headers', () => {
  const headers = new Map([
    ['strict-transport-security', 'max-age=63072000'],
    ['x-content-type-options', 'nosniff'],
  ]);

  const result = auditHeaders(headers);
  const present = result.findings.filter((f) => f.present).map((f) => f.header);

  assert.ok(present.includes('Strict-Transport-Security'));
  assert.ok(present.includes('X-Content-Type-Options'));

  const csp = result.findings.find((f) => f.header === 'Content-Security-Policy');
  assert.equal(csp.present, false);

  assert.ok(result.score < result.max, 'partial coverage should not be a perfect score');
  assert.equal(result.grade, gradeFromScore(result.score, result.max));
});

test('auditHeaders gives a perfect score when all headers are set', () => {
  const headers = new Map([
    ['strict-transport-security', 'max-age=1'],
    ['content-security-policy', "default-src 'self'"],
    ['x-content-type-options', 'nosniff'],
    ['x-frame-options', 'DENY'],
    ['referrer-policy', 'no-referrer'],
    ['permissions-policy', 'geolocation=()'],
  ]);

  const result = auditHeaders(headers);
  assert.equal(result.score, result.max);
  assert.equal(result.grade, 'A');
});
