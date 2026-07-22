import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createApp } from '../src/server.js';
import { createAuth } from '../src/auth.js';

const DB_PATH = join(tmpdir(), `sentinel-http-test-${process.pid}.db`);
const auth = createAuth({ password: 'test-pass', secret: 'test-secret' });
let base;
let server;

before(async () => {
  server = createApp({ dbPath: DB_PATH, auth });
  await new Promise((resolve) => server.listen(0, resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  try { rmSync(DB_PATH); } catch {}
});

const req = (path, opts = {}) =>
  fetch(base + path, { ...opts, headers: { 'content-type': 'application/json', ...(opts.headers || {}) } });

async function tokenFor() {
  const res = await req('/api/login', { method: 'POST', body: JSON.stringify({ password: 'test-pass' }) });
  return (await res.json()).token;
}

test('login rejects a wrong password and accepts the right one', async () => {
  const bad = await req('/api/login', { method: 'POST', body: JSON.stringify({ password: 'nope' }) });
  assert.equal(bad.status, 401);

  const good = await req('/api/login', { method: 'POST', body: JSON.stringify({ password: 'test-pass' }) });
  assert.equal(good.status, 200);
  assert.ok((await good.json()).token);
});

test('protected routes require a valid token', async () => {
  const noAuth = await req('/api/sites');
  assert.equal(noAuth.status, 401);

  const token = await tokenFor();
  const withAuth = await req('/api/sites', { headers: { authorization: `Bearer ${token}` } });
  assert.equal(withAuth.status, 200);
});

test('responses carry security headers', async () => {
  const res = await req('/api/sites');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.ok(res.headers.get('content-security-policy'));
});

test('adding a site enforces the SSRF guard', async () => {
  const token = await tokenFor();
  const headers = { authorization: `Bearer ${token}` };

  const blocked = await req('/api/sites', { method: 'POST', headers, body: JSON.stringify({ url: 'http://127.0.0.1/' }) });
  assert.equal(blocked.status, 400);

  const meta = await req('/api/sites', { method: 'POST', headers, body: JSON.stringify({ url: 'http://169.254.169.254/' }) });
  assert.equal(meta.status, 400);

  const ok = await req('/api/sites', { method: 'POST', headers, body: JSON.stringify({ url: 'http://93.184.216.34/', label: 'Public IP' }) });
  assert.equal(ok.status, 201);
});

test('malformed JSON is rejected with 400', async () => {
  const res = await req('/api/login', { method: 'POST', body: '{ not json' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /invalid json/i);
});

test('overly long url and label are rejected', async () => {
  const token = await tokenFor();
  const headers = { authorization: `Bearer ${token}` };

  const longUrl = 'http://93.184.216.34/' + 'a'.repeat(2100);
  const r1 = await req('/api/sites', { method: 'POST', headers, body: JSON.stringify({ url: longUrl }) });
  assert.equal(r1.status, 400);

  const r2 = await req('/api/sites', {
    method: 'POST', headers,
    body: JSON.stringify({ url: 'http://93.184.216.34/', label: 'x'.repeat(200) }),
  });
  assert.equal(r2.status, 400);
});

test('oversized request bodies are rejected', async () => {
  const token = await tokenFor();
  const big = 'x'.repeat(70 * 1024);
  const res = await req('/api/sites', {
    method: 'POST',
    headers: { authorization: `Bearer ${token}` },
    body: JSON.stringify({ url: 'https://example.com', label: big }),
  });
  assert.equal(res.status, 413);
});

test('repeated failed logins are rate limited', async () => {
  let sawLimit = false;
  for (let i = 0; i < 8; i++) {
    const res = await req('/api/login', { method: 'POST', body: JSON.stringify({ password: 'wrong' }) });
    if (res.status === 429) { sawLimit = true; break; }
  }
  assert.equal(sawLimit, true, 'expected a 429 after repeated failures');
});
