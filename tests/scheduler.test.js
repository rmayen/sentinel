import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { initDb, addSite, listChecks } from '../src/db.js';
import { runAllChecks } from '../src/scheduler.js';

const DB_PATH = join(tmpdir(), `sentinel-sched-test-${process.pid}.db`);

before(() => initDb(DB_PATH));
after(() => {
  try { rmSync(DB_PATH); } catch {}
});

// Uses a private-address target so the SSRF guard short-circuits the check
// without making any network request — the run still stores a result row.
test('runAllChecks records a check for every site', async () => {
  const a = addSite('http://127.0.0.1/', 'loopback');
  const b = addSite('http://10.0.0.1/', 'private');

  const results = await runAllChecks();
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.ok === false)); // blocked, but attempted

  assert.equal(listChecks(a.id).length, 1);
  assert.equal(listChecks(b.id).length, 1);
});
