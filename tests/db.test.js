import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { initDb, addSite, getSite, deleteSite, listSites, insertCheck, listChecks } from '../src/db.js';

const DB_PATH = join(tmpdir(), `sentinel-db-test-${process.pid}.db`);

before(() => initDb(DB_PATH));
after(() => {
  try { rmSync(DB_PATH); } catch {}
});

const sampleResult = {
  ok: true, statusCode: 200, responseMs: 120, grade: 'B',
  findings: [{ header: 'Content-Security-Policy', valid: false }],
};

test('addSite stores a site and getSite reads it back', () => {
  const site = addSite('https://example.com', 'Example');
  assert.equal(site.url, 'https://example.com');
  assert.equal(site.label, 'Example');
  assert.deepEqual(getSite(site.id).url, 'https://example.com');
});

test('insertCheck and listChecks round-trip, newest first', () => {
  const site = addSite('https://a.example', 'A');
  insertCheck(site.id, { ...sampleResult, grade: 'A' });
  insertCheck(site.id, { ...sampleResult, grade: 'C' });

  const checks = listChecks(site.id);
  assert.equal(checks.length, 2);
  assert.equal(checks[0].grade, 'C'); // most recent first
  assert.equal(checks[0].ok, true);
  assert.equal(Array.isArray(checks[0].findings), true);
});

test('listSites attaches the latest check per site', () => {
  const site = addSite('https://b.example', 'B');
  insertCheck(site.id, { ...sampleResult, grade: 'D' });

  const found = listSites().find((s) => s.id === site.id);
  assert.equal(found.latest.grade, 'D');
});

test('deleteSite removes the site and cascades to its checks', () => {
  const site = addSite('https://c.example', 'C');
  insertCheck(site.id, sampleResult);

  assert.equal(deleteSite(site.id), true);
  assert.equal(getSite(site.id), undefined);
  assert.equal(listChecks(site.id).length, 0); // cascade removed the checks
});
