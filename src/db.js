import { DatabaseSync } from 'node:sqlite';

let db;

export function initDb(path = 'sentinel.db') {
  db = new DatabaseSync(path);
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS sites (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      url        TEXT NOT NULL UNIQUE,
      label      TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS checks (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id     INTEGER NOT NULL,
      ts          TEXT NOT NULL,
      ok          INTEGER NOT NULL,
      status_code INTEGER,
      response_ms INTEGER,
      grade       TEXT,
      findings    TEXT,
      FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_checks_site_ts ON checks(site_id, ts DESC);
  `);
  return db;
}

export function addSite(url, label) {
  const info = db
    .prepare('INSERT INTO sites (url, label, created_at) VALUES (?, ?, ?)')
    .run(url, label ?? null, new Date().toISOString());
  return getSite(info.lastInsertRowid);
}

export function getSite(id) {
  return db.prepare('SELECT * FROM sites WHERE id = ?').get(id);
}

export function deleteSite(id) {
  return db.prepare('DELETE FROM sites WHERE id = ?').run(id).changes > 0;
}

// Each site with its most recent check attached (or null if never checked).
export function listSites() {
  const sites = db.prepare('SELECT * FROM sites ORDER BY created_at DESC').all();
  const latest = db.prepare('SELECT * FROM checks WHERE site_id = ? ORDER BY ts DESC, id DESC LIMIT 1');
  return sites.map((s) => ({ ...s, latest: parseCheck(latest.get(s.id)) }));
}

export function insertCheck(siteId, result) {
  const info = db
    .prepare(
      `INSERT INTO checks (site_id, ts, ok, status_code, response_ms, grade, findings)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      siteId,
      new Date().toISOString(),
      result.ok ? 1 : 0,
      result.statusCode ?? null,
      result.responseMs ?? null,
      result.grade ?? null,
      JSON.stringify(result.findings ?? [])
    );
  return info.lastInsertRowid;
}

export function listChecks(siteId, limit = 50) {
  return db
    .prepare('SELECT * FROM checks WHERE site_id = ? ORDER BY ts DESC, id DESC LIMIT ?')
    .all(siteId, limit)
    .map(parseCheck);
}

function parseCheck(row) {
  if (!row) return null;
  return { ...row, ok: Boolean(row.ok), findings: safeParse(row.findings) };
}

function safeParse(json) {
  try {
    return JSON.parse(json ?? '[]');
  } catch {
    return [];
  }
}
