import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, extname } from 'node:path';
import { initDb, addSite, getSite, deleteSite, listSites, insertCheck, listChecks } from './db.js';
import { checkSite } from './monitor.js';
import { assertSafeUrl } from './ssrf.js';
import { createAuth } from './auth.js';
import { loadEnv } from './env.js';
import { startScheduler } from './scheduler.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, '..', 'public');

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };
const MAX_BODY_BYTES = 64 * 1024; // reject oversized request bodies
const MAX_URL_LEN = 2048;
const MAX_LABEL_LEN = 100;
const LOGIN_MAX_ATTEMPTS = 5; // failed logins allowed per window, per IP
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'",
};

// Builds the HTTP server. Everything it needs (database path, auth helper) is
// injected, so tests can spin up an isolated instance on a random port.
export function createApp({ dbPath, auth, staticDir = PUBLIC_DIR } = {}) {
  if (!auth) throw new Error('createApp: an auth helper is required');
  initDb(dbPath);

  const loginAttempts = new Map(); // ip -> { count, resetAt }

  function rateLimited(ip) {
    const now = Date.now();
    const entry = loginAttempts.get(ip);
    if (!entry || now > entry.resetAt) return false;
    return entry.count >= LOGIN_MAX_ATTEMPTS;
  }
  function recordFailure(ip) {
    const now = Date.now();
    const entry = loginAttempts.get(ip);
    if (!entry || now > entry.resetAt) {
      loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    } else {
      entry.count += 1;
    }
  }
  // Drop expired entries so the map can't grow unbounded under many attacking IPs.
  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of loginAttempts) {
      if (now > entry.resetAt) loginAttempts.delete(ip);
    }
  }, LOGIN_WINDOW_MS);
  cleanup.unref();

  function setSecurity(res) {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  }
  function json(res, status, body) {
    setSecurity(res);
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  }

  async function readJson(req) {
    let size = 0;
    const chunks = [];
    for await (const chunk of req) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) throw new PayloadTooLarge();
      chunks.push(chunk);
    }
    if (chunks.length === 0) return {};
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new InvalidJson();
    }
  }

  const isAuthed = (req) => {
    const header = req.headers.authorization || '';
    return auth.verify(header.startsWith('Bearer ') ? header.slice(7) : '');
  };

  async function handleApi(req, res, path, ip) {
    if (path === '/api/login' && req.method === 'POST') {
      if (rateLimited(ip)) return json(res, 429, { error: 'too many attempts, try again later' });
      const { password } = await readJson(req);
      const token = auth.login(password || '');
      if (!token) {
        recordFailure(ip);
        return json(res, 401, { error: 'invalid credentials' });
      }
      return json(res, 200, { token });
    }

    if (!isAuthed(req)) return json(res, 401, { error: 'unauthorized' });

    if (path === '/api/sites' && req.method === 'GET') {
      return json(res, 200, { sites: listSites() });
    }

    if (path === '/api/sites' && req.method === 'POST') {
      const { url, label } = await readJson(req);
      if (typeof url !== 'string' || url.length > MAX_URL_LEN) {
        return json(res, 400, { error: 'url must be a string of at most 2048 characters' });
      }
      if (label != null && (typeof label !== 'string' || label.trim().length > MAX_LABEL_LEN)) {
        return json(res, 400, { error: 'label must be at most 100 characters' });
      }
      try {
        await assertSafeUrl(url);
      } catch (err) {
        return json(res, 400, { error: err.message });
      }
      const normalized = new URL(url).href;
      try {
        return json(res, 201, { site: addSite(normalized, label ? label.trim() : null) });
      } catch (err) {
        if (/UNIQUE/i.test(err.message)) {
          return json(res, 409, { error: 'that url is already being monitored' });
        }
        console.error('addSite failed:', err);
        return json(res, 500, { error: 'could not save site' });
      }
    }

    const match = path.match(/^\/api\/sites\/(\d+)(\/check|\/history)?$/);
    if (match) {
      const id = Number(match[1]);
      const site = getSite(id);
      if (!site) return json(res, 404, { error: 'site not found' });

      if (match[2] === '/check' && req.method === 'POST') {
        const result = await checkSite(site.url);
        insertCheck(id, result);
        return json(res, 200, { result });
      }
      if (match[2] === '/history' && req.method === 'GET') {
        return json(res, 200, { checks: listChecks(id) });
      }
      if (!match[2] && req.method === 'DELETE') {
        deleteSite(id);
        return json(res, 200, { deleted: true });
      }
    }

    return json(res, 404, { error: 'not found' });
  }

  async function serveStatic(res, path) {
    const rel = path === '/' ? 'index.html' : normalize(path).replace(/^(\.\.[/\\])+/, '').replace(/^\//, '');
    const file = join(staticDir, rel);
    if (!file.startsWith(staticDir)) {
      setSecurity(res);
      res.writeHead(403, { 'content-type': 'text/plain' });
      return res.end('Forbidden');
    }
    try {
      const data = await readFile(file);
      setSecurity(res);
      res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
      res.end(data);
    } catch {
      setSecurity(res);
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('Not found');
    }
  }

  return http.createServer(async (req, res) => {
    const ip = req.socket.remoteAddress || 'unknown';
    const { pathname } = new URL(req.url, `http://${req.headers.host}`);
    try {
      if (pathname.startsWith('/api/')) {
        await handleApi(req, res, pathname, ip);
      } else {
        await serveStatic(res, pathname);
      }
    } catch (err) {
      if (err instanceof PayloadTooLarge) return json(res, 413, { error: 'request body too large' });
      if (err instanceof InvalidJson) return json(res, 400, { error: 'invalid JSON body' });
      json(res, 500, { error: 'server error' });
    }
  });
}

class PayloadTooLarge extends Error {}
class InvalidJson extends Error {}

// Start a real server only when run directly. Config comes from the
// environment; there are no insecure fallback credentials.
if (import.meta.url === `file://${process.argv[1]}`) {
  loadEnv();
  const password = process.env.SENTINEL_PASSWORD;
  if (!password) {
    console.error('SENTINEL_PASSWORD is required. Copy .env.example to .env and set it.');
    process.exit(1);
  }
  if (!process.env.SENTINEL_SECRET) {
    console.warn('SENTINEL_SECRET is not set; using a random secret (sessions reset on restart).');
  }
  const auth = createAuth({ password, secret: process.env.SENTINEL_SECRET });
  const dbPath = process.env.SENTINEL_DB || join(__dirname, '..', 'sentinel.db');
  const port = Number(process.env.PORT) || 3000;
  createApp({ dbPath, auth }).listen(port, () => console.log(`Sentinel running on http://localhost:${port}`));

  // Optional automatic monitoring: set SENTINEL_INTERVAL_MINUTES to enable.
  const minutes = Number(process.env.SENTINEL_INTERVAL_MINUTES);
  if (minutes > 0) {
    startScheduler({ intervalMs: minutes * 60 * 1000, onError: (e) => console.error('scheduled check failed:', e) });
    console.log(`Automatic checks every ${minutes} minute(s).`);
  }
}
