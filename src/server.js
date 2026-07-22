import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, extname } from 'node:path';
import { initDb, addSite, getSite, deleteSite, listSites, insertCheck, listChecks } from './db.js';
import { checkSite } from './monitor.js';
import { login, verify } from './auth.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, '..', 'public');
const PORT = Number(process.env.PORT) || 3000;
const DB_PATH = process.env.SENTINEL_DB || join(__dirname, '..', 'sentinel.db');

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };

initDb(DB_PATH);

function json(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString());
  } catch {
    return {};
  }
}

function isAuthed(req) {
  const header = req.headers.authorization || '';
  return verify(header.startsWith('Bearer ') ? header.slice(7) : '');
}

function isValidUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

async function handleApi(req, res, path) {
  if (path === '/api/login' && req.method === 'POST') {
    const { password } = await readJson(req);
    const token = login(password || '');
    return token ? json(res, 200, { token }) : json(res, 401, { error: 'invalid credentials' });
  }

  if (!isAuthed(req)) return json(res, 401, { error: 'unauthorized' });

  if (path === '/api/sites' && req.method === 'GET') {
    return json(res, 200, { sites: listSites() });
  }

  if (path === '/api/sites' && req.method === 'POST') {
    const { url, label } = await readJson(req);
    if (!isValidUrl(url)) return json(res, 400, { error: 'a valid http(s) url is required' });
    try {
      return json(res, 201, { site: addSite(url, label) });
    } catch {
      return json(res, 409, { error: 'that url is already being monitored' });
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
  const file = join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'content-type': 'text/plain' });
    return res.end('Forbidden');
  }
  try {
    const data = await readFile(file);
    res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' });
    res.end(data);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('Not found');
  }
}

export const server = http.createServer(async (req, res) => {
  const { pathname } = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (pathname.startsWith('/api/')) {
      await handleApi(req, res, pathname);
    } else {
      await serveStatic(res, pathname);
    }
  } catch {
    json(res, 500, { error: 'server error' });
  }
});

// Only start listening when run directly, so tests can import pieces without opening a port.
if (import.meta.url === `file://${process.argv[1]}`) {
  server.listen(PORT, () => console.log(`Sentinel running on http://localhost:${PORT}`));
}
