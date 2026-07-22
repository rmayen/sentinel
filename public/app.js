const TOKEN_KEY = 'sentinel_token';
let token = localStorage.getItem(TOKEN_KEY);

const el = (id) => document.getElementById(id);
const loginView = el('login-view');
const appView = el('app-view');

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });
  if (res.status === 401 && path !== '/api/login') {
    signOut();
    throw new Error('session expired');
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}

function showApp() {
  loginView.hidden = true;
  appView.hidden = false;
  el('logout').hidden = false;
  loadSites();
}

function signOut() {
  token = null;
  localStorage.removeItem(TOKEN_KEY);
  appView.hidden = true;
  loginView.hidden = false;
  el('logout').hidden = true;
}

// --- Login ---
el('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = el('login-error');
  err.hidden = true;
  try {
    const { token: t } = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ password: el('password').value }),
    });
    token = t;
    localStorage.setItem(TOKEN_KEY, t);
    el('password').value = '';
    showApp();
  } catch {
    err.textContent = 'Incorrect password.';
    err.hidden = false;
  }
});

el('logout').addEventListener('click', signOut);

// --- Sites ---
async function loadSites() {
  const { sites } = await api('/api/sites');
  const body = el('sites-body');
  body.innerHTML = '';
  el('empty').hidden = sites.length > 0;
  for (const site of sites) body.appendChild(renderRow(site));
}

function renderRow(site) {
  const tr = document.createElement('tr');
  const c = site.latest;
  const status = c ? (c.ok ? 'up' : 'down') : '';
  const grade = c && c.grade ? c.grade : 'none';
  tr.innerHTML = `
    <td><div class="site-url">${escape(hostname(site.url))}</div>
        <div class="site-label">${escape(site.label || site.url)}</div></td>
    <td>${c ? `<span class="pill ${status}">${c.ok ? 'Up' : 'Down'}</span>` : '<span class="muted">—</span>'}</td>
    <td>${c && c.status_code ? c.status_code : '—'}</td>
    <td>${c && c.response_ms != null ? c.response_ms + ' ms' : '—'}</td>
    <td><span class="grade ${grade}">${grade === 'none' ? '–' : grade}</span></td>
    <td class="muted">${c ? timeAgo(c.ts) : 'never'}</td>
    <td style="white-space:nowrap">
      <button class="link" data-check="${site.id}">Check</button>
      <button class="link" data-history="${site.id}" data-name="${escape(hostname(site.url))}">History</button>
      <button class="link" data-delete="${site.id}" style="color:var(--down)">Delete</button>
    </td>`;
  return tr;
}

el('sites-body').addEventListener('click', async (e) => {
  const t = e.target;
  if (t.dataset.check) {
    t.textContent = '…';
    await api(`/api/sites/${t.dataset.check}/check`, { method: 'POST' });
    await loadSites();
  } else if (t.dataset.delete) {
    if (confirm('Stop monitoring this site?')) {
      await api(`/api/sites/${t.dataset.delete}`, { method: 'DELETE' });
      await loadSites();
    }
  } else if (t.dataset.history) {
    openHistory(t.dataset.history, t.dataset.name);
  }
});

el('add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = el('add-error');
  err.hidden = true;
  try {
    await api('/api/sites', {
      method: 'POST',
      body: JSON.stringify({ url: el('url').value, label: el('label').value || null }),
    });
    el('url').value = '';
    el('label').value = '';
    await loadSites();
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
});

el('check-all').addEventListener('click', async () => {
  const { sites } = await api('/api/sites');
  await Promise.all(sites.map((s) => api(`/api/sites/${s.id}/check`, { method: 'POST' })));
  await loadSites();
});

// --- History ---
async function openHistory(id, name) {
  const { checks } = await api(`/api/sites/${id}/history`);
  el('drawer-title').textContent = `History — ${name}`;
  el('history-body').innerHTML = checks
    .map(
      (c) => `<tr>
        <td class="muted">${new Date(c.ts).toLocaleString()}</td>
        <td>${c.ok ? '<span class="pill up">Up</span>' : '<span class="pill down">Down</span>'}</td>
        <td>${c.status_code ?? '—'}</td>
        <td>${c.response_ms != null ? c.response_ms + ' ms' : '—'}</td>
        <td><span class="grade ${c.grade || 'none'}">${c.grade || '–'}</span></td>
      </tr>`
    )
    .join('') || '<tr><td colspan="5" class="muted">No checks yet.</td></tr>';
  el('drawer').hidden = false;
}
el('drawer-close').addEventListener('click', () => (el('drawer').hidden = true));
el('drawer').addEventListener('click', (e) => {
  if (e.target === el('drawer')) el('drawer').hidden = true;
});

// --- helpers ---
function hostname(url) {
  try { return new URL(url).hostname; } catch { return url; }
}
function escape(s) {
  return String(s).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}
function timeAgo(ts) {
  const secs = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

// Restore session on load.
if (token) showApp();
