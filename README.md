# Sentinel

Self-hosted uptime and HTTP security-header monitor. You register the URLs you
care about, and Sentinel checks whether each one is reachable, how fast it
responds, and how well it sets its HTTP security headers — storing every result
so you can see history over time.

Built as a zero-dependency Node.js service: the backend uses only the standard
library (`node:http`, `node:sqlite`, `node:crypto`, and the global `fetch`), with
a plain HTML/CSS/JavaScript dashboard on top.

![Sentinel dashboard](docs/dashboard.png)

## Features

- Uptime checks with status code and response time for each monitored site
- HTTP security-header audit (HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Permissions-Policy) scored to an A–F grade. Header *values* are
  validated, not just their presence — `max-age=0` HSTS or a bad `X-Frame-Options`
  earns no credit.
- Full check history per site, stored in SQLite (indexed on `site_id, ts`)
- Token-based sign-in (HMAC-signed, constant-time password check)
- Web dashboard to add sites, run checks, and browse history
- No runtime dependencies

## Security

Because Sentinel fetches user-supplied URLs, it is built to resist being misused:

- **SSRF protection** — before any fetch, the target is resolved and rejected if it
  points at a loopback, private, link-local, or otherwise reserved address (this
  blocks `localhost`, internal LANs, and cloud metadata at `169.254.169.254`). Only
  `http`/`https` schemes are allowed. Redirects are followed **manually and
  re-validated at every hop**, so a public URL cannot bounce the request to an
  internal address.
- **Input limits** — URLs and labels are length-checked and the URL is normalized
  before storage; malformed JSON is rejected with `400`.
- **No insecure defaults** — the server refuses to start without `SENTINEL_PASSWORD`,
  and generates a random signing secret if none is provided.
- **Login rate limiting** — repeated failed logins from an address are throttled.
- **Request body size limit** — oversized payloads are rejected with `413`.
- **Security response headers** — Sentinel serves its own dashboard with
  `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, and
  `Referrer-Policy`.

## Requirements

- Node.js 22.5 or newer (uses the built-in `node:sqlite` module)

## Setup

```bash
git clone https://github.com/rmayen/sentinel.git
cd sentinel
cp .env.example .env   # then set a password and secret
```

The defaults in `.env.example` are for local development only. Set
`SENTINEL_PASSWORD` and a long random `SENTINEL_SECRET` before exposing the
service anywhere.

## Run

```bash
npm start          # or: node --no-warnings src/server.js
```

Then open `http://localhost:3000` and sign in with your `SENTINEL_PASSWORD`.

### Automatic checks

By default, checks run on demand. To have Sentinel check every site on a schedule,
set `SENTINEL_INTERVAL_MINUTES` in `.env` (for example, `10`). Leave it unset to
keep checks on-demand only.

## How the security grade works

Each check produces a **security-header posture score** — it reflects how well a
site sets its HTTP security headers, not a guarantee that the site is secure.
Header *values* are judged, not just presence:

- **HSTS** counts only over HTTPS and requires `max-age` of at least 180 days.
- **CSP** must be present and is penalized for `unsafe-eval` or a wildcard
  `default-src`/`script-src`.
- **Clickjacking protection** is satisfied by `X-Frame-Options` *or* a CSP
  `frame-ancestors` directive.
- **Referrer-Policy** must be a recognized value; **Permissions-Policy** must
  contain a real directive.

HSTS and CSP are weighted more heavily. The weighted score maps to a grade:

| Grade | Coverage |
| ----- | -------- |
| A | ≥ 90% |
| B | ≥ 75% |
| C | ≥ 50% |
| D | ≥ 25% |
| F | < 25% |

## API

All endpoints except `POST /api/login` require an `Authorization: Bearer <token>`
header.

| Method | Path | Description |
| ------ | ---- | ----------- |
| POST | `/api/login` | Exchange the password for a token |
| GET | `/api/sites` | List sites with their latest check |
| POST | `/api/sites` | Add a site (`{ "url", "label" }`) |
| DELETE | `/api/sites/:id` | Stop monitoring a site |
| POST | `/api/sites/:id/check` | Run a check now and store the result |
| GET | `/api/sites/:id/history` | List past checks for a site |

Example:

```bash
TOKEN=$(curl -s -XPOST localhost:3000/api/login \
  -d '{"password":"admin"}' | node -pe 'JSON.parse(require("fs").readFileSync(0)).token')

curl -s -XPOST localhost:3000/api/sites \
  -H "authorization: Bearer $TOKEN" \
  -d '{"url":"https://github.com","label":"GitHub"}'
```

## Tests

```bash
npm test
```

The suite covers header grading and value validation, redirect re-validation in
the fetch layer, the token sign/verify flow, the SSRF address checks, input
handling, the database layer, the scheduler, and the HTTP API end to end (auth,
SSRF blocking on add, rate limiting, body-size and input limits).

## Notes

- The SQLite file (`sentinel.db`) and `.env` are gitignored.
- The SSRF guard resolves the host and re-validates every redirect before
  fetching. One residual gap remains: because the guard resolves DNS and `fetch`
  then resolves again, a determined DNS-rebinding attack is still theoretically
  possible. Closing it completely requires connecting to the validated IP while
  preserving the original hostname for TLS and the `Host` header — a worthwhile
  next step for a fully untrusted deployment.
