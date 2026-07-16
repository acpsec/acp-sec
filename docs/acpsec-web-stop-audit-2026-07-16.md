# acpsec.app — Group 9C staged-stop audit (`web` Flask service)

**Date:** 2026-07-16
**Auditor:** Read-only reconstruction from live repo + Railway infra (no code changed)
**Purpose:** Record the decision to STOP (not delete) the legacy Flask `web`
Railway service after the blue-green cutover to Vercel + `api-prod`. Section
9C-1 reconstructs the Process-B decoupling and data-safety audit from actual
evidence (every claim cited to `file:line` or a Railway command). Section 9C-2
records the staged-stop execution and the reproducible rollback recipe.

> This doc replaces the never-persisted 9C-1 transcript. The findings below were
> re-derived from the repo/infra on 2026-07-16, not paraphrased from memory.

---

## 9C-1: Process B & data-safety audit (findings)

**Conclusion:** `web` can be safely stopped (not deleted). Process B (the ACP
provider seller) is fully decoupled from `web`; there is no durable data unique
to `web`; and no code references `web`'s URL. The `acpsec.app` custom-domain
attachment must be **left in place** on `web` during the grace period — it is
the linchpin of the DNS-revert rollback.

### A. `web` is the only Railway-deployed process, and it is Flask

- `Procfile:1` — `web: python dashboard/serve.py` — the single Railway process is
  the Flask app.
- `railway.json:7` — `"startCommand": "python dashboard/serve.py"`; `railway.json:8`
  — `"healthcheckPath": "/api/health"`. This is the `web` service config.
- (For contrast, `api-prod` is a *different* service: `railway.prod.json:20` —
  `"startCommand": "uvicorn acpsec_api.main:app --host 0.0.0.0 --port $PORT"`.)

### B. Process B (ACP provider seller) is fully decoupled from `web`

Process B is a standalone Node loop that spawns a local Python bridge — it does
not run on Railway and never talks to `web`.

- `acpsec/acp_provider/provider.mjs:24` — `import { spawn } from "node:child_process";`
- `provider.mjs:58-59` — Python executable resolves to `process.env.ACPSEC_PYTHON`
  or `path.join(REPO_ROOT, ".venv", "bin", "python")` — i.e. the **local venv**,
  not a network service.
- `provider.mjs:74-75` — `const args = ["-m", "acpsec.acp_provider", reqStr, ...];`
  `const child = spawn(py, args, { cwd: REPO_ROOT });` — direct process spawn, no
  HTTP call to `web`.
- **Zero** Flask / `dashboard` / `acpsec_api` / `api` imports under
  `acpsec/acp_provider/` (grep across the directory returns no matches).
- Process B is **not referenced by any deploy config**: `provider.mjs` /
  `acp_provider` appear in none of `Procfile`, `railway.json`, `railway.prod.json`,
  `nixpacks.toml`, `package.json`. The only mention in a Railway config is a
  deliberate **exclusion** — `railway.prod.json:8` — `"!acpsec/acp_provider/**"`
  in `watchPatterns`, so provider changes don't even trigger an `api-prod` build.

**⟹ Stopping `web` cannot affect Process B.**

### C. No code references `web`'s URL (no internal callers)

- `grep -rn "web-production-2ef7a"` across the repo (excluding `node_modules/`,
  `.venv/`) — **no matches.** Nothing points at `web`'s raw Railway URL.
- `grep -rn "acpsec.app"` across `acpsec/` and `dashboard/*.py` — **no matches**
  in Python code. `acpsec.app` is not used as a backend origin anywhere in code.

### D. No durable data unique to `web`

- **Railway volumes:** `railway volume list` → `No volumes found in environment
  production`. `web` has **no persistent volume** — all runtime writes are
  ephemeral and lost on every restart already.
- The four data stores:
  | Store | Git status | On disk | Notes |
  |---|---|---|---|
  | `dashboard/leaderboard.json` | **TRACKED / committed** (`git log` → `18fec87`, 2026-06-05) | yes | Source of truth is git. `api-prod` serves the identical 26-agent set (verified in 9C-2 Phase 1). |
  | `dashboard/reports/*.json` | **TRACKED / committed** (25 files) | yes | Source of truth is git. |
  | `dashboard/score_store.json` | **gitignored** (`.gitignore:44`) | no | Ephemeral runtime store; not even present locally. |
  | `dashboard/scan_store.json` | **gitignored** (`.gitignore:43`) | (local only) | Ephemeral runtime store; never committed, never deployed. |
- `.railwayignore:11` — `reports/` — the committed reports are **excluded from the
  deploy** and regenerated at runtime, i.e. ephemeral on `web` by design.

**⟹ The only durable data (`leaderboard.json`, `reports/`) already lives in git,
and is served live by `api-prod`. Nothing unique to `web` is lost by stopping it.**

### E. Live infra state at audit time (2026-07-16, from 9C-2 Phase 1 preflight)

- `acpsec.app` DNS → `216.198.79.1`, `server: Vercel`, `x-vercel-cache: HIT` —
  **the DNS flip to the Vercel frontend is already done.**
- `web`'s raw URL `web-production-2ef7a.up.railway.app` still serves Flask
  (`server: railway-hikari`), status **Online**.
- `web` domains (`railway domain --service web`): raw
  `web-production-2ef7a.up.railway.app` (service) + `acpsec.app` (custom, port
  8080, ACTIVE). **The `acpsec.app` attachment stays in place during the grace
  period — it is the DNS-revert rollback linchpin.**

### Decision

**STOP `web`, do not DELETE.** Do not touch the `acpsec.app` custom-domain
attachment. Domain detach + service deletion happen only via a separate explicit
instruction in a later session.

---

## 9C-2: Staged stop of `web` (record)

### Phase 1 — pre-stop evidence (read-only, 2026-07-16)

**1. Inbound-traffic check (closes uncertainty b) — no real external callers.**
Pulled `web`'s runtime log buffer via `railway logs --service web` (~22h
available: 15 Jul 12:09 → 16 Jul 10:47; the Werkzeug buffer does not retain the
full 48h target). All source IPs are Railway edge (`100.64.x`), so classified by
request path:
- **Vulnerability scanners → 404:** `/wp-admin/install.php`, `/xmlrpc.php`,
  `/.git/HEAD`, `/.git/config`.
- **SEO / crawlers:** `/robots.txt`, `/sitemap.xml`, systematic full-nav bursts
  (all pages hit within <2s).
- **Page GETs:** `/`, `/scanner`, `/leaderboard`, `/monitor`, `/security`,
  `/terms`, `/privacy`, `/agents/sentryagent`, `/static/logo.jpg`.
- **1×** `/api/health`.
- **Zero** real API calls (`/api/scanner/*`, `/api/score`, `/api/onchain/check`,
  `/api/chat/sentryagent`), **zero** ACP callbacks, no scheduled uptime-monitor
  pattern.
- **Decisive:** `acpsec.app` already resolves to Vercel (see 9C-1 §E), so this
  traffic reaches `web` only via the **raw Railway URL** (bot/crawler-indexed) —
  not real users on the domain. **No real external caller depends on `web`.**

**2. Data-parity check — no web-only entries.**
- `api-prod` `/api/leaderboard`: **26 agents**, an **identical set** to committed
  `dashboard/leaderboard.json` (`diff` of the sorted `name` field is empty).
- `web` `/api/leaderboard` (raw URL): returns **HTTP 500** — Werkzeug debugger,
  `TypeError: '>' not supported between instances of 'NoneType' and 'NoneType'`.
  The endpoint is broken on empty ephemeral state and holds no data to lose.
  _(Side note: `web` is currently serving with the Werkzeug debugger exposed;
  stopping it also removes that exposure.)_

**3. Env backup — done.** `railway variables --service web --kv` →
`~/sentrak/backups/acpsec-web-env-20260716.txt` (`chmod 600`). **13 variables,
all Railway system vars (`RAILWAY_*`) — no custom app secrets are set on `web`.**
Path recorded here (contents never printed).

**Baselines for post-stop verification:** `api-prod` `/api/health` →
`{"ok":true,"service":"acp-sec-dashboard","acpsec_available":true,"scanner_protected":true}`;
`web` raw `/` → HTTP 200 (Flask still up).

**STOP 2a outcome:** neither trigger fired (no real external callers, no
web-only data). Awaiting explicit user GO before executing the stop.

### Phase 2 — execution & rollback

_Pending explicit user GO. Will record: exact stop mechanism + timestamp, the
reproducible restart command, the full rollback recipe (restart `web` +
Namecheap DNS revert + cert re-issue caveat), and confirmation that the
`acpsec.app` custom-domain attachment was intentionally left in place._
