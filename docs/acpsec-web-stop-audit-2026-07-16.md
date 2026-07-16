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

### F. Incidental security finding — Werkzeug debugger exposed on `web` raw URL

Surfaced while running the 9C-2 Phase 1 data-parity check.

- **Observed:** `GET https://web-production-2ef7a.up.railway.app/api/leaderboard`
  (2026-07-16) returned **HTTP 500** rendered as the **interactive Werkzeug
  debugger UI** — full Python traceback plus the in-browser debugger console
  markup (`TypeError: '>' not supported between instances of 'NoneType' and
  'NoneType'`). i.e. `web` is serving with `debug=True` / the debugger middleware
  active in production.
- **Exposure scope:** the **raw Railway URL only**
  (`web-production-2ef7a.up.railway.app`). Since the cutover, `acpsec.app` is on
  Vercel (9C-1 §E), so the debugger is **not** reachable via the custom domain —
  but the raw URL is still publicly reachable and **bot-indexed** (Phase 1 logs
  show automated `/wp-admin`, `/.git/*`, `xmlrpc` probes already hitting it).
- **Risk:** an exposed Werkzeug debugger is a **remote-code-execution surface** —
  its evaluation console runs arbitrary Python in the app process. Modern Werkzeug
  gates the console behind a PIN, but the PIN is derivable/brute-forceable from
  information the traceback and environment can leak, so this is treated as a
  latent RCE exposure, not merely an information leak.
- **Mitigation:** the staged stop of `web` (Phase 2) **removes this exposure
  entirely** — no deployment, no debugger. This is an **additional reason to
  proceed with the stop, not a reason to delay.** (Fixing it in place —
  `debug=False` — is moot for a service being retired; noted only so the finding
  isn't lost if the stop is ever reverted.)

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
  _(This 500 also revealed an exposed Werkzeug debugger — promoted to 9C-1 §F.)_

**3. Env backup + completeness sanity check — done.**
`railway variables --service web --kv` →
`~/sentrak/backups/acpsec-web-env-20260716.txt` (`chmod 600`). **13 variables,
all Railway system vars (`RAILWAY_*`) — no custom app secrets are set on `web`.**
Path recorded here (contents never printed).

- **3a — second-method cross-check:** re-read via
  `railway variables --service web --json` and diffed the variable **names**
  against the backup — **identical 13-name set** (diff empty). The backup is
  **complete**, not a `--kv` serialization artifact. Because none of the 13 are
  application config, `web`'s Flask app sources its configuration from **in-code
  defaults** (and, where a dotenv-style file is present, via
  `dashboard/auth_scanner.py:154-169`, which loads keys into `os.environ` only if
  unset) — **not from Railway env**. Consistent with there being no custom app
  secret on `web`.
- **3b — code cross-check:** env vars actually read by the Flask app
  (`dashboard/serve.py`, `dashboard/auth_scanner.py`), cross-checked against the
  backup:

  | Env var | Read at | In backup? | Verdict (absent ⟹ unset ⟹ code default) |
  |---|---|---|---|
  | `PORT` | `serve.py:40` | no | Railway auto-injects at runtime; code default `8080`. |
  | `ANTHROPIC_API_KEY` | `serve.py:486`; `auth_scanner.py:465,967` | no | **Unset** → chat proxy returns 503 (default `""`). |
  | `LEADERBOARD_PASSWORD` | `serve.py:579,594` | no | **Unset** → default `""` (leaderboard auth open/empty). |
  | `SCANNER_TOKEN` | `serve.py:717,764` | no | **Unset** → scanner endpoints run **open** (`scanner_protected=False`). |
  | `BASE_RPC_URL` | `serve.py:636` | no | **Unset** → falls back to the public RPC default. |
  | `FLASK_ENV` | `serve.py:1156` | no | **Unset** → `is_prod=False` → **debug on** — root cause of 9C-1 §F. |

  **Verdict:** every application var the code reads is **absent from the backup
  and therefore unset in prod**; Flask runs entirely on in-code defaults. Combined
  with 3a (backup proven complete by two independent methods), there is **no
  incompleteness** — the backup captured everything actually set. This corroborates
  9C-1 §D (no unique data to preserve) and explains 9C-1 §F (unset `FLASK_ENV` ⟹
  debugger exposed). `web` is running in a fully default/degraded config with no
  secrets to preserve.

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

---

## Post-delete follow-ups

Deferred cleanup, all **gated on the separate later instruction to delete `web`**
(detach `acpsec.app` + delete the service). Not scheduled here — captured so
nothing is lost.

- **Fold this audit into `main`.** This doc currently lives only on
  `deploy/staging` (the sole audit stranded off `main` — the 9A/9B docs and
  `session-summary-v16.md` are already on both branches, in sync). Cherry-pick it
  onto `main` **after** `web` is deleted, when `main` is no longer a live deploy
  target for a filter-less service. (Blocked today only because `web` tracks
  `main` with no `watchPatterns` — see 9C-1 §-note / Phase 1.5 finding.)
- **Remove `railway.json`** from the repo alongside the `web` service deletion —
  it is the `web` (Flask) service config and becomes dead once `web` is gone. Its
  missing `watchPatterns` inconsistency (vs `railway.prod.json` /
  `railway.staging.json`) is therefore **not worth fixing in place** — it
  disappears with the file.
- **Remove `Procfile`** (`web: python dashboard/serve.py`) at the same time — it
  is the other `web` start-command artifact and pairs with `railway.json`.
- **Consider retiring the legacy Flask/dashboard stack** now superseded by
  `api-prod` (FastAPI) + the Vercel frontend: `dashboard/serve.py`, the 10 inline
  HTML pages, `dashboard/scanner.py`, `dashboard/auth_scanner.py`. Larger change,
  its own PR — only the committed data (`dashboard/leaderboard.json`,
  `dashboard/reports/*.json`) must be preserved as the source of truth already
  served by `api-prod`.
- **Delete the env backup** `~/sentrak/backups/acpsec-web-env-20260716.txt` once
  `web` is gone — it holds only 13 Railway system vars (no secrets), so it can be
  removed without redaction concerns.
- **`web-staging`** is out of 9C scope but likely a parallel retirement candidate
  post-cutover — flag for its own audit before any action.
