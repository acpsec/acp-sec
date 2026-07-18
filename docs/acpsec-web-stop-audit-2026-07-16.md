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

**Executed:** 2026-07-16 **13:23:03 UTC** / **20:23:03 WIB**. Verification
completed within ~5 min of the stop.

#### Stop mechanism (exact, reproducible)

```bash
railway down --service web --environment production -y
```

- Removes `web`'s **most recent (active) deployment** — the CLI's scale-to-zero
  equivalent. The **service, variables, domains, and deployment history all
  persist**; nothing is deleted.
- `--service web` and `--environment production` are passed **explicitly** because
  the CLI is linked to `api-prod` — without them the command would target the
  wrong service. `-y` skips the confirmation prompt. Command produced no stdout on
  success.

#### Deploy IDs / status — `web`

| | Deploy ID | Status |
|---|---|---|
| **Pre-stop** | `bba131bd-f455-4912-b183-06de8479fe17` (commit `5ca798c`, created 2026-07-14T01:35:43Z) | RUNNING |
| **Post-stop** | — none — | `no-active-deployment` |

`api-prod` (`2a1bdb22-…`, RUNNING) and `web-staging` (`7b5a8fb9-…`, RUNNING) were
**untouched** before and after.

#### Post-stop verification (step 3 — all PASS)

| # | Check | Result | Evidence |
|---|---|---|---|
| a | `acpsec.app` serves Vercel | **PASS** | `HTTP 200`, `server: Vercel`, `x-vercel-cache: HIT` |
| b | `api-prod` `/api/health` | **PASS** | `{"ok":true,"service":"acp-sec-dashboard","acpsec_available":true,"scanner_protected":true}` |
| c | Leaderboard end-to-end | **PASS** | Browser-path CORS fetch `Origin: https://acpsec.app` → `api-prod` `/api/leaderboard`: `HTTP 200`, `access-control-allow-origin: https://acpsec.app`, **26 agents** |
| d | `web` raw URL → no-deployment | **PASS** | `GET https://web-production-2ef7a.up.railway.app/` → `HTTP 404`, body verbatim: `{"status":"error","code":404,"message":"Application not found","request_id":"SuCq0hJ-Tj-BJnS4WUN5dQ"}` |
| e | `acpsec.app` still attached to `web` | **PASS** | `railway domain status acpsec.app --service web` → custom, ID `4f999606-…`, port 8080, Sync ACTIVE, Verified yes, cert VALID |

Browser-path note: `https://acpsec.app/api/leaderboard` returns `404` HTML — the
Next.js frontend has **no server-side `/api` route**; it fetches the backend
**client-side**. `api.acpsec.app` is **not configured** (no DNS), so the frontend's
API base is the `api-prod` raw URL, reached cross-origin under CORS (check c).

**The `acpsec.app` custom-domain attachment was intentionally LEFT IN PLACE** on
`web` (linchpin of the DNS-revert rollback). Not touched.

#### Rollback recipe (executable standalone, months later)

Restore the pre-cutover state = `acpsec.app` served by the Flask `web` service.
**Order matters: rebuild `web` first, then revert DNS.**

**a. Rebuild `web` from commit `5ca798c`** (verified state as of 2026-07-18 — this
is a **cold build, not a restart**):

- ❌ **`railway redeploy` is NOT viable.** The pinned deployment `bba131bd`
  (commit `5ca798c`) is **REMOVED** and **does not appear in the Railway
  Deployments UI at all** — there is no Redeploy button for it.
- ❌ The **only** remaining deployment record is the **FAILED** one from
  2026-07-09 (`dd72e034`), which errors `service config at
  '/railway.staging.json' not found` — a Group 8 artifact from when `web`'s
  source branch was briefly switched to `deploy/staging`. Not redeployable.
- ✅ **The only rollback path is a fresh build of `web` from commit `5ca798c`**
  (the last commit with the Flask tree intact). ⚠️ **`main` HEAD will NOT work
  after Group 9.6** — the retired Flask `dashboard/serve.py` still reads
  `dashboard/leaderboard.json` / `dashboard/reports/` / `import scanner`, all of
  which 9.6 moved (`→ data/`, `→ acpsec_api/`), so a HEAD build deploys a
  **broken Flask**.
- 🔴 **CRITICAL — re-enable auto-deploy first.** `web`'s "Auto deploys when
  pushed to GitHub" was **DISABLED on 2026-07-18** (Settings → the branch
  connected to `production`). Until it's re-enabled — or a **manual deploy from
  `5ca798c`** is triggered — **nothing will deploy**, and the cause is
  non-obvious (no error, just silence). Steps: Railway → `sublime-truth` → `web`
  → **Settings** → branch connected to `production` → **Enable**, then trigger a
  deploy pinned to commit `5ca798c` (not HEAD).
- ⏱️ **Duration:** a cold NIXPACKS build ≈ **10–15 min**, plus DNS propagation
  after the revert and a possible cert re-issue (step c). This is materially
  slower than the "restart" originally assumed.
- ⚠️ **This rollback path has NOT been tested.** Validate `web`'s raw URL returns
  `HTTP 200` before touching DNS.

**b. Namecheap DNS revert** (`acpsec.app` root record):
- Current (Vercel): `A  @  → 216.198.79.1`.
- Revert to Railway — set the root (`@`) to the Railway target:
  **`ALIAS  @  → k8je5ty4.up.railway.app`** (remove the Vercel `A 216.198.79.1`).
- **Record type (validated assumption):** Namecheap's Advanced DNS supports an
  **ALIAS Record at apex** (verified 2026-07-17 — the ALIAS Record type appears in
  the Add New Record dropdown on this account). Pre-cutover, `acpsec.app` used
  `ALIAS @ → k8je5ty4.up.railway.app`; that record was **replaced (not parked)** by
  the current `A @ → 216.198.79.1` during cutover — so rollback **recreates** the
  ALIAS record, it is not restored from a disabled state.
- **Supporting evidence:** viewdns.info shows only `216.198.79.1` in the domain's
  IP history — consistent with a non-A (ALIAS) apex before cutover, since
  A-record-history services don't capture ALIAS/CNAME targets.
- This is the exact, still-valid target — the domain remains attached to `web`.
  Source of truth: `railway domain status acpsec.app --service web` → DNS record
  `CNAME @ → k8je5ty4.up.railway.app` (Railway reports it as `CNAME`; at apex on
  Namecheap this is created as an **ALIAS**).

**c. Cert re-issue caveat:** the Railway-managed (Let's Encrypt) cert for
`acpsec.app` is currently **VALID**. During a prolonged Vercel-only grace period,
Railway's ACME renewal can lapse (validation needs DNS pointing back at Railway,
which it won't be until revert). On DNS revert Railway re-validates and may
**re-issue the cert → expect a few-minute window** where HTTPS to `acpsec.app`
fails or shows a cert warning before resolving cleanly. Don't detach/re-attach the
domain to force it unless it stalls beyond ~15 min.

**d. Post-rollback verification** (mirrors step 3, reverted state):
- `acpsec.app` → `HTTP 200`, `server: railway-hikari` (Flask, **not** Vercel).
- `acpsec.app/api/health` → `{"ok":true,...}` (Flask serves API + pages again).
- `acpsec.app/leaderboard` → Flask leaderboard page loads.
- `web` raw URL → `HTTP 200` (deployment running again).
- `api-prod` `/api/health` still `ok:true` (DNS revert doesn't affect it).

#### Grace-period note

`web` stays **stopped-but-present** — no active deployment; service, variables,
domains, and deployment history intact — until an **explicit later instruction to
delete**. Deletion (detach `acpsec.app` + delete the service) is **not scheduled
here.**

---

## Post-delete follow-ups

Deferred cleanup. Except where marked done, all remain **gated on the separate
later instruction to delete `web`** (detach `acpsec.app` + delete the service).
Not scheduled here — captured so nothing is lost.

- **✅ DONE (2026-07-18) — Fold this audit into `main`.** Brought to `main` via
  fast-forward merge on 2026-07-18 (`origin/main == deploy/staging == f81ce04`);
  no longer stranded on `deploy/staging`. This happened ahead of `web` deletion
  because `web`'s auto-deploy was disabled the same day, removing the
  filter-less-rebuild hazard that had blocked it.
- **Remove `railway.json`** alongside the `web` service deletion — it is the
  `web` (Flask) service config and becomes dead once `web` is gone. (Its missing
  `watchPatterns` are moot: `web`'s auto-deploy is disabled, so `main` pushes no
  longer rebuild it regardless.)
- **Remove `Procfile`** (`web: python dashboard/serve.py`) at the same time — the
  other `web` start-command artifact, pairs with `railway.json`.
- **Retire the legacy Flask/`dashboard/` stack** — superseded by `api-prod`
  (FastAPI) + the Vercel frontend. **After Group 9.6 this is smaller and
  data-safe:** `dashboard/scanner.py` and the committed data
  (`leaderboard.json`, `reports/`) have already moved out (`→ acpsec_api/`,
  `→ data/`), so **no data must be preserved here anymore.** What remains to
  delete in `dashboard/` is only the retired Flask app + its assets:
  `serve.py`, `auth_scanner.py`, the 10 inline HTML pages
  (`acp-sec-dashboard.html`, `scanner.html`, `monitor_dashboard.html`,
  `leaderboard*.html`, `security/privacy/terms.html`, `agents/…`), the static
  assets (`static/logo.jpg`, `robots.txt`, `sitemap.xml`,
  `.well-known/security.txt`), `requirements.txt`, and the `mock_*.py` helpers.
  `dashboard/serve.py:254` (`import scanner`) is already broken post-9.6 — dead
  code confirming nothing live depends on it.
- **Delete the env backup** `~/sentrak/backups/acpsec-web-env-20260716.txt` once
  `web` is gone — it holds only 13 Railway system vars (no secrets), removable
  without redaction concerns.
- **`web-staging`** is out of 9C scope but likely a parallel retirement candidate
  post-cutover — flag for its own audit before any action.
- **`web` auto-deploy is DISABLED (2026-07-18).** If `web` is ever **deleted**,
  this setting disappears with the service (nothing to clean up). If `web` is
  ever **revived** (rollback — see Phase 2 §a), the setting must be
  **re-enabled first**, or the deploy silently does nothing.

---

## Group 9.3 — post-cutover monitoring record

**Recorded:** 2026-07-17 11:48 UTC / 18:48 WIB.

- **Cutover date:** `acpsec.app` DNS flipped to Vercel on **2026-07-16**, on/after
  the api-prod CORS go-live gate (`api-prod` restart `2026-07-16T03:18:34Z`,
  deploy `2a1bdb22`). The exact DNS-flip timestamp is not independently logged in
  the repo; it falls between that gate (03:18 UTC) and the `web` stop (13:23 UTC).
- **`web` stop:** `2026-07-16 13:23:03 UTC` / `20:23:03 WIB` (see Phase 2).

**5xx since cutover — `api-prod` HTTP logs**
(`railway logs --service api-prod --http --since 2026-07-13T00:00:00Z`; buffer
retained `2026-07-16T03:20:44Z → 13:30:19Z`, i.e. bounded to the current
deployment start — older logs are not retained, so this window starts just after
cutover):

- **5xx count: 0.** No server errors, no bursts across 29 requests.
- Non-2xx were all expected client-side: `3×401` (`/api/scanner/lookup` auth gate),
  `2×499` (client closed a ~90 s `/api/b20/scan` at 03:30 & 03:44 — an early
  smoke run, not recurring), `2×400` + `1×422` (request validation). 21×200.

**Today's spot checks (2026-07-17 11:48 UTC)**

| Check | Result |
|---|---|
| `api-prod` `/api/health` | `HTTP 200` — `{"ok":true,"acpsec_available":true,"scanner_protected":true}` |
| Leaderboard CORS (`Origin: https://acpsec.app`) | `HTTP 200`, `access-control-allow-origin: https://acpsec.app`, **26 agents** |
| `acpsec.app` frontend | `HTTP 200`, `server: Vercel` |

**Verdict: STABLE.** ~1 day post-cutover / ~22 h post-`web`-stop: zero server
errors on api-prod, frontend and leaderboard healthy end-to-end. No action needed.
Retention caveat: continuous 5xx history is limited by Railway's
deployment-scoped log retention — this record reflects the retained window plus
live spot checks, not an uninterrupted trace back to the DNS flip.

---

## Group 9.6 — scanner.py relocation

**Goal:** sever api-prod's runtime dependency on `dashboard/` so the Flask tree
can be deleted with `web` after the grace period, without breaking api-prod.

### What moved
- **Engine:** `dashboard/scanner.py` → `acpsec_api/scanner.py` (2,380 lines,
  framework-agnostic — stdlib + `requests` + `bs4`, zero Flask coupling).
- **Committed data:** `dashboard/leaderboard.json` → `data/leaderboard.json`;
  `dashboard/reports/` (25 files) → `data/reports/`.

### Repointed references (the one import + four path constants)
| Reader | Was | Now |
|---|---|---|
| `acpsec_api/deps.py` `get_scanner_engine()` | `from dashboard import scanner` | `from acpsec_api import scanner` |
| `acpsec_api/deps.py` `DEFAULT_REPORTS_DIR` | `dashboard/reports` | `data/reports` |
| `acpsec_api/deps.py` `DEFAULT_SCAN_STORE` | `dashboard/scan_store.json` | `data/scan_store.json` |
| `acpsec_api/store.py` `_DEFAULT_STORE_FILE` | `dashboard/score_store.json` | `data/score_store.json` |
| `acpsec_api/leaderboard_store.py` `_DEFAULT_LEADERBOARD_FILE` | `dashboard/leaderboard.json` | `data/leaderboard.json` |

Config repointed too: `.gitignore` (store paths), `.railwayignore`
(root-anchored `/reports/` so shipped `data/reports/` isn't excluded),
`railway.prod.json` + `railway.staging.json` watchPatterns (`dashboard/*.json` →
`data/*.json`, `dashboard/reports/**` → `data/reports/**`, dropped
`dashboard/scanner.py` — covered by `acpsec_api/**`). Result: **zero runtime
`dashboard/` dependency in `acpsec_api/`** (provenance docstrings kept as
history).

### Behavior-preservation proof — characterization test
`dashboard/scanner.py` had **no direct unit test** (the `tests/api/` scanner
tests inject a fake and pin only the router contract). So before moving anything,
`tests/test_scanner_engine.py` was written to **pin the current behavior** of the
two entry points api-prod calls (`analyze_agent`, `extract_token_info`) with the
network fully stubbed — captured from live output, not aspirational. It ran green
at the **old** location, then again — **byte-for-byte identical assertions** — at
the **new** location. That identity is the proof the move changed nothing;
`test_report_found_parity` (the Flask oracle, now cut off from the relocated data)
was retired in favor of api-prod's live 200 as ground truth. Full suite: 1122
passed.

### Deploy + verification
- **web-staging** (FastAPI staging, `deploy/staging` push): rebuilt `073a88d7`
  SUCCESS. Smoke: `/api/health` ok; `/api/leaderboard` 26 (from
  `data/leaderboard.json`); live `POST /api/scanner/scan` → 200; report
  round-trip via `data/reports/` (200); seed `aixbt` served.
- **api-prod** (main push, 2026-07-18): pre `2a1bdb22` → post **`6f17d334`**
  SUCCESS. `web` stayed **dormant** (auto-deploy disabled; `activeDeployments`
  empty, no new record). Smoke: `/api/health` ok; `/api/leaderboard` 26; live
  scan → 200; report round-trip via `data/reports/` (`/api/report/prod_smoke_96`
  → 200); seed `aixbt` → 200; `acpsec.app` 200/Vercel; CORS leaderboard from
  `acpsec.app` origin → 200. *(Both smokes leave an ephemeral throwaway agent in
  the respective leaderboard; clears on next restart.)*
