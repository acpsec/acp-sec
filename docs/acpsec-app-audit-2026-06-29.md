# acpsec.app — Phase 0 Migration Audit

**Date:** 2026-06-29
**Auditor:** Read-only inventory (no code changed)
**Purpose:** Map the existing Flask+static acpsec.app before planning a Next.js migration (Pilihan C). Establish exactly what the migration can touch (UI) vs what must keep running untouched (protocol-facing backend).

---

## TL;DR

acpsec.app is **two cooperating processes that share no runtime**:

- **Process A — Flask web app** (`dashboard/serve.py`): the 10-page UI + a ~14-endpoint JSON API. **Deployed on Railway.** This is the migration target.
- **Process B — ACP Provider seller** (`acpsec/acp_provider/`): a Node SDK loop + Python bridge that sells the `acp-sec-trust-score` offering on Base Sepolia. **NOT in any deploy config, NOT touched by Railway, independent of the UI.** This is the protocol money-path and must keep running as-is.

**The Next.js migration is cleanly scoped to Process A's presentation layer. Process B is unaffected.** The one real coupling to design around is Process A's Python JSON API (scoring/scanner/leaderboard/onchain), which cannot move to Next.js and must remain a backend service behind the new frontend.

This directly answers the concern about PR #11 / the Virtuals showcase: the protocol offering lives entirely in Process B and is untouched by a UI rebuild.

---

## AREA 1 — Page inventory

**Reality vs assumption:** Pages do NOT live in `dashboard/static/` (that holds only `logo.jpg`). They are standalone HTML files directly under `dashboard/` and `dashboard/agents/`, each with fully inline `<style>` and `<script>` — no external `.js`/`.css` files anywhere.

### 10 HTML pages (~8,072 lines, ~336 KB total)

| File | Lines | Bytes | Role |
|---|---|---|---|
| dashboard/scanner.html | 1880 | 77574 | **The big one** — Agent Scanner UI |
| dashboard/acp-sec-dashboard.html | 1718 | 67018 | Dashboard — scoring editor (the `/` landing) |
| dashboard/agents/sentryagent/playground.html | 1382 | 59352 | SentryAgent playground (ethers.js wallet flow) |
| dashboard/monitor_dashboard.html | 900 | 32405 | Monitor — watchlist + score history + drift alerts |
| dashboard/agents/sentryagent.html | 848 | 40591 | SentryAgent info page |
| dashboard/leaderboard.html | 594 | 24585 | Leaderboard |
| dashboard/leaderboard_login.html | 286 | 8802 | Leaderboard password gate |
| dashboard/security.html | 190 | 10097 | Legal/static |
| dashboard/terms.html | 144 | 8118 | Legal/static |
| dashboard/privacy.html | 130 | 7460 | Legal/static |

### Navigation & assets
- **Shared app nav:** `/` · `/scanner` · `/leaderboard` · `/monitor` · `/agents/sentryagent` · logo at `/static/logo.jpg?v=6`
- **Social/GitHub:** x.com/acpsecagent (⚠️ typo'd as `apsecagent` on some pages), github.com/acpsecagent/acp-sec
- **Hardcoded on-chain:** SentryAgent contract `0x7770ED57E3993d4555951a557cd158a6Fb87A470` on Base Sepolia (Basescan + Sourcify links)
- **Dynamic hrefs (JS template literals):** playground uses `${BASESCAN}/tx/${t.txHash}`, `${CONTRACT_ADDRESS}`; leaderboard uses `${scanUrl}`

### JavaScript
- **No standalone .js files** — all JS is inline `<script>` blocks.
- **External CDN scripts (only 3 libs):** chart.js@3.9.1 (jsdelivr + cdnjs, duplicated), ethers@6.7.1 (cdnjs UMD, for wallet/contract interaction)
- **Inline script counts:** scanner=2, dashboard=2, playground=2, monitor=2, leaderboard=1, leaderboard_login=1; legal pages + sentryagent.html have 0.

### CSS / design tokens
- **No standalone .css files** — every page has its own inline `<style>`.
- **Palette (Coinbase-style):** Brand blue `#0052FF`, green `#00C087`, amber `#F5A623`. Danger `#FF4444/#FF6B6B`, warn `#F0C000`. Dark: bg `#0A0B0D`, bg-secondary `#1C1D1F`, fg `#FFFFFF`. Light: bg `#FFFFFF`. Purple `#a78bfa`. SVG score-ring circumference `--ring-circ: 603.19`.
- ⚠️ **Token names inconsistent across files** — same hex `#0052FF` aliased as `--blue`, `--accent-base`, `--accent-info`, `--accent-purple`. **Consolidation target for the migration's design system.**

---

## AREA 2 — Flask app (`dashboard/serve.py`, 1,157 lines)

Single-file Flask app. Serves the 10 HTML pages via `send_file` + a JSON API. Key design points:

- **Optional acpsec integration:** try/import at module load; falls back to inline tables if absent (`ACPSEC_AVAILABLE` flag everywhere).
- **Persistence:** in-memory + disk (`score_store.json`, `scan_store.json`, `leaderboard.json`, `reports/*.json`) — explicitly ephemeral on Railway.
- **Two scoring schemes coexist:** 5-band `_FALLBACK_BANDS` + 6-band `_LEADERBOARD_BANDS`, plus a static 38-control `_FALLBACK_CHECKS` catalogue (AUTH/CTX/INJ/PRIV/OUT/GOV) duplicating `acpsec.catalogue`.
- **Security gating:** `_require_scanner_token()` + `_is_same_origin_request()` (Origin-header check) to stop the heuristic scanner being an open SSRF relay; leaderboard password + cookie sessions (`_lb_sessions`, 7-day).
- **External calls:** Nitter scrape (X profiles), heuristic site fetches (lazy `scanner.py`), Anthropic Claude proxy (`claude-sonnet-4-6`, server-side key), public RPC ACP-registration check (`acpsec.onchain`).
- **Prod:** debug off unless `FLASK_ENV != production`; binds `0.0.0.0`, PORT default 8080 (docstring says 5001 — stale). Runs Werkzeug dev server (gunicorn available but unused).

### acpsec package coupling (4 points, all soft/optional)
- L77–79 (module load): `acpsec.scorer` (CRITICAL_PENALTY, SCORE_BANDS, ScoringEngine), `acpsec.models` (CheckStatus, Severity), `acpsec.catalogue` (get_check_catalogue)
- L120 (`_apply_critical_penalties`): `acpsec.models` (CheckResult, CheckStatus, Severity)
- L632 (`/api/onchain/check`): `acpsec.onchain` (check_acp_registration)
- L254 (lazy): local `scanner.py` (heuristic engine — NOT part of acpsec)

---

## AREA 3 — The acpsec package

`acpsec/` is a large Python package (~50 modules). Beyond the scanner core (scorer.py, models.py, catalogue.py, cli.py, checks/, injection/), two subsystems matter:

### acpsec/acp_provider/ — the ACP protocol seller (Process B)
- **Python:** `__main__.py` (95), `executor.py` (92), `job_logic.py` (116), `__init__.py` (43)
- **Node:** `provider.mjs` (222), `lifecycle.mjs` (74), `boundedSet.mjs` (43), `test_client.mjs` (140), own package.json
- **Offering name:** `SERVICE_NAME = "acp-sec-trust-score"` (job_logic.py:19), `DEFAULT_CHAIN = "base-sepolia"`
- **Bridge invocation:** `python -m acpsec.acp_provider <requirement> [--mode evaluate|scan]` — single source of truth for parse → accept/reject → scan → deliverable

### acpsec/trust_score/ — the scoring engine
engine.py, weights.py, dimensions/*, data/* adapters (basescan.py, virtuals_client.py, acp_lifecycle.py, smart_account_reader.py, slither_runner.py).

### Protocol/Virtuals coupling (concentrated, not pervasive)
- config_loader.py / models.py — v0.4.0 Virtuals-ACP / ERC-8183 identity + commerce config
- onchain.py (158 lines) — best-effort read-only ACP registration check against Base mainnet ACP Core `0x238E541BfefD82238730D00a2208E5497F1832E0` (default mainnet.base.org, last ~50k blocks). Returns `registered=None` on failure, never raises.
- checks/commerce.py, checks/identity.py — Virtuals ACP commerce/identity scoring dimensions

---

## AREA 4 — Deployment

| Artifact | Value |
|---|---|
| Procfile | `web: python dashboard/serve.py` |
| railway.json | startCommand `python dashboard/serve.py`, healthcheck `/api/health`, NIXPACKS, restart-on-failure (max 5) |
| runtime.txt | python-3.11.9 |
| requirements.txt | `-e .` (whole acpsec package) + flask, requests, beautifulsoup4, gunicorn (unused) |
| .railwayignore | excludes tests/, docs/, reports/, .venv/ — **reports/ NOT shipped (leaderboard reports regenerated at runtime, ephemeral)** |

- **Only the Flask web process is deployed.** The ACP provider Node loop (Process B) is NOT in any deploy config.
- Two `__main__` entrypoints: `dashboard/serve.py` (Flask) + `acpsec/acp_provider/__main__.py` (scan bridge).
- ⚠️ **Version drift:** deploy pins Python 3.11.9, local venv is 3.14.

---

## AREA 5 — Git state

| | |
|---|---|
| Remote | github.com/acpsec/acp-sec.git (org "acpsec", NOT "acpsecagent" used in HTML links) |
| HEAD | `414a841` refactor(acp-provider): single source of truth for accept/reject (M2.3) |
| Last commit | 2026-06-14 17:45 (≈2 weeks stale) |
| Working tree | **DIRTY** |

- Recent commits are all acp-provider Phase 2 ("M2.x") work — the protocol seller is the active workstream.
- **Modified (uncommitted):** CLAUDE.md, acpsec/cli.py, showcase/acp-sec/skills/acp-sec-scan/SKILL.md, showcase/acp-sec/soul.md
- **Untracked:** contracts/package-lock.json, scripts/acp-roundtrip.sh, scripts/find-entity-id.mjs, showcase/acp-sec/{README.md, examples/, showcase.json}

⚠️ **Before migration starts, this working tree must be cleaned (commit or stash).** Don't migrate on top of a dirty tree mixed with active Phase 2 provider work.

---

## AREA 6 — Protocol-facing vs UI-only map (CRITICAL)

```
┌─────────────────────────────────────────────────────────────┐
│ PROCESS A — Flask web app   (DEPLOYED on Railway)            │
│   dashboard/serve.py  → 10 HTML pages + 27 routes / JSON API │
│   Imports acpsec (scorer/catalogue/models/onchain) + scanner │
│   This is the UI + heuristic web-scanner. 100% UI-facing.    │
│   ★ MIGRATION TARGET                                          │
└─────────────────────────────────────────────────────────────┘
                  (no shared runtime; separate processes)
┌─────────────────────────────────────────────────────────────┐
│ PROCESS B — ACP Provider seller   (NOT in any deploy config) │
│   acpsec/acp_provider/provider.mjs                           │
│     • Node loop on @virtuals-protocol/acp-node 0.3.0-beta.40 │
│     • polls Base Sepolia for jobs (REQUEST/TRANSACTION)      │
│     • spawns `python -m acpsec.acp_provider` to scan         │
│     • delivers Trust Score JSON via ACP escrow               │
│   Python bridge: job_logic.py + executor.py (run_scan)       │
│   Offering: "acp-sec-trust-score" on Base Sepolia            │
│   Wallet env: WHITELISTED_WALLET_PRIVATE_KEY,                │
│     SELLER_AGENT_WALLET_ADDRESS, SELLER_ENTITY_ID            │
│   ★ MUST KEEP RUNNING — DO NOT TOUCH                          │
└─────────────────────────────────────────────────────────────┘
```

### Migration safety matrix

| Layer | Safe to migrate to Next.js? | Notes |
|---|---|---|
| 10 HTML pages (inline CSS/JS) | ✅ Yes — pure UI | scanner/dashboard/monitor/leaderboard/playground + legal |
| Flask /api/* (27 routes) | ⚠️ Must PRESERVE the contract | ~14 real JSON endpoints; logic is Python (acpsec, scanner.py). Keep a Python API service behind the new frontend. |
| scanner.py heuristic engine + acpsec scoring | ❌ Stays Python | SSRF-gated; Nitter/site fetches; Slither; Basescan. Not portable to React/edge cheaply. |
| ACP Provider (Process B) | ❌ Must stay running, untouched | Node SDK + Python bridge + wallet keys + Base Sepolia escrow. Independent of UI. |
| contracts/ | ❌ Out of scope | On-chain. |

### Operational tooling (Process B support, not migration scope)
- scripts/acp-roundtrip.sh (15.5 KB — end-to-end buyer↔seller test), find-entity-id.mjs, verify-acp-env.mjs (ACP env preflight)
- examples/ — static YAML agent configs + saved .scan.json fixtures (test/demo data, no runtime role)
- showcase/ — agent persona/skill assets (has uncommitted changes)

---

## The 14 JSON API endpoints — contract index (what Next.js will consume)

| # | Route | Method | Auth gate | Request | Success → |
|---|---|---|---|---|---|
| 1 | /api/score | GET | none | — | {ok, data\|null} |
| 2 | /api/score | POST | none | acpsec {dimensions} or ASF {controls} | {ok, data:wire} |
| 3 | /api/score/manual | POST | none | {agent_name, controls[]} | {ok, data:wire+source:"manual"} |
| 4 | /api/score | DELETE | none | — | {ok} |
| 5 | /api/controls | GET | none | — | {source, acpsec_available, checks[], asf_controls[]} |
| 6 | /api/scanner/lookup | POST | scanner | {username} | {ok, data:{display_name, bio, website, avatar_url, …}} |
| 7 | /api/scanner/scan | POST | scanner | {url, agent_name, username, scan_mode, scraped, x_bio} | {ok, data:scan} (write-heavy) |
| 8 | /api/scanner/bulk | POST | scanner | {usernames[≤10], scan_mode} | {ok, count, results[]} |
| 9 | /api/leaderboard | GET | open | — | {ok, updated, checks_per_scan, count, agents[]} |
| 10 | /api/report/<id> | GET | open | path id | {ok, data} / 404 report_not_found |
| 11 | /api/leaderboard/auth | POST | — | {password} | {ok} + Set-Cookie lb_session |
| 12 | /api/onchain/check | POST | scanner | {wallet} | {ok, data:{registered:true\|false\|null, …}} |
| 13 | /api/chat/sentryagent | POST | server key | {messages[]} | {ok, reply} (Claude proxy) |
| 14 | /api/health | GET | open | — | {ok, service, acpsec_available, scanner_protected} |

### Three contract risks the Next.js frontend must design around

1. **Same-origin scanner gate** — a different-origin frontend loses the free same-origin pass on #6/#7/#8/#12 and must send `X-Scanner-Token` (or be proxied under the API's host).
2. **lb_session cookie** is `secure=False, SameSite=Lax, httpOnly` — split-origin needs `SameSite=None; Secure` + credentialed CORS.
3. **No CORS headers anywhere** — cross-origin consumption requires adding them server-side.

---

## Recommended architecture (revised Pilihan C)

The migration is NOT "everything becomes Next.js." It is a **clean frontend/backend split**, identical to the proven acp-sec-b20 pattern:

```
BEFORE (today):
  Flask serve.py = UI (HTML) + API (JSON) in one app on Railway
  ACP Provider (Process B) runs separately

AFTER (Pilihan C, revised):
  Next.js  = UI only (React pages → fetch the API)   [Vercel or Railway]
  Python   = API only (preserve the ~14 endpoints)   [Railway]
  ACP Provider (Process B) = UNCHANGED, still separate
```

Two clean ways to do the backend:
- **Option 1 (lower risk):** Keep `dashboard/serve.py` as a headless JSON API (strip the HTML page routes, keep the /api/* surface). Add CORS + token handling for the new frontend origin.
- **Option 2 (more work):** Port the /api/* layer to FastAPI (matching acp-sec-b20's stack), reusing the same acpsec package + scanner.py imports.

Decision deferred to Phase 1 spec.

---

## Phase 1 inputs (what the OpenSpec proposal must cover)

1. **Backend strategy:** Option 1 (headless Flask) vs Option 2 (FastAPI port). Decide based on effort vs stack-consistency.
2. **Page port order:** Suggested — legal pages first (lowest risk, no API), then dashboard, leaderboard, monitor, scanner (highest complexity), playground (ethers.js wallet flow) last.
3. **Design system:** consolidate the inconsistent token aliases into one Tailwind theme. Preserve the Coinbase-style palette.
4. **Auth/CORS:** how the split-origin frontend handles the scanner token + leaderboard session.
5. **Deployment:** frontend host (Vercel vs Railway), backend stays Railway, DNS cutover with zero downtime, ACP Provider untouched.
6. **State:** the file/in-memory stores (score, scan, leaderboard, reports) — keep server-side in the Python API; the Next.js frontend is stateless.
7. **Pre-migration cleanup:** commit/stash the dirty working tree first; align Python version (3.11.9 deploy vs 3.14 local).
8. **The /b20 page:** port the existing `~/sentrak/acpsec-app/` Next.js scaffold components (HolderView, DimensionBreakdown, RawJson, badges) into the new structure as the `/b20` route, pointing at the acp-sec-b20 backend (separate deploy).

---

## What Phase 0 did NOT touch (by design)

No code changed. No files modified. No commits. No deploys. Pure read-only exploration. The dirty working tree (Areas 5) is pre-existing and unrelated to this audit.
