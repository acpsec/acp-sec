## Context

acpsec.app today is a single Flask app (`dashboard/serve.py`, 1,157 lines) that both serves 10 inline-styled HTML pages and exposes a ~14-endpoint JSON API, deployed on Railway via the Werkzeug dev server. The Phase 0 audit (`docs/acpsec-app-audit-2026-06-29.md`) is the source of truth for everything below and confirmed the one fact that makes this migration safe: the **ACP Provider seller (Process B, `acpsec/acp_provider/`) shares no runtime with the web app** and is not in any deploy config. This change rebuilds the web app (Process A) as a Next.js frontend + FastAPI backend with strict behavioral parity.

Constraints: preserve the exact `/api/*` contract; do not reimplement scoring/scanner logic (import `acpsec` + `scanner.py`); keep all persistence server-side (frontend stateless); do not touch Process B, `contracts/`, or the `showcase/` manifest; staging-first with a zero-downtime DNS cutover.

## Goals / Non-Goals

**Goals:**
- Behavioral parity: all 10 pages and all 14 API endpoints behave identically to the live site (verified, not assumed).
- A real frontend foundation: one Tailwind design system (consolidating the contradictory token aliases), shared components, TypeScript, ready for the `/b20` route and future features.
- A clean frontend/backend split mirroring the proven acp-sec-b20 stack (FastAPI backend, Next.js frontend).
- Zero-downtime cutover with Process B untouched.

**Non-Goals (this change):**
- Rewriting or "improving" the scoring engine, `scanner.py`, the heuristic checks, or `acpsec.onchain` — they are imported as-is.
- Touching the ACP Provider (Process B), the `acp-sec-trust-score` offering, `contracts/`, or the `showcase/` manifest.
- New product features, redesigns, or content changes beyond consolidating the design tokens (parity first; features come after cutover).
- Migrating the file/in-memory stores to a database (the Railway-ephemeral trade-off is carried over unchanged).
- Building the acp-sec-b20 backend (separate repo/deploy); only the `/b20` frontend route is in scope here.

## Decisions

The following four decisions are **locked** (session-level) and are recorded here for rationale, not re-litigation.

**1. Backend: port `/api/*` to FastAPI (Option 2), not headless Flask (Option 1).**
- Same stack as acp-sec-b20 → one backend pattern across both repos, less context-switching, and a typed/OpenAPI surface for the frontend client.
- The port is a re-exposure, not a rewrite: handlers import `acpsec.scorer/models/catalogue/onchain` and the local `scanner.py` exactly as `serve.py` does today (audit Area 2 lists the 4 coupling points). Parity is enforced by testing each endpoint's response against the live Flask app.
- *Alternative (Option 1, headless Flask) was considered and rejected* in favor of stack consistency with acp-sec-b20; the extra port effort buys a unified backend and removes the dev-server.

**2. Page port order: legal → dashboard → leaderboard → monitor → scanner → playground.**
- Risk-ascending. Legal pages (privacy/terms/security) are static prose with **0 inline scripts** and **no API calls** — they prove the scaffold, layout shell, and design system end-to-end with near-zero risk. Dashboard and leaderboard add read-mostly API calls. Monitor adds charting (chart.js). Scanner is the highest-complexity page (1,880 lines, the SSRF-gated scan flow). The SentryAgent **playground is last** — it carries the ethers.js wallet/contract flow against the hardcoded Base Sepolia contract and is the most failure-prone to port.

**3. Frontend on Vercel, backend stays on Railway.**
- Vercel is the Preset-1/2 default and the natural Next.js host; Railway already runs the Python and the editable `acpsec` install. This is a **split origin**, which is the single biggest contract consequence (see Decision 4 / the `acpsec-auth-cors` capability).

**4. Staging-first cutover via `staging.acpsec.app`, then DNS.**
- Stand up the full frontend+backend on a staging subdomain, run the parity suite against the live site, and only then repoint `acpsec.app`. A DNS/alias cutover (not an in-place replace) keeps rollback to "repoint DNS back" and gives zero downtime. Process B is never redeployed as part of this.

**5. Cross-origin auth is an explicit capability, not an afterthought.**
- The audit flagged three contract risks created purely by splitting the origin: (a) the scanner gate's same-origin shortcut no longer fires from a Vercel origin, so the frontend must send `X-Scanner-Token` on the four gated endpoints (`/api/scanner/lookup|scan|bulk`, `/api/onchain/check`); (b) the `lb_session` cookie is `secure=False, SameSite=Lax` today and needs `SameSite=None; Secure` + credentialed fetches to survive split-origin; (c) the API sets no CORS headers today and must allow the known frontend origins explicitly. These live in `acpsec-auth-cors`.

**6. The frontend is stateless; all stores stay server-side.**
- The four stores (`score_store.json`, `scan_store.json`, `leaderboard.json`, `reports/*.json`) remain owned by the FastAPI service. `POST /api/scanner/scan` keeps its write side-effects (persist scan + upsert leaderboard + save report) on the backend; the frontend only reads/writes through the API.

### Target architecture

```
BEFORE (today):
  Flask serve.py = UI (10 HTML pages) + API (14 JSON endpoints)  [Railway, Werkzeug dev server]
  ACP Provider (Process B)                                        [separate, not deployed by Railway]

AFTER (acpsec-app-migration-v1):
  Next.js  = UI only (10 pages + /b20), one Tailwind theme        [Vercel]
       │  fetch (typed client, X-Scanner-Token, credentialed for lb_session)
       ▼
  FastAPI  = API only (14 endpoints, contract-identical)          [Railway]
       │  imports acpsec.{scorer,models,catalogue,onchain} + scanner.py (unchanged)
       ▼
  acpsec package + scanner.py + file/in-memory stores             [unchanged logic]

  ACP Provider (Process B)                                        [UNCHANGED, still separate]
```

### Endpoint parity matrix (the contract to preserve, from the audit)

| # | Route | Method | Gate | Notes for the port |
|---|---|---|---|---|
| 1–4 | `/api/score` (GET/POST/DELETE), `/api/score/manual` (POST) | — | none | score store; `_auto_normalise` acpsec/ASF detection must be preserved |
| 5 | `/api/controls` | GET | none | 38-control catalogue from `acpsec.catalogue` (fallback inline) |
| 6 | `/api/scanner/lookup` | POST | scanner | Nitter scrape |
| 7 | `/api/scanner/scan` | POST | scanner | **write-heavy**: persist + leaderboard upsert + report save |
| 8 | `/api/scanner/bulk` | POST | scanner | ≤10, 5s pacing |
| 9 | `/api/leaderboard` | GET | open | movement/rank derivation |
| 10 | `/api/report/<id>` | GET | open | 404 `report_not_found` shape |
| 11 | `/api/leaderboard/auth` | POST | — | sets `lb_session` cookie |
| 12 | `/api/onchain/check` | POST | scanner | `acpsec.onchain.check_acp_registration` |
| 13 | `/api/chat/sentryagent` | POST | server key | Claude proxy, server-side key |
| 14 | `/api/health` | GET | open | Railway healthcheck target |

## Risks / Trade-offs

- **Silent contract drift during the port.** → Parity is verified, not trusted: a per-endpoint comparison harness runs the same request against live Flask and the new FastAPI and diffs status + envelope + fields. No endpoint is "done" until it matches.
- **Split-origin breaks the scanner gate / session cookie.** → `acpsec-auth-cors` makes the frontend send `X-Scanner-Token` and credentialed requests, and moves the cookie to `SameSite=None; Secure`; tested on staging before cutover.
- **Reusing `scanner.py`/`acpsec` could tempt "small improvements."** → Explicit non-goal: imports only, zero logic edits. Any behavioral change there is out of scope for this change.
- **Playground wallet flow (ethers.js) is the riskiest port.** → Sequenced last, after the scaffold and every read-only page is proven; the hardcoded Base Sepolia contract address and BASESCAN links are carried over verbatim.
- **Dirty working tree mixed with active Phase 2 provider work.** → Investigate-then-decide is a Phase 1 task (commit vs stash) so the migration starts from a clean, understood base — not blocked on it, but done before frontend/backend code lands.
- **Python version drift (deploy 3.11.9 vs local 3.14).** → Reconciled as a Phase 1 task; the FastAPI service pins a single version across local + Railway.
- **DNS cutover risk.** → Staging-first with a DNS repoint (not in-place) keeps rollback trivial (repoint back) and downtime zero.

## Migration Plan

Brownfield, parity-first, staging-gated:

1. **Cleanup/Phase-1 prep** — investigate the dirty tree, decide commit/stash, pin Python version, scaffold the Next.js app + FastAPI service.
2. **Backend first** — port the 14 endpoints to FastAPI importing `acpsec`/`scanner.py`; stand up the parity harness against live Flask; add CORS + token/session handling.
3. **Frontend in risk order** — design system → legal → dashboard → leaderboard → monitor → scanner → playground, each consuming the API via the typed client; add the `/b20` route.
4. **Staging** — deploy frontend (Vercel) + backend (Railway) under `staging.acpsec.app`; run the full parity suite (10 pages, 14 endpoints, 4 gated flows).
5. **Cutover** — zero-downtime DNS repoint of `acpsec.app` to the new frontend/backend; Process B untouched. Rollback = repoint DNS back.

## Open Questions

- **Frontend origin value(s)** for the CORS allowlist and cookie domain — production `acpsec.app` + `staging.acpsec.app` + Vercel preview URLs? (affects `acpsec-auth-cors`).
- **Dirty-tree disposition** — do the uncommitted `CLAUDE.md`/`acpsec/cli.py`/`showcase/*` changes belong to Phase 2 provider work (commit on that branch) or are they orphaned (stash)? Resolved by the Phase 1 investigation task.
- **Same-origin proxy vs. true split-origin** — is a Vercel rewrite/proxy of `/api/*` onto the Railway backend preferred (restores same-origin, sidesteps CORS/cookie changes) or a clean cross-origin call? Decision affects how much of `acpsec-auth-cors` is needed; default assumption is true split-origin.
- **`/b20` backend availability** — the `/b20` route needs the acp-sec-b20 backend deployed; if it is not yet live, the route ships behind a feature flag.
