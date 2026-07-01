## Why

acpsec.app is live and working, but its presentation layer is tech-debt heavy and blocks future velocity. The Phase 0 audit (`docs/acpsec-app-audit-2026-06-29.md`) found **10 standalone HTML pages (~8,072 lines / ~336 KB) with fully inline `<style>`/`<script>`, no shared components, and design tokens whose names contradict each other** (the same `#0052FF` aliased as `--blue`, `--accent-base`, `--accent-info`, `--accent-purple` across files). The app is served by Flask's **Werkzeug dev server** (gunicorn is in `requirements.txt` but unused). There is no component system, no type safety, and no path to ship the planned `/b20` page cleanly. Migrating the UI to Next.js + the API to FastAPI unlocks the `/b20` integration and gives every future feature a real component/design-system foundation. This is the **Pilihan C** decision from session planning (46/50 quality score) — a clean frontend/backend split, not a rewrite.

The audit's central finding makes this safe: acpsec.app is **two processes that share no runtime**. Process A (Flask `dashboard/serve.py`) is UI + a ~14-endpoint JSON API and is the only thing Railway deploys. Process B (`acpsec/acp_provider/` — the ACP seller for the `acp-sec-trust-score` offering on Base Sepolia) runs separately and is untouched by anything the UI does. This migration is scoped entirely to Process A's presentation layer.

## What Changes

- Introduce **acpsec-app-migration-v1**: rebuild Process A as a **Next.js frontend (Vercel) + FastAPI backend (Railway)** while preserving exact behavioral parity with the current site.
- **UI → Next.js + TypeScript + Tailwind (Preset 1/2):** port all **10 pages** — legal (privacy, terms, security) first, then dashboard, leaderboard, monitor, scanner, and the SentryAgent playground (ethers.js wallet flow) last. Consolidate the contradictory inline tokens into **one Tailwind theme** preserving the Coinbase-style palette (blue `#0052FF`, green `#00C087`, amber `#F5A623`, dark/light surfaces). Add the `/b20` route by porting the existing acp-sec-b20 Next.js scaffold (it calls the separate acp-sec-b20 backend, not this API).
- **API → FastAPI (Option 2, locked):** port the **14 `/api/*` endpoints** to FastAPI (same stack as acp-sec-b20), **reusing the `acpsec` package and `scanner.py` imports directly** — no scoring/scanner logic is rewritten. Every endpoint MUST return a byte-for-contract-identical response (status codes, envelope `{ok, data?, error?}`, field names).
- **Cross-origin auth/CORS (new concern):** a split-origin frontend (Vercel) loses the same-origin free pass the current scanner gate relies on. Define how the scanner token (`X-Scanner-Token`), the leaderboard `lb_session` cookie (`SameSite`/`Secure`), and server-side CORS are handled so the four gated endpoints keep working.
- **Staging-first cutover (locked):** stand up `staging.acpsec.app`, run parity testing against the live site, then perform a **zero-downtime DNS cutover**. Backend stays on Railway; ACP Provider (Process B) keeps running untouched throughout.
- **Pre-migration cleanup:** the working tree is dirty with active Phase 2 provider work. Investigate the dirty contents and decide commit-vs-stash, and reconcile the Python version drift (deploy pins 3.11.9, local venv is 3.14) — these are Phase 1 tasks, not preconditions.

## Capabilities

### New Capabilities
- `acpsec-api-service`: A FastAPI service that re-exposes the 14 `/api/*` endpoints with identical request/response contracts, importing the existing `acpsec` package (`scorer`, `models`, `catalogue`, `onchain`) and the local `scanner.py` heuristic engine rather than reimplementing them. Owns the server-side file/in-memory stores (score, scan, leaderboard, reports) so the frontend stays stateless.
- `acpsec-web-frontend`: The Next.js + TypeScript + Tailwind app replacing the 10 inline-styled HTML pages, with a single consolidated design-system theme, shared components, and the new `/b20` route. Ports pages in the locked low-risk-first order and consumes the API via one typed client.
- `acpsec-auth-cors`: The cross-origin contract — scanner-endpoint gating via `X-Scanner-Token` (replacing the same-origin shortcut for a different-origin frontend), the leaderboard session cookie adapted for split-origin (`SameSite=None; Secure` + credentialed requests), and explicit server-side CORS for the known frontend origins.
- `acpsec-deploy-cutover`: The staging-first rollout — `staging.acpsec.app`, full parity verification against the live site, zero-downtime DNS cutover, and the explicit guarantee that Process B (ACP Provider) is neither redeployed nor interrupted.

### Modified Capabilities
<!-- None — openspec/specs/ is empty (no previously-deployed capabilities to amend). This change introduces the first specs for the acpsec.app frontend/backend split. -->

## Impact

- **In scope (Process A only):** `dashboard/*.html` (10 pages) → Next.js; `dashboard/serve.py`'s `/api/*` surface → FastAPI; the inline CSS/JS → Tailwind theme + components; new `/b20` route; deployment topology (Vercel frontend + Railway backend) and DNS.
- **Out of scope (do NOT touch):** the ACP Provider (`acpsec/acp_provider/`, Process B) and its offering; `contracts/`; the `showcase/` manifest; and the internals of `scanner.py` + the `acpsec` scoring engine (`trust_score/`, `checks/`, `scorer.py`, `onchain.py`) — these are **imported as-is** by the new FastAPI service, never reimplemented.
- **Frontend:** new Vercel deploy (Preset 1/2 — Next.js + TypeScript + Tailwind; wagmi/viem/ethers only on the playground + `/b20`). Stateless; all persistence stays server-side.
- **Backend:** FastAPI on Railway, replacing the Werkzeug dev server. Same `acpsec` editable install; adds CORS + token handling. The four file/in-memory stores remain server-side and Railway-ephemeral (unchanged trade-off).
- **External constraints:** Vercel (frontend host), Railway (backend host), `acpsec.app` DNS (cutover), `staging.acpsec.app` (new staging subdomain). Env vars carried over: `SCANNER_TOKEN`, `LEADERBOARD_PASSWORD`, `ANTHROPIC_API_KEY`, `BASE_RPC_URL`, `PORT`.
- **Success criteria:** (1) all **10 pages** render and behave at parity with the current site; (2) all **14 API endpoints** return contract-identical responses (status + envelope + fields) verified against the live site; (3) the four gated endpoints work from the new frontend origin; (4) **zero-downtime** DNS cutover; (5) Process B (ACP Provider) runs uninterrupted and unredeployed throughout.
