# Staging environment inventory — `staging.acpsec.app`

> **Names and purposes only — never values.** Secret values are entered by
> Fadhlan directly into Railway/Vercel (CLI prompt or dashboard). This file is
> committed; it must never carry a secret.

Scope: the **FastAPI backend** (`web-staging` Railway service, `deploy/staging`
branch, config `railway.staging.json`) and the **Next.js frontend** (Vercel).
Gate decisions this reflects: **8.0a = split origin**, **8.0b = ephemeral
storage (no volume)**, **8.0c = public Base RPC**.

## Backend — Railway `web-staging`

| Variable | Purpose | Secret? | Required for staging? | Notes |
|---|---|---|---|---|
| `PORT` | Port uvicorn binds (`--port $PORT`). | no | yes | Injected by Railway automatically — do **not** set by hand. |
| `SCANNER_TOKEN` | Shared token gating the SSRF-sensitive endpoints (`/api/scanner/lookup\|scan\|bulk`, `/api/onchain/check`). Unset ⟹ endpoints run open (dev mode). | **yes** | yes | Split-origin: the browser no longer satisfies the same-origin bypass, so the frontend sends it as `X-Scanner-Token`. **Must equal** the frontend's `NEXT_PUBLIC_SCANNER_TOKEN`. |
| `LEADERBOARD_PASSWORD` | Password checked by `POST /api/leaderboard/auth` before issuing the `lb_session` cookie. | **yes** | yes | Needed for leaderboard login to work on staging. |
| `ANTHROPIC_API_KEY` | Server-side Claude key for the `POST /api/chat/sentryagent` proxy. Unset ⟹ chat returns 503. | **yes** | optional | Required only if the SentryAgent playground chat is exercised on staging. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated exact origin allowlist (overrides the built-in default). | no | optional | Default already includes `https://staging.acpsec.app`, `https://acpsec.app`, and localhost — leave unset unless locking further. |
| `CORS_ALLOWED_ORIGIN_REGEX` | Regex allowing Vercel preview origins (overrides the default `acpsec-web-<hash>.vercel.app` pattern). | no | optional | Default already matches acpsec-web preview URLs. |
| `ACPSEC_COOKIE_SAMESITE` | `SameSite` attribute for `lb_session`. | no | optional | Default `none` — correct for split-origin. Leave unset. |
| `ACPSEC_COOKIE_SECURE` | `Secure` flag for `lb_session`. | no | optional | Default `true` — correct over HTTPS. Leave unset. |
| `BASE_RPC_URL` | Optional RPC override for `POST /api/onchain/check` only. | no (public endpoint) | optional | Gate 8.0c: **leave unset** on staging → uses the public Base endpoint. Does **not** affect the b20 scan engine (which hardcodes its own public endpoints). |

**Minimal staging set to enter by hand:** `SCANNER_TOKEN`, `LEADERBOARD_PASSWORD`
(both secret), plus `ANTHROPIC_API_KEY` if chat is tested. Everything else uses
correct built-in defaults.

## Frontend — Vercel

| Variable | Purpose | Secret? | Required? | Notes |
|---|---|---|---|---|
| `NEXT_PUBLIC_API_URL` | Base URL of the FastAPI backend, baked into the bundle at build time. | no | yes | Split-origin (8.0a=B): set to the backend origin, e.g. `https://api-staging.acpsec.app`. A missing value silently falls back to `http://localhost:8001`. |
| `NEXT_PUBLIC_SCANNER_TOKEN` | Token the browser sends as `X-Scanner-Token` on gated calls. **Must equal** the backend `SCANNER_TOKEN`. | see note | yes (for gated flows) | `NEXT_PUBLIC_*` is **inlined into the client bundle → publicly visible**. This is the existing design's accepted trade-off (a low-privilege SSRF gate, not a real secret); do not put a high-value secret here. |

## Persistence note (Gate 8.0b → Group 9)

Staging is **ephemeral**: the file stores under `dashboard/`
(`score_store.json`, `scan_store.json`, `leaderboard.json`, `reports/*.json`)
live on Railway's ephemeral filesystem and **reset on every redeploy**. Seeds
committed to the repo re-appear; runtime writes (new scans, leaderboard upserts)
are lost on redeploy. Acceptable for staging. **Group 9 (production) must add
durable persistence** — a Railway volume mounted at `dashboard/` or a managed DB.
