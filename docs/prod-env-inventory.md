# Production environment inventory — `acpsec.app` / `api.acpsec.app`

> **Names and purposes only — never values.** Secret values are entered by
> Fadhlan directly into Railway/Vercel (CLI prompt or dashboard) during 9B.
> This file is committed; it must never carry a secret.

Scope: the **FastAPI backend** (`api-prod` Railway service, `main` branch,
config `railway.prod.json`, domain `api.acpsec.app`) and the **Next.js
frontend** (Vercel, prod domain `acpsec.app`).

Cutover strategy: **blue-green.** The legacy Flask `web` service keeps serving
`acpsec.app` until the new stack is validated; the DNS flip is the last step and
rollback is one CNAME change. Until the flip, the new frontend is reachable on a
Vercel prod URL / temporary hostname, and the backend on `api.acpsec.app`.

Mirrors `staging-env-inventory.md`. Two prod-specific differences are called out
below: **persistence must be durable** (not ephemeral) and **secrets are fresh
prod values**, rotated in 9B — do **not** reuse the staging token/password.

## Backend — Railway `api-prod`

| Variable | Purpose | Secret? | Required for prod? | Notes |
|---|---|---|---|---|
| `PORT` | Port uvicorn binds (`--port $PORT`). | no | yes | Injected by Railway automatically — do **not** set by hand. |
| `SCANNER_TOKEN` | Shared token gating the SSRF-sensitive endpoints (`/api/scanner/lookup\|scan\|bulk`, `/api/onchain/check`). Unset ⟹ endpoints run open (dev mode). | **yes** | yes | **Rotate a fresh prod value in 9B** — not the staging token. Split-origin: the frontend sends it as `X-Scanner-Token`. **Must equal** the frontend's `NEXT_PUBLIC_SCANNER_TOKEN`. |
| `LEADERBOARD_PASSWORD` | Password checked by `POST /api/leaderboard/auth` before issuing the `lb_session` cookie. | **yes** | yes | **Rotate a fresh prod value in 9B.** Needed for leaderboard login. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated exact origin allowlist (overrides the built-in default). | no | optional | Default already includes `https://acpsec.app` and localhost — leave unset unless locking further (e.g. dropping localhost for prod hardening). |
| `CORS_ALLOWED_ORIGIN_REGEX` | Regex allowing Vercel preview origins (overrides the default `acpsec-web-<hash>.vercel.app` pattern). | no | optional | Default matches acpsec-web preview URLs. Consider clearing on prod to reject preview origins. |
| `ACPSEC_COOKIE_SAMESITE` | `SameSite` attribute for `lb_session`. | no | optional | Default `none` — correct for split-origin (`acpsec.app` ↔ `api.acpsec.app`). Leave unset. |
| `ACPSEC_COOKIE_SECURE` | `Secure` flag for `lb_session`. | no | optional | Default `true` — correct over HTTPS. Leave unset. |
| `BASE_RPC_URL` | Optional RPC override for `POST /api/onchain/check` only. | no (public endpoint) | optional | Staging leaves this unset (public Base endpoint, gate 8.0c). Affects **only** `/api/onchain/check` — the b20 scan engine has its own per-chain vars (below). |
| `B20_RPC_URL_8453` | Per-chain RPC endpoint for the **b20 scan engine** on Base **mainnet** (8453). Unset ⟹ the hardcoded public endpoint. | **yes** — provider URLs embed API keys | optional | **Recommended for prod (#24):** a dedicated provider removes the public-endpoint rate-limiting that made mainnet scans pessimistically unrate. Zero-config = today's public endpoint; setting this is the activation step. |
| `B20_RPC_URL_84532` | Per-chain RPC endpoint for the b20 scan engine on Base **Sepolia** (84532). Unset ⟹ the hardcoded public endpoint. | **yes** — provider URLs embed API keys | optional | Same as `B20_RPC_URL_8453`, for testnet. |

**Minimal prod set to enter by hand (9B):** `SCANNER_TOKEN`,
`LEADERBOARD_PASSWORD` (both secret, fresh prod values).
Everything else uses correct built-in defaults.

`ANTHROPIC_API_KEY` is **no longer a prod requirement** — it powered only the
SentryAgent chat endpoint, removed in the teardown. Any value still set on
api-prod is a leftover and can be removed (revoke the key in the Anthropic
console). NOTE: the same var name is still read by `acpsec/agent_client.py` (the
CLI injection framework), which is not the prod api.

## Frontend — Vercel (prod)

| Variable | Purpose | Secret? | Required? | Notes |
|---|---|---|---|---|
| `NEXT_PUBLIC_API_URL` | Base URL of the FastAPI backend, baked into the bundle at build time. | no | yes | Split-origin: set to `https://api.acpsec.app`. A missing value silently falls back to `http://localhost:8001`. |
| `NEXT_PUBLIC_SCANNER_TOKEN` | Token the browser sends as `X-Scanner-Token` on gated calls. **Must equal** the backend `SCANNER_TOKEN`. | see note | yes (for gated flows) | `NEXT_PUBLIC_*` is **inlined into the client bundle → publicly visible**. A low-privilege SSRF gate, not a real secret; do not put a high-value secret here. Rotate together with the backend `SCANNER_TOKEN` in 9B. |

## Persistence note (Gate 8.0b → 9B) ⚠️ prod differs from staging

Staging is **ephemeral** — the file stores under `dashboard/`
(`score_store.json`, `scan_store.json`, `leaderboard.json`, `reports/*.json`)
live on Railway's ephemeral filesystem and reset on every redeploy. Committed
seeds re-appear; runtime writes (new scans, leaderboard upserts) are lost.

**This is not acceptable for prod.** The live prod dashboard's history
(the committed `dashboard/leaderboard.json` + 25 `dashboard/reports/*.json`
seeds) survives redeploys precisely because it is **committed to the repo** — so
the cutover itself needs **no data migration**. But any *runtime* writes after
cutover (new user scans, leaderboard changes) would be wiped by the next
redeploy unless persistence is made durable.

**9B infra action (not in this task):** mount a **Railway volume** at
`dashboard/` on the `api-prod` service so runtime writes survive redeploys
(or move the stores to a managed DB). Nothing in 9A provisions this.
