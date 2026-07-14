# Staging Smoke Test — 2026-07-11

**Result:** ✅ 16 passed / 0 failed

## Targets

- Frontend: https://staging.acpsec.app (Vercel, project `acp-sec-app`)
- Backend:  https://api-staging.acpsec.app (Railway, service `web-staging`)

## Fixture pair (from Group 7)

- Positive: `0xb20000000000000000000037670bd90fedb52901` (fixb20, Base Sepolia 84532)
- Negative: `0xb200faf3827258193fb18c24b43aa138c3dcc08c` (Clanker vanity, Base mainnet 8453)

## Assertions (16/16 PASS)

**Backend health**
- `/api/health` returns 200
- `ok: true`
- `scanner_protected: true`

**B20 scan positive (fixb20 @ Sepolia)**
- returns 200
- `rated: true`
- `grade: "A"` (matches on-chain fixb20)
- `deployed_via_factory` = canonical B20 factory `0xB20f...`

**B20 scan negative (Clanker vanity @ mainnet)**
- returns 400 (rejected)
- `error: "not_b20"` (prefix-spoof rejected)

**Frontend pages**
- GET `/` → 200
- GET `/b20` → 200
- GET `/leaderboard` → 200
- GET `/scanner` → 200
- `ACP-SEC` sentinel present in `/b20` HTML

**Scanner auth gate**
- Unauthenticated `/api/scanner/lookup` → 401
- Authenticated (via `X-Scanner-Token` header) → 422 (auth accepted; 422 = body validation, not auth failure)

## Script

`scripts/staging-smoke.sh` — reads `SCANNER_TOKEN` from env, never hardcoded.

Usage:
    SCANNER_TOKEN=<value> ./scripts/staging-smoke.sh

Auth check is skipped automatically if `SCANNER_TOKEN` is unset.

## Notes

- `NEXT_PUBLIC_API_URL` on Vercel points to `https://api-staging.acpsec.app`
  (custom domain, not the Railway-generated `web-staging-production-*.up.railway.app`).
- CORS allowlist on backend (from `af85238`) includes `https://staging.acpsec.app` by
  default — no `CORS_ALLOWED_ORIGINS` env var override needed for staging.
- Positive scan timeout raised from 30s → 90s in the script; B20 dimension checks
  do multiple Base Sepolia RPC calls and can exceed 30s on cold start via
  custom-domain routing.
