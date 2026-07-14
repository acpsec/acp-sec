#!/usr/bin/env bash
#
# staging-smoke.sh — end-to-end smoke test for acp-sec staging.
#
# Verifies the full split-origin stack over the public custom domains:
#   frontend  https://staging.acpsec.app       (Vercel / Next.js)
#   backend   https://api-staging.acpsec.app   (Railway / FastAPI)
#
# Uses the real-world B20 fixture pair validated during Group 7:
#   positive  fixb20   (Base Sepolia 84532)  -> expect 200 + rated
#   negative  Clanker  (Base mainnet 8453)   -> expect 400 + not_b20
#
# Secrets: SCANNER_TOKEN is read from the environment, never hardcoded.
#   Run:  SCANNER_TOKEN=xxxx ./scripts/staging-smoke.sh
#   (leaderboard-login check is skipped automatically if the token is unset)
#
# Exit code 0 = all required checks passed; non-zero = at least one failed.

set -uo pipefail

FRONTEND="${FRONTEND_URL:-https://staging.acpsec.app}"
BACKEND="${BACKEND_URL:-https://api-staging.acpsec.app}"

FIXB20_ADDR="0xb20000000000000000000037670bd90fedb52901"   # Base Sepolia, real B20
FIXB20_CHAIN=84532
CLANKER_ADDR="0xb200faf3827258193fb18c24b43aa138c3dcc08c"  # Base mainnet, vanity-prefix non-B20
CLANKER_CHAIN=8453

pass=0; fail=0
green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }
ok()    { green "  PASS  $1"; pass=$((pass+1)); }
ko()    { red   "  FAIL  $1"; fail=$((fail+1)); }
head()  { printf '\n\033[1m%s\033[0m\n' "$1"; }

# GET body + status. curl failures (DNS/TLS/timeout) surface as status 000.
# usage: http_get <url>  -> sets $BODY and $CODE
http_get() {
  local resp; resp=$(curl -sS -m 20 -w $'\n%{http_code}' "$1" 2>/dev/null)
  CODE="${resp##*$'\n'}"; BODY="${resp%$'\n'*}"
}
# POST JSON. usage: http_post <url> <json>  -> sets $BODY and $CODE
# Timeout 90s: b20 scans do 5 RPC calls to Base Sepolia (~20-40s cold, longer via custom domain)
http_post() {
  local resp; resp=$(curl -sS -m 90 -X POST "$1" \
    -H 'Content-Type: application/json' -d "$2" -w $'\n%{http_code}' 2>/dev/null)
  CODE="${resp##*$'\n'}"; BODY="${resp%$'\n'*}"
}

echo "staging smoke test"
echo "  frontend: $FRONTEND"
echo "  backend:  $BACKEND"

# ---- 1. backend health -----------------------------------------------------
head "1. Backend health ($BACKEND/api/health)"
http_get "$BACKEND/api/health"
if [ "$CODE" = "200" ]; then
  ok "health returns 200"
else
  ko "health returned $CODE (expected 200)"; echo "       body: $BODY"
fi
case "$BODY" in
  *'"ok":true'*)             ok 'health ok:true' ;;
  *)                         ko 'health missing ok:true' ;;
esac
case "$BODY" in
  *'"scanner_protected":true'*)  ok 'scanner protection active' ;;
  *'"scanner_protected":false'*) ko 'scanner_protected is false (SCANNER_TOKEN not applied on backend)' ;;
  *)                             ko 'scanner_protected field absent' ;;
esac

# ---- 2. b20 positive (fixb20, Sepolia) ------------------------------------
head "2. B20 scan positive — fixb20 @ Base Sepolia"
http_post "$BACKEND/api/b20/scan" \
  "{\"address\":\"$FIXB20_ADDR\",\"chain_id\":$FIXB20_CHAIN}"
if [ "$CODE" = "200" ]; then
  ok "scan returns 200"
else
  ko "scan returned $CODE (expected 200)"; echo "       body: $BODY"
fi
case "$BODY" in
  *'"rated":true'*)  ok 'result is rated' ;;
  *)                 ko 'result not rated' ;;
esac
# grade is ground-truth for this token; score is NOT asserted (engine may evolve)
case "$BODY" in
  *'"grade":"A"'*)   ok 'grade A (matches on-chain fixb20)' ;;
  *)                 ko 'grade != A' ;;
esac
case "$BODY" in
  *'0xB20f000000000000000000000000000000000000'*) ok 'deployed_via_factory = canonical B20 factory' ;;
  *)                                              ko 'factory address mismatch' ;;
esac

# ---- 3. b20 negative (Clanker vanity, mainnet) ----------------------------
head "3. B20 scan negative — Clanker vanity @ Base mainnet"
http_post "$BACKEND/api/b20/scan" \
  "{\"address\":\"$CLANKER_ADDR\",\"chain_id\":$CLANKER_CHAIN}"
if [ "$CODE" = "400" ]; then
  ok "scan returns 400 (rejected)"
else
  ko "scan returned $CODE (expected 400)"; echo "       body: $BODY"
fi
case "$BODY" in
  *'"error":"not_b20"'*) ok 'error = not_b20 (prefix spoof rejected)' ;;
  *)                     ko 'expected not_b20 error body' ;;
esac

# ---- 4. frontend pages -----------------------------------------------------
head "4. Frontend pages ($FRONTEND)"
for path in "/" "/b20" "/leaderboard" "/scanner"; do
  http_get "$FRONTEND$path"
  if [ "$CODE" = "200" ]; then ok "GET $path -> 200"; else ko "GET $path -> $CODE"; fi
done
# sentinel: the app shell should render its brand name
http_get "$FRONTEND/b20"
case "$BODY" in
  *ACP-SEC*)  ok 'frontend shell renders (ACP-SEC present)' ;;
  *)          ko 'ACP-SEC sentinel not found in /b20 HTML' ;;
esac

# ---- 5. scanner auth gate (optional; needs SCANNER_TOKEN) ------------------
head "5. Scanner auth gate"
if [ -z "${SCANNER_TOKEN:-}" ]; then
  echo "  SKIP  SCANNER_TOKEN not set — export it to run this check"
else
  # Backend uses X-Scanner-Token header (confirmed from serve.py _require_scanner_token).
  # Use /api/scanner/lookup (read-only, lightweight) instead of /scan so we don't
  # incur a full scan on every smoke run.

  # without token -> must be rejected
  http_post "$BACKEND/api/scanner/lookup" '{"handle":"claudeai"}'
  case "$CODE" in
    401|403) ok "unauthenticated scanner call rejected ($CODE)" ;;
    *)       ko "unauthenticated scanner call returned $CODE (expected 401/403)" ;;
  esac
  # with token via X-Scanner-Token header -> must NOT be an auth error
  resp=$(curl -sS -m 30 -X POST "$BACKEND/api/scanner/lookup" \
    -H 'Content-Type: application/json' \
    -H "X-Scanner-Token: $SCANNER_TOKEN" \
    -d '{"handle":"claudeai"}' -w $'\n%{http_code}' 2>/dev/null)
  acode="${resp##*$'\n'}"
  case "$acode" in
    401|403) ko "authenticated scanner call still $acode (token not accepted — check SCANNER_TOKEN value matches Railway)" ;;
    000)     ko "authenticated scanner call failed to connect" ;;
    *)       ok "authenticated scanner call accepted ($acode)" ;;
  esac
fi

# ---- summary ---------------------------------------------------------------
head "Summary"
green "  $pass passed"
[ "$fail" -gt 0 ] && red "  $fail failed" || echo "  0 failed"
echo
if [ "$fail" -gt 0 ]; then
  echo "RESULT: FAIL"
  exit 1
else
  echo "RESULT: PASS"
  exit 0
fi
