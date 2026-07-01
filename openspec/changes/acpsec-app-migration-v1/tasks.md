## 1. Pre-migration cleanup & investigation

- [ ] 1.1 Investigate the dirty working tree contents (modified: `CLAUDE.md`, `acpsec/cli.py`, `showcase/acp-sec/skills/acp-sec-scan/SKILL.md`, `showcase/acp-sec/soul.md`; untracked: `contracts/package-lock.json`, `scripts/acp-roundtrip.sh`, `scripts/find-entity-id.mjs`, `showcase/acp-sec/{README.md,examples/,showcase.json}`) and decide commit-vs-stash per item — do NOT migrate on top of an un-understood tree
- [ ] 1.2 Reconcile the Python version drift: deploy pins `python-3.11.9`, local venv is 3.14 — pin one version for the new FastAPI service across local + Railway
- [ ] 1.3 Confirm the migration branch base is clean and that Process B (`acpsec/acp_provider/`) and its active Phase 2 work are isolated from this change
- [ ] 1.4 Scaffold the FastAPI service (Preset 3, same stack as acp-sec-b20): package layout, deps, entry point, `/api/health` first
- [ ] 1.5 Scaffold the Next.js app (Preset 1/2): TypeScript, Tailwind, app router, deploy target Vercel

## 2. Backend — FastAPI port of the 14 `/api/*` endpoints (acpsec-api-service)

- [ ] 2.1 Build the per-endpoint parity harness: run the same request against live Flask and the new FastAPI, diff status + envelope `{ok,data?,error?}` + field names; no endpoint is "done" until it matches
- [ ] 2.2 Port the score store: `GET/POST/DELETE /api/score` + `POST /api/score/manual`, preserving `_auto_normalise` acpsec/ASF detection and CRITICAL-penalty math; reuse `acpsec.scorer`/`models`
- [ ] 2.3 Port `GET /api/controls` reusing `acpsec.catalogue.get_check_catalogue` with the inline 38-control fallback shape
- [ ] 2.4 Port the scanner endpoints `POST /api/scanner/lookup|scan|bulk` importing the local `scanner.py` as-is (no logic changes); preserve the `/scan` write side-effects (persist scan + leaderboard upsert + report save) and the ≤10 / 5s pacing on bulk
- [ ] 2.5 Port the leaderboard endpoints `GET /api/leaderboard` (movement/rank derivation) and `GET /api/report/<id>` (incl. the 404 `report_not_found` shape)
- [ ] 2.6 Port `POST /api/onchain/check` reusing `acpsec.onchain.check_acp_registration` and `BASE_RPC_URL`
- [ ] 2.7 Port `POST /api/chat/sentryagent` keeping the Anthropic key server-side (`ANTHROPIC_API_KEY`) and the fixed SentryAgent system prompt
- [ ] 2.8 Own the server-side stores (`score_store.json`, `scan_store.json`, `leaderboard.json`, `reports/*.json`) so the frontend stays stateless; confirm Railway-ephemeral behavior is unchanged
- [ ] 2.9 Replace the Werkzeug dev server with the production ASGI server; `/api/health` returns `{ok, service, acpsec_available, scanner_protected}` for the Railway healthcheck

## 3. Cross-origin auth / CORS (acpsec-auth-cors)

- [ ] 3.1 Add explicit server-side CORS for the known frontend origins (production `acpsec.app`, `staging.acpsec.app`, Vercel previews) — the current API sets no CORS headers
- [ ] 3.2 Gate the scanner endpoints (`/api/scanner/lookup|scan|bulk`, `/api/onchain/check`) on `X-Scanner-Token` for the split-origin frontend (the same-origin shortcut no longer fires from Vercel); frontend sends the token
- [ ] 3.3 Adapt the leaderboard session: issue `lb_session` with `SameSite=None; Secure` and make the frontend send credentialed requests so split-origin auth survives
- [ ] 3.4 Decide same-origin proxy (Vercel rewrite of `/api/*` → Railway) vs true cross-origin, and document which auth path is active (resolves Open Question)
- [ ] 3.5 Parity-test all four gated flows + the leaderboard login from the new frontend origin on staging

## 4. Frontend — design system + shell (acpsec-web-frontend)

- [ ] 4.1 Consolidate the contradictory inline tokens into ONE Tailwind theme (single source for `#0052FF`/`#00C087`/`#F5A623`, dark+light surfaces, `--ring-circ`), preserving the Coinbase-style palette
- [ ] 4.2 Build the shared shell: nav (`/ · /scanner · /leaderboard · /monitor · /agents/sentryagent`), footer, logo, social/GitHub links (fix the `apsecagent` typo → `acpsecagent`)
- [ ] 4.3 Build one typed API client wrapping the `{ok, data?, error?}` envelope + status codes, with `X-Scanner-Token` + credentialed-request support

## 5. Page ports — locked low-risk-first order (acpsec-web-frontend)

- [ ] 5.1 Legal pages first (lowest risk, 0 scripts, no API): `/privacy`, `/terms`, `/security` — proves scaffold + shell + design system end-to-end
- [ ] 5.2 Dashboard `/` (scoring editor) — consumes `/api/score*` + `/api/controls`
- [ ] 5.3 Leaderboard `/leaderboard` (+ `/leaderboard/login`) — consumes `/api/leaderboard`, `/api/report/<id>`, `/api/leaderboard/auth`
- [ ] 5.4 Monitor `/monitor` — watchlist + score history + drift alerts (chart.js → React charting)
- [ ] 5.5 Scanner `/scanner` (highest complexity, 1,880 lines) — the SSRF-gated scan flow consuming `/api/scanner/*`
- [ ] 5.6 SentryAgent info `/agents/sentryagent`
- [ ] 5.7 SentryAgent playground `/agents/sentryagent/playground` LAST — ethers.js wallet/contract flow against the hardcoded Base Sepolia contract `0x7770ED57E3993d4555951a557cd158a6Fb87A470`; consumes `/api/chat/sentryagent`

## 6. /b20 route integration (acpsec-web-frontend)

- [ ] 6.1 Port the existing acp-sec-b20 Next.js scaffold components (HolderView / DimensionBreakdown / RawJson / badges) into the new structure as the `/b20` route
- [ ] 6.2 Point `/b20` at the separate acp-sec-b20 backend (not this API); ship behind a feature flag if that backend is not yet deployed

## 7. Staging deploy + parity testing (acpsec-deploy-cutover)

- [ ] 7.1 Deploy the FastAPI backend to Railway (replacing the Werkzeug dev server) and the Next.js frontend to Vercel under `staging.acpsec.app`
- [ ] 7.2 Run the full parity suite on staging: all 10 pages render/behave at parity AND all 14 endpoints return contract-identical responses vs the live site
- [ ] 7.3 Verify Process B (ACP Provider) is neither redeployed nor interrupted by the staging stand-up

## 8. Zero-downtime cutover (acpsec-deploy-cutover)

- [ ] 8.1 DNS cutover: repoint `acpsec.app` to the new frontend/backend (alias/repoint, not in-place replace) for zero downtime; rollback = repoint DNS back
- [ ] 8.2 Post-cutover smoke: all 10 pages + 14 endpoints + 4 gated flows green on production `acpsec.app`
- [ ] 8.3 Confirm Process B still running and the `acp-sec-trust-score` offering unaffected; decommission the old Flask web process only after parity is confirmed
