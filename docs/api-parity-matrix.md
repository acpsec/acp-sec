# API Parity Matrix — FastAPI port (Group 2)

Tracks how the FastAPI backend (`acpsec_api/`) matches the legacy Flask reference
(`dashboard/serve.py`) for all 14 `/api` endpoints, plus the documented
intentional deviations, mock-only limitations, and the environment-variable
surface. This is the completion artifact for **Group 2 (Task 2.9)**.

Parity is validated two ways (see `tests/api/conftest.py::assert_parity`):
1. Direct contract assertions against the FastAPI app.
2. Byte-for-byte parity against the Flask handler, wherever externally reachable.

## Parity categories

- **byte-identical** — `assert_parity` (or an equivalent side-by-side assertion)
  proves both apps emit identical status + JSON.
- **intentional-deviation** — FastAPI diverges on purpose; documented in code and
  test comments. A crash is not a contract, and a split-origin cookie is not a
  regression.
- **mock-only success** — the success path calls a live external service (Nitter,
  the heuristic engine's network fetches, Base RPC, the Claude API) that cannot be
  driven from the Flask oracle. Success is asserted FastAPI-only with a mock; the
  **denial/error** path is still byte-identical against Flask.
- **empty-state-only** — Flask's on-disk store is not externally seedable, so
  parity is asserted for the empty state; populated behaviour is FastAPI-only.

## The 14 endpoints

| # | Endpoint | Method | Test file | Parity status | Notes |
|---|----------|--------|-----------|---------------|-------|
| 1 | `/api/health` | GET | `test_health.py` | **byte-identical** | `assert_parity` |
| 2 | `/api/score` | GET | `test_score_read.py`, `test_score_write.py` | **byte-identical** | Empty state via `assert_parity` (skipped if the real store is populated); populated state proven in `test_post_parity_with_flask` (POST→GET on both apps). |
| 3 | `/api/score` | POST | `test_score_write.py` | **byte-identical** | Full real-state parity in `test_post_parity_with_flask` (creates + cleans up real store on both apps). |
| 4 | `/api/score/manual` | POST | `test_score_write.py` | **byte-identical** | Full real-state parity, same test. |
| 5 | `/api/score` | DELETE | `test_score_write.py`, `test_score_read.py` | **byte-identical (static)** | Both handlers unconditionally return `{"ok": true}`. Exercised on **both** apps in the write-parity cleanup; FastAPI response contract-asserted in `test_delete_score`. |
| 6 | `/api/controls` | GET | `test_score_read.py` | **byte-identical** | Stateless → `assert_parity`. |
| 7 | `/api/leaderboard` | GET | `test_leaderboard.py` | **intentional-deviation** | Fix-forward: Flask raises `TypeError` (`None > None`) on the seeded SentryAgent null-score entry and **500s**; FastAPI coerces null score→0. Parity against the real seeded file is impossible (Flask crashes); populated behaviour is FastAPI-only (`test_leaderboard_null_scores_handled`). |
| 8 | `/api/leaderboard/auth` | POST | `test_leaderboard.py` | **byte-identical body + intentional-deviation (cookie)** | Wrong-password 401 is byte-identical (`test_auth_wrong_parity`). Correct-password JSON body + stable cookie fields match Flask; the `SameSite`/`Secure` flags **diverge by design** (Task 2.8: `SameSite=None; Secure` vs Flask `SameSite=Lax`; not-Secure) for the split-origin deployment. |
| 9 | `/api/report/{agent_id}` | GET | `test_leaderboard.py` | **byte-identical** | Found + not-found both via `assert_parity`. |
| 10 | `/api/scanner/lookup` | POST | `test_scanner_lookup.py` | **denial byte-identical + mock-only success** | 401 gate denial via `assert_parity`; success mocks the scraper (live Nitter, no suite network). |
| 11 | `/api/scanner/scan` | POST | `test_scanner_scan.py` | **denial byte-identical + mock-only success** | Denial via `assert_parity`; success mocks the heuristic engine (2,380-line network scanner). |
| 12 | `/api/scanner/bulk` | POST | `test_scanner_bulk.py` | **denial byte-identical + mock-only success** | Denial via `assert_parity`; success mocks the engine. |
| 13 | `/api/onchain/check` | POST | `test_onchain.py` | **denial byte-identical + mock-only success** | Denial via `assert_parity`; success needs a live Base-mainnet RPC call, mocked in the suite. Live shape-parity was verified by hand during Task 2.6. |
| 14 | `/api/chat/sentryagent` | POST | `test_chat.py` | **error byte-identical + mock-only success** | Missing-key 503 + empty-messages 422 via `assert_parity`; success mocks the Anthropic client (live Claude API costs $, deliberately never called in the suite). |

**No true gaps.** Every endpoint carries parity coverage appropriate to its
constraints. The `mock-only`, `empty-state-only`, and `intentional-deviation`
categories are unavoidable (live external service, non-seedable Flask store, or a
deliberate fix), not omissions.

## Intentional deviations (the full list)

1. **`GET /api/leaderboard` null-score fix-forward** — Flask 500s on the seeded
   null-score agent; FastAPI coerces null→0 and returns a sorted board. A crash
   is not a contract. (`acpsec_api/routers/leaderboard.py`,
   `test_leaderboard_null_scores_handled`.)
2. **`lb_session` cookie flags (Task 2.8)** — production default is
   `SameSite=None; Secure` so the cookie rides cross-origin (Vercel frontend →
   Railway API). Flask keeps `SameSite=Lax`; not-Secure. Env-overridable for local
   dev via `ACPSEC_COOKIE_SAMESITE` / `ACPSEC_COOKIE_SECURE`.
   (`acpsec_api/sessions.py`, `test_auth_correct_parity`, `test_cookie_*`.)

## Cross-endpoint consistency notes

- **Error envelope shape** is intentionally mixed to match Flask **per endpoint**:
  some errors are `{"ok": false, "error": ...}` (onchain, chat, leaderboard-auth),
  others are bare `{"error": ...}` (scanner, score). This mirrors Flask exactly —
  it is parity, not drift, and must not be "normalised" (that would create a new
  parity break).
- **Content type** — every handler returns `application/json` (FastAPI dict →
  `JSONResponse`, and explicit `JSONResponse` for non-200s). The scanner/onchain
  gate denial renders as Flask's flat `{"ok": false, "error": ...}` via
  `scanner_access_denied_handler`, not FastAPI's default `{"detail": ...}`.
- **HTTP methods** — all 14 FastAPI routes match the Flask method set exactly
  (verified: `GET`/`POST`/`DELETE` line up 1:1).

## Environment-variable reference

| Variable | Consumed by | Default | Purpose |
|----------|-------------|---------|---------|
| `SCANNER_TOKEN` | scanner + onchain gate (`scanner_auth.py`) | unset = **open** (dev) | SSRF gate: allow same-origin browser requests or a matching `X-Scanner-Token` header. |
| `LEADERBOARD_PASSWORD` | `/api/leaderboard/auth` | unset = **open** | Password for the leaderboard session cookie. |
| `ANTHROPIC_API_KEY` | `/api/chat/sentryagent` (`get_anthropic_client`) | unset → 503 | Server-side Claude key; never sent by the client. |
| `BASE_RPC_URL` | `/api/onchain/check` | unset → `mainnet.base.org` default | Optional Base RPC endpoint override. |
| `CORS_ALLOWED_ORIGINS` | CORS middleware (`main.py`) | built-in static list | Comma-separated allowlist override (staging/prod lock-down). |
| `CORS_ALLOWED_ORIGIN_REGEX` | CORS middleware | Vercel-preview regex | Override the preview-deploy origin regex. |
| `ACPSEC_COOKIE_SAMESITE` | `lb_session` cookie (`sessions.py`) | `none` | Local-dev override (`lax` for plain-http localhost). |
| `ACPSEC_COOKIE_SECURE` | `lb_session` cookie | `true` | Local-dev override (`false` for plain-http localhost). |

Static CORS allowlist default: `https://acpsec.app`, `http://localhost:3000`,
`http://127.0.0.1:3000`, plus the Vercel-preview regex
`https://acpsec-web-[a-z0-9-]+\.vercel\.app`. Credentialed CORS never uses `*`.

## Cutover checklist (reminder — executed in later groups)

- [ ] **Relocate `dashboard/scanner.py`** (Group 9). `get_scanner_engine()` currently
      imports `from dashboard import scanner` (approved exception, Task 2.5b-i). Move
      the engine into a shared package so FastAPI has **no** `dashboard/` import.
- [ ] **Decommission `dashboard/serve.py`** once the frontend cuts over to the
      FastAPI backend. Until then it remains the parity oracle for the test suite.
- [ ] **Production env** must set `SCANNER_TOKEN`, `LEADERBOARD_PASSWORD`,
      `ANTHROPIC_API_KEY`, and serve over **HTTPS** (`SameSite=None` requires
      `Secure`); set `CORS_ALLOWED_ORIGINS` to the real frontend origin(s).
