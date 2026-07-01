## ADDED Requirements

### Requirement: Contract-identical endpoint parity

The FastAPI service SHALL re-expose all 14 `/api/*` endpoints with responses that are identical to the current Flask app in HTTP status code, the `{ok, data?, error?}` envelope, and field names. No endpoint is complete until its response matches the live site for the same request.

#### Scenario: Endpoint response matches the live site
- **WHEN** the same request is sent to the current Flask `/api/*` endpoint and the new FastAPI endpoint
- **THEN** the status code, envelope shape, and field names are identical

#### Scenario: Error shapes preserved
- **WHEN** an invalid request hits a ported endpoint (e.g. non-JSON body, missing required field, unsupported input)
- **THEN** the service returns the same status code and the same error envelope as the current app (e.g. 415 / 422 / 400 / 404 with matching keys)

### Requirement: Reuse existing scoring and scanner logic

The service MUST import the existing `acpsec` package (`scorer`, `models`, `catalogue`, `onchain`) and the local `scanner.py` heuristic engine rather than reimplementing scoring or scanning. The internals of those modules MUST NOT be modified by this change.

#### Scenario: Scoring sourced from the package
- **WHEN** `/api/score`, `/api/score/manual`, or `/api/controls` is served
- **THEN** the result is produced by the imported `acpsec` scoring/catalogue logic, with the existing inline fallback when the package is unavailable

#### Scenario: Scanning delegates to scanner.py
- **WHEN** `/api/scanner/lookup`, `/api/scanner/scan`, or `/api/scanner/bulk` is served
- **THEN** the work is delegated to the existing `scanner.py` functions with no change to their behavior

### Requirement: Score store endpoints

The service SHALL provide `GET/POST/DELETE /api/score` and `POST /api/score/manual` preserving the acpsec/ASF auto-normalisation, the CRITICAL-penalty calculation, and the persisted score store.

#### Scenario: Auto-normalisation preserved
- **WHEN** a client POSTs either acpsec output (`{dimensions}`) or native ASF (`{controls}`) to `/api/score`
- **THEN** the service detects the format, normalises to the wire format, persists it, and returns `{ok: true, data}`

### Requirement: Scanner endpoints with preserved side-effects

The service SHALL provide `POST /api/scanner/lookup|scan|bulk`. `POST /api/scanner/scan` MUST keep its server-side write side-effects — persist the scan, upsert the leaderboard, and save the full report — and `bulk` MUST keep the ≤10-agents cap and inter-scan pacing.

#### Scenario: Scan persists and updates leaderboard
- **WHEN** `/api/scanner/scan` completes successfully
- **THEN** the scan is persisted, the agent is upserted into the leaderboard, and the full report is saved, as today

#### Scenario: Bulk cap enforced
- **WHEN** `/api/scanner/bulk` receives more than 10 usernames
- **THEN** the service rejects the request with the same 422 error as today

### Requirement: Leaderboard, report, onchain, chat, and health endpoints

The service SHALL provide `GET /api/leaderboard` (with movement/rank derivation), `GET /api/report/<id>` (including the 404 `report_not_found` shape), `POST /api/leaderboard/auth`, `POST /api/onchain/check` (via `acpsec.onchain`), `POST /api/chat/sentryagent` (Claude proxy with a server-side key), and `GET /api/health`.

#### Scenario: Health probe shape preserved
- **WHEN** `GET /api/health` is requested
- **THEN** the response is `{ok, service, acpsec_available, scanner_protected}` suitable for the Railway healthcheck

#### Scenario: Missing report falls back
- **WHEN** `GET /api/report/<id>` is requested for an agent with no stored report
- **THEN** the service returns 404 with `{ok: false, error: "report_not_found", message, scan_url}`

### Requirement: Server-side state ownership

The service MUST own the file/in-memory stores (score, scan, leaderboard, reports) so the frontend remains stateless. The frontend MUST NOT hold authoritative state.

#### Scenario: Frontend reads through the API
- **WHEN** the frontend needs score, scan, leaderboard, or report data
- **THEN** it obtains the data through the API and stores nothing authoritative locally

### Requirement: Production server replaces the dev server

The service MUST run under a production ASGI server, replacing the Werkzeug dev server used today.

#### Scenario: No dev server in production
- **WHEN** the backend is deployed
- **THEN** it serves the API via a production ASGI server rather than the Flask/Werkzeug development server
