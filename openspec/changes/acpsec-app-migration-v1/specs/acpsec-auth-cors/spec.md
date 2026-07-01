## ADDED Requirements

### Requirement: Server-side CORS for known frontend origins

The API MUST set explicit CORS headers permitting the known frontend origins (production `acpsec.app`, `staging.acpsec.app`, and Vercel preview URLs). The current app sets no CORS headers, which only works same-origin.

#### Scenario: Allowed origin permitted
- **WHEN** the Next.js frontend on an allowed origin calls the API
- **THEN** the API returns the appropriate CORS headers and the browser permits the response

#### Scenario: Unknown origin not permitted
- **WHEN** a request arrives from an origin not on the allowlist
- **THEN** the API does not grant cross-origin access to it

### Requirement: Scanner-endpoint token gating for split origin

Because a different-origin frontend does not satisfy the same-origin shortcut, the frontend MUST authenticate to the gated endpoints (`/api/scanner/lookup`, `/api/scanner/scan`, `/api/scanner/bulk`, `/api/onchain/check`) by sending a valid `X-Scanner-Token` header, and the API MUST accept that path.

#### Scenario: Gated call with token succeeds
- **WHEN** the frontend calls a gated scanner endpoint with a valid `X-Scanner-Token`
- **THEN** the API processes the request as authorized

#### Scenario: Gated call without token rejected
- **WHEN** a gated scanner endpoint is called from a non-allowed origin without a valid `X-Scanner-Token`
- **THEN** the API rejects it with 401, as the SSRF gate does today

### Requirement: Split-origin leaderboard session

The leaderboard session cookie (`lb_session`) MUST be issued so it survives a split-origin frontend — `SameSite=None; Secure` — and the frontend MUST send credentialed requests for leaderboard-gated calls.

#### Scenario: Session works cross-origin
- **WHEN** a user authenticates via `/api/leaderboard/auth` from the Vercel frontend and then makes a credentialed leaderboard request
- **THEN** the `lb_session` cookie is accepted and the session is recognized

### Requirement: Auth path documented and verified on staging

The chosen cross-origin strategy (true cross-origin vs. a Vercel `/api/*` proxy that restores same-origin) MUST be documented, and all four gated flows plus leaderboard login MUST be verified from the new frontend origin on staging before cutover.

#### Scenario: Gated flows verified before cutover
- **WHEN** staging is up
- **THEN** the scanner lookup/scan/bulk, onchain check, and leaderboard login flows are all confirmed working from the new frontend origin before any DNS cutover
