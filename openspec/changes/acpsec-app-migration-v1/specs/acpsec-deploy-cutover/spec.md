## ADDED Requirements

### Requirement: Split frontend/backend hosting

The migrated app SHALL deploy the Next.js frontend to Vercel and the FastAPI backend to Railway. The backend MUST keep the editable `acpsec` install and serve the API; the frontend MUST be UI-only.

#### Scenario: Hosts as specified
- **WHEN** the migration deploys
- **THEN** the Next.js frontend runs on Vercel and the FastAPI backend runs on Railway

### Requirement: Staging-first rollout

The migration MUST stand up the full frontend + backend on `staging.acpsec.app` and pass parity verification there before any production cutover.

#### Scenario: Staging stood up before cutover
- **WHEN** the new stack is ready
- **THEN** it is deployed to `staging.acpsec.app` and exercised before `acpsec.app` is repointed

### Requirement: Parity verification gate

Before cutover, parity MUST be verified: all 10 pages render and behave at parity with the live site, and all 14 API endpoints return contract-identical responses (status + envelope + fields).

#### Scenario: Cutover gated on parity
- **WHEN** parity verification has not fully passed on staging
- **THEN** the production DNS cutover does not proceed

### Requirement: Zero-downtime DNS cutover with rollback

The cutover MUST repoint `acpsec.app` to the new stack via DNS (an alias/repoint, not an in-place replacement) so there is no downtime, and rollback MUST be a simple DNS repoint back to the old stack.

#### Scenario: Cutover is a DNS repoint
- **WHEN** parity passes and cutover proceeds
- **THEN** `acpsec.app` is repointed to the new frontend/backend with no downtime, and the old Flask process is decommissioned only after production parity is confirmed

#### Scenario: Rollback by repointing DNS
- **WHEN** a problem is found post-cutover
- **THEN** the team can roll back by repointing DNS to the old stack

### Requirement: ACP Provider (Process B) untouched

The migration MUST NOT redeploy, interrupt, or modify the ACP Provider (Process B, `acpsec/acp_provider/`) or its `acp-sec-trust-score` offering at any point.

#### Scenario: Provider unaffected through cutover
- **WHEN** the staging stand-up and the production cutover happen
- **THEN** Process B continues running unchanged and the offering is unaffected
