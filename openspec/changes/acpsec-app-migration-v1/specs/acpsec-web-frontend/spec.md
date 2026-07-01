## ADDED Requirements

### Requirement: Next.js app replaces the inline-styled pages

The frontend SHALL be a Next.js + TypeScript + Tailwind application that replaces the 10 standalone inline-styled HTML pages, consuming the API via a single typed client. No page may retain a per-page inline `<style>`/`<script>` design.

#### Scenario: Page rendered by the Next.js app
- **WHEN** a migrated route is requested
- **THEN** it is served by the Next.js app using shared components and the consolidated theme, not a standalone inline-styled HTML file

### Requirement: Single consolidated design system

The frontend MUST consolidate the contradictory inline design tokens into one Tailwind theme that is the single source of truth for the palette, while preserving the existing Coinbase-style look (blue `#0052FF`, green `#00C087`, amber `#F5A623`, dark and light surfaces).

#### Scenario: One token source
- **WHEN** a component needs the brand blue
- **THEN** it references the single themed token rather than one of the old contradictory aliases (`--blue`/`--accent-base`/`--accent-info`/`--accent-purple`)

### Requirement: Page parity for all 10 pages

The frontend SHALL port all 10 pages at behavioral parity with the current site: `/privacy`, `/terms`, `/security`, `/` (dashboard), `/leaderboard`, `/leaderboard/login`, `/monitor`, `/scanner`, `/agents/sentryagent`, `/agents/sentryagent/playground`.

#### Scenario: A migrated page behaves at parity
- **WHEN** a user exercises a migrated page's primary flow
- **THEN** it behaves the same as the current acpsec.app page for that flow

### Requirement: Risk-ascending port order

The pages SHALL be ported in the locked order legal → dashboard → leaderboard → monitor → scanner → playground, so the lowest-risk static pages prove the scaffold and the highest-risk wallet flow ships last.

#### Scenario: Legal pages prove the scaffold first
- **WHEN** the migration begins porting pages
- **THEN** the static legal pages (privacy/terms/security) are completed before any API-driven page

#### Scenario: Playground ported last
- **WHEN** pages are ported
- **THEN** the SentryAgent playground (ethers.js wallet/contract flow) is the final page ported

### Requirement: Stateless frontend

The frontend MUST be stateless with respect to scoring, scan, leaderboard, and report data — all such state is read from and written to the API.

#### Scenario: No authoritative client state
- **WHEN** the frontend displays scan or leaderboard data
- **THEN** it has fetched that data from the API and holds no authoritative copy

### Requirement: /b20 route

The frontend SHALL add a `/b20` route by porting the existing acp-sec-b20 Next.js scaffold components, pointing at the separate acp-sec-b20 backend (not this API). If that backend is not yet deployed, the route MAY ship behind a feature flag.

#### Scenario: /b20 calls the b20 backend
- **WHEN** a user opens `/b20` and runs a token scan
- **THEN** the page calls the acp-sec-b20 backend (not the acpsec.app API) and renders the b20 progressive-disclosure result
