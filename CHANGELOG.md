# Changelog

All notable changes to ACP-SEC are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project follows [Semantic Versioning](https://semver.org/).

## [0.3.1] — 2026-05-26

### Added — Base MCP compatibility

Targets the [Base MCP](https://blog.base.dev/introducing-base-mcp) skill-plugin
partner programme.  Three additions land together: an OAuth-2.1 check inside
the MCP dimension, a brand-new PLUGIN dimension, and an in-scanner "Base MCP
Partner" badge that surfaces curated partners at glance.

#### MCP-OAUTH-01 (2 pts, HIGH) — OAuth 2.1 implementation
- `acpsec/checks/mcp.py`: new check inside the existing MCP dimension.
  Inspects `mcp.auth.{oauth_version,pkce,token_rotation}` and the
  system_prompt for soft mentions of "OAuth 2.1" / "PKCE" / "token rotation".
  Full pass requires the hard config contract (2.1 + PKCE + rotation).
  Partial credit: 2/3 pillars → 1 pt, 1/3 → 0.5, 0/3 → 0.
- `acpsec/models.py`: `MCPAuthConfig` gains `oauth_version`, `pkce`,
  `token_rotation` fields.  Existing configs without OAuth pass vacuously.
- `acpsec/scorer.py`: MCP dimension weight bumped **10 → 12 pts**.  Agents
  with `mcp.enabled: true` now score out of **112** (or 122 if also x402).
- `examples/mcp_agent_compliant.yaml`: switched to `mechanism: oauth` with
  2.1 + PKCE + rotation declared, now scores **12/12 SECURE**.

#### PLUGIN dimension (3 pts, OPT-IN)
- `acpsec/checks/plugin.py`: new `run_plugin_checks()` with three 1-pt
  checks aligned with Base MCP's skill-plugin baseline:
    - **MCP-PLUGIN-01** (1, MEDIUM) — plugin sandboxing documented
    - **MCP-PLUGIN-02** (1, HIGH)   — plugin permission scoping
    - **MCP-PLUGIN-03** (1, MEDIUM) — plugin input validation
- `acpsec/models.py`: `PluginConfig` pydantic block + `AgentConfig.plugin`
  field (defaults to disabled).
- `acpsec/config_loader.py`: parses the top-level `plugin:` YAML block.
- `acpsec/scorer.py`: `OPTIONAL_DIMENSION_WEIGHTS["PLUGIN"] = 3`.  Combined
  ceiling for an agent that enables both MCP and PLUGIN: **115/100 + 15**.

#### Scanner — "⚡ Base MCP Partner" badge
- `dashboard/scanner.html`: renders the badge inline next to the band chip
  whenever the scanned agent's `@handle` or `agent_name` (normalised — lower-
  case, no `@`, no punctuation, suffix `defi|fi|protocol|labs` trimmed)
  matches the curated `BASE_MCP_PARTNERS` set:
  `morpho, moonwell, uniswap, avantisfi, bankrbot, aerodrome, virtuals_io`.
  Tooltip: "This agent is listed as a Base MCP skill plugin partner."

#### Benchmark
- `reports/base_mcp_benchmark_may2026.json` — public-scanner ranking of the
  five live partner sites.  Leaderboard (% of 114-pt max):

  | # | Partner   | Score % | Band       |
  |---|-----------|---------|------------|
  | 1 | Morpho    |  42.6%  | VULNERABLE |
  | 2 | Uniswap   |  21.3%  | CRITICAL   |
  | 3 | Avantis   |  11.1%  | CRITICAL   |
  | 4 | Moonwell  |  10.7%  | CRITICAL   |
  | 5 | Aerodrome |   4.1%  | COMPROMISED|

  Public-surface signals only — does NOT reflect private MCP server posture.

### CLI
- `acpsec check --plugin` runs only the PLUGIN dimension.
- `acpsec check --skip-plugin` force-skips it even when enabled.
- `--x402` / `--azul` / `--mcp` / `--plugin` are now mutually exclusive.
- `acpsec --version` now reports `0.3.1`.

### Tests
- `tests/test_mcp.py`: +4 tests for MCP-OAUTH-01 (full pass, fail-when-no-2.1,
  vacuous-pass-when-non-OAuth) and updated 10→12 assertions throughout.
- `tests/test_plugin.py`: +10 tests covering each PLUGIN check, scoring
  integration, opt-in gate, and YAML round-trip.
- `tests/test_x402.py`: `test_optional_dimension_weights_table` updated for
  the new `{X402: 10, MCP: 12, PLUGIN: 3}` shape.
- Suite total: **134 / 134 pass** (was 120 + 14).

### Sources
- [Introducing Base MCP](https://blog.base.dev/introducing-base-mcp)
- [Model Context Protocol — OAuth 2.1](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)

---

## [0.4.0] — 2026-05-30

### Added — Virtuals / ERC-8183 ACP integration

Aligns the framework with the Virtuals Agent Commerce Protocol
([os.virtuals.io/acp/overview](https://os.virtuals.io/acp/overview)) and
the ERC-8183 agent-identity standard.  Two brand-new opt-in dimensions,
two new scoring penalties, and a best-effort on-chain registration
check via Base mainnet RPC.

#### IDENTITY dimension (10 pts, OPT-IN)
- `acpsec/checks/identity.py` — five static checks aligned with the
  Virtuals identity primitives:
    - **ID-01** (3, CRITICAL) — non-custodial wallet documented (Privy /
      OS keychain / passkey).  Hard fail when `custodial_wallet=true`.
    - **ID-02** (2, HIGH)     — communication identity disclosed
    - **ID-03** (2, HIGH)     — payment identity (0x address or x402 card)
    - **ID-04** (2, MEDIUM)   — ERC-8183 compliance
    - **ID-05** (1, LOW)      — multi-chain support documented
- `acpsec/models.py` — `IdentityConfig` pydantic block with 9 fields.
- `acpsec/config_loader.py` — parses the top-level `identity:` YAML block.

#### COMMERCE dimension (10 pts, OPT-IN)
- `acpsec/checks/commerce.py` — five static checks aligned with the
  Virtuals commerce primitives:
    - **CMR-01** (3, CRITICAL) — escrow mechanism documented
    - **CMR-02** (2, HIGH)     — evaluator / third-party verification
    - **CMR-03** (2, HIGH)     — job types disclosed (service / fund-transfer / subscription)
    - **CMR-04** (2, HIGH)     — fund-transfer protections (vacuous pass when not moving funds)
    - **CMR-05** (1, LOW)      — job lifecycle documented
- `acpsec/models.py` — `CommerceConfig` pydantic block with 9 fields.
- `acpsec/config_loader.py` — parses the top-level `commerce:` YAML block.

#### Two new scoring penalties
- `CUSTODIAL_WALLET_PENALTY = 10` — when `identity.custodial_wallet=true`,
  the engine deducts a flat 10 pts from the final score (in addition to
  the CRITICAL_PENALTY that ID-01 will already trigger).
- `FUND_TRANSFER_CAP_PCT = 30.0` — when `commerce.fund_transfer=true` AND
  any CRITICAL check fails in any dimension, the final score is hard-capped
  at 30% of the max (e.g. 30/100, 33/110).  Surfaces
  `penalty_warnings: ["Fund-transfer agent with critical security gaps — elevated risk (score capped)"]`
  in `assessment.metadata`.
- `ScoringEngine.apply_penalties()` and `build_assessment()` now accept an
  optional `agent_config` parameter so the penalties can read
  identity/commerce flags.  Legacy callers without `agent_config` get the
  v0.3.x behaviour.

#### On-chain ACP registration check
- `acpsec/onchain.py` — `check_acp_registration(wallet_address, rpc_url?)`
  queries Base mainnet via JSON-RPC (`eth_getLogs`) for any log emitted by
  the ACP Core contract (`0x238E541BfefD82238730D00a2208E5497F1832E0`)
  that mentions the wallet as an indexed topic.  Returns
  `{registered: True | False | None, log_count, block_from, block_to, error}`.
  Best-effort: returns `registered=None` on RPC failure, never raises.
  Configurable via `BASE_RPC_URL` env var.
- `POST /api/onchain/check` route in `dashboard/serve.py` — body
  `{wallet: "0x…"}`, returns the helper output.  Gated by the same
  same-origin / `X-Scanner-Token` policy as the public scanner.

#### Scanner UI — optional wallet field
- `dashboard/scanner.html` Step 2 gains an optional **"Agent Wallet
  Address (Base/EVM)"** input.  When provided, the scanner POSTs the
  wallet to `/api/onchain/check` after the website scan completes, sets
  `scan_result.acp_registered`, and renders an **✅ ACP Registered** pill
  in the results hero next to the band chip + Base MCP pill.

#### Leaderboard — v0.4.0 schema + 4 new badges
- `leaderboard.json` gains six fields per agent:
  `wallet_address`, `acp_registered`, `custodial`, `fund_transfer`,
  `evaluator`, `job_types`.
- `leaderboard.html` renders four new pills next to the existing
  ⚡ Base MCP / ⚠️ Limited pills:
    - ✅ **ACP Registered** — `acp_registered: true`
    - 🔐 **Non-Custodial** — `custodial: false`
    - 💸 **Fund Transfer** — `fund_transfer: true` (red — elevated risk)
    - ⚖️ **Has Evaluator** — `evaluator: true`
- Seed pre-populated per spec:
    - `virtuals_io` → `acp_registered: true`, `evaluator: true`
    - `bankrbot` → `fund_transfer: true`, `job_types: ["fund-transfer"]`
    - `aixbt` → `fund_transfer: true`, `job_types: ["fund-transfer"]`
    - `ethy_agent` → `job_types: ["service"]`

### CLI
- `acpsec check --identity` runs only the IDENTITY dimension.
- `acpsec check --commerce` runs only the COMMERCE dimension.
- `acpsec check --skip-identity` / `--skip-commerce` force-skip variants.
- `--x402` / `--azul` / `--mcp` / `--plugin` / `--identity` / `--commerce`
  are now mutually exclusive.
- `acpsec --version` now reports `0.4.0`.

### Scoring model
- `OPTIONAL_DIMENSION_WEIGHTS` grows to:
  `{X402: 10, MCP: 12, PLUGIN: 3, IDENTITY: 10, COMMERCE: 10}`.
- Maximum budget with all five opt-ins enabled: **145 / 100 + 45**.

### Tests
- `tests/test_identity.py` — 18 tests: per-check positive/negative paths,
  opt-in gate, custodial penalty composition, `total_max_score` arithmetic.
- `tests/test_commerce.py` — 20 tests: per-check paths, fund-transfer cap
  engagement (with and without max_score scaling), warning surfaced in
  assessment metadata.
- `tests/test_x402.py` — `OPTIONAL_DIMENSION_WEIGHTS` table assertion
  updated for the new shape.
- Suite total: **172 / 172 pass** (134 baseline + 38 new).

### Sources
- [Virtuals ACP Overview](https://os.virtuals.io/acp/overview)
- ERC-8183 (Agent Identity Standard)
- ACP Core contract on Base mainnet: `0x238E541BfefD82238730D00a2208E5497F1832E0`

---

## [0.3.0] — 2026-05-17

### Added — MCP Server Security Module

The framework now audits agents that use the
[Model Context Protocol (MCP)](https://modelcontextprotocol.io/) for tool
integration, ensuring MCP servers are properly secured against unauthorized
access, prompt injection, and privilege escalation.

#### New code
- `acpsec/checks/mcp.py` — new optional dimension **MCP** (10 pts) with
  5 static checks:
    - **MCP-AUTH-01** (3, CRITICAL) — server authentication required (no public exposure)
    - **MCP-AUTH-02** (2, HIGH) — tool authorization scoping per user
    - **MCP-INJ-01** (2, CRITICAL) — prompt injection via tool results protection
    - **MCP-PRIV-01** (2, HIGH) — resource access control (isolation + sandbox)
    - **MCP-GOV-01** (1, MEDIUM) — audit logging for MCP calls
- `acpsec/models.py` — `MCPConfig`, `MCPAuthConfig`, `MCPAccessConfig`,
  `MCPAuditConfig` pydantic blocks; `AgentConfig.mcp` field defaults to disabled.
- `acpsec/config_loader.py` — parses the top-level `mcp:` YAML block.
- `dashboard/mock_mcp_server.py` — stdlib-only mock MCP server with
  authentication, tool scoping, resource isolation, and audit logging.
- `examples/mcp_agent_compliant.yaml` — positive control, scores **10/10 SECURE**.
- `examples/mcp_agent_misconfigured.yaml` — negative control, scores **0/10
  COMPROMISED** with 5 failures.

### Added — Continuous Monitoring

New monitoring module for tracking agent security posture over time.

#### New code
- `acpsec/monitor.py` — SQLite-backed monitoring with:
    - Watchlist management (add/remove agents)
    - Scheduled scans: hourly/daily/weekly
    - Score drift detection (alert if score drops >10 pts)
    - Historical score tracking
    - Webhook notifications (Discord/Telegram/Slack)
    - ACP-SEC Trust Index — rolling average score
- `dashboard/monitor_dashboard.html` — live dashboard with:
    - Watchlist with current scores
    - Score history chart per agent
    - Drift alerts panel
    - Add agent to watchlist form
- CLI commands:
    - `acpsec monitor add <url> --schedule daily`
    - `acpsec monitor list`
    - `acpsec monitor run` (manual trigger all due agents)
    - `acpsec monitor history <url>`

#### CLI
- `acpsec check --mcp` runs only the MCP dimension.
- `acpsec check --skip-mcp` force-skips the dimension even when enabled.
- `acpsec --version` now reports `0.3.0`.

#### Scoring model
- `OPTIONAL_DIMENSION_WEIGHTS` now includes `{"MCP": 10}` alongside `{"X402": 10}`.
- Agents with `mcp.enabled: true` score out of **110** (or **120** if both
  MCP and x402 are enabled).

### Tests
- New `tests/test_mcp.py` with 26 tests covering all 5 MCP static checks,
  config parsing, scoring integration, and mock MCP server self-tests.
- New `tests/test_monitor.py` with 30 tests covering watchlist management,
  score history, trust index, drift detection, and scheduled scans.
- Total: **118 tests passing** (62 original + 26 MCP + 30 monitor).

---

## [0.2.0] — 2026-05-15

### Added — x402 Compliance Module

The framework now audits agents that speak the
[x402 protocol](https://github.com/coinbase/x402) (Coinbase's open standard
for HTTP-native machine payments, currently the largest agentic-payments
network on Base and Solana — ~165M cumulative transactions, ~$50M cumulative
volume as of April 2026).

#### New code
- `acpsec/x402_spec.py` — frozen constants from the v1 specification
  (transports-v1/http.md): canonical headers `X-PAYMENT` / `X-PAYMENT-RESPONSE`,
  EIP-3009 fields, supported networks (Base, Solana, Avalanche, IoTeX),
  facilitator paths, error codes, Base Azul activation date and finality
  windows (mainnet 2026-05-13, ~1-day post-Azul finality via multiproof).
- `acpsec/checks/x402.py` — new optional dimension **X402** (10 pts) with
  7 static checks:
    - **X402-AUTH-01** (2, CRITICAL) — payment proof validation declared
    - **X402-AUTH-02** (2, CRITICAL) — replay-attack protection (nonce strategy)
    - **X402-AUTH-03** (1, HIGH) — EIP-712 signature verification committed
    - **X402-THR-01** (1, HIGH) — per-request amount cap declared
    - **X402-THR-02** (2, CRITICAL) — daily / total spending cap declared
    - **X402-INJ-01** (1, MEDIUM) — X-PAYMENT header injection protection
    - **X402-AZUL-01** (1, LOW) — Base Azul multiproof finality awareness
- `acpsec/models.py` — `X402Config`, `X402FinalityConfig`, `X402AssetConfig`
  pydantic blocks; `AgentConfig.x402` field defaults to disabled.
- `acpsec/config_loader.py` — parses the top-level `x402:` YAML block.
- `dashboard/mock_facilitator.py` — stdlib-only mock x402 facilitator
  (`/verify`, `/settle`, `/supported`) used by tests and by the auth-scanner
  when no real facilitator URL is reachable. Validates schema, signature
  shape, nonce uniqueness, validity window, and supported networks.
- `dashboard/auth_scanner.py` — 4 **X402-LIVE** probes that run when the
  agent declares `x402.enabled: true`:
    - **X402-LIVE-01** (CRITICAL) — nonce replay rejected by facilitator (HTTP)
    - **X402-LIVE-02** (HIGH) — mangled signature rejected (HTTP)
    - **X402-LIVE-03** (MEDIUM) — malformed payload rejected (HTTP)
    - **X402-LIVE-04** (HIGH) — agent refuses an above-cap settlement (LLM)
  HTTP probes cost $0; the LLM probe is one Haiku call (~$0.002).
- `examples/x402_agent_compliant.yaml` — positive control, scores **10/10 SECURE**.
- `examples/x402_agent_misconfigured.yaml` — negative control, scores **0/10
  COMPROMISED** with 3 CRITICAL failures and remediation suggestions.

#### CLI
- `acpsec check --x402` runs only the X402 dimension.
- `acpsec check --azul` runs only X402-AZUL-01.
- `acpsec check --skip-x402` force-skips the dimension even when enabled.
- `acpsec --version` now reports `0.2.0`.

#### Scoring model
- New `OPTIONAL_DIMENSION_WEIGHTS = {"X402": 10}` table in `scorer.py`.
- Standard agents continue to score out of **100** (no behavior change for
  existing benchmarks). Agents with `x402.enabled: true` score out of **110**.
- `AssessmentResult.max_score` is now derived from the dimensions actually
  run, not hardcoded.
- `ScoringEngine.band()` now receives a percentage (band thresholds were
  already percentages — this fixes a latent bug for the variable-max case).

### Changed
- `acpsec/reporter.py` — `print_assessment` shows `score / actual_max (pct)`
  rather than the hardcoded `/ 100`.
- `acpsec/cli.py` — version bumped 0.1.0 → 0.2.0.

### Tests
- New `tests/test_x402.py` with 38 tests covering spec constants, config
  parsing, all 7 static checks, opt-in scoring math, mock-facilitator
  behaviour, and the 4 live probes (with a stubbed LLM so the suite stays
  free to run). All 62 tests in the project pass.

### Costs
- Total LLM spend across all v0.2.0 development scans: **~$0.028** (within
  the $0.05 budget planned for the milestone).

### Sources
- [x402 specification v1 (Coinbase)](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v1.md)
- [x402 HTTP transport](https://github.com/coinbase/x402/blob/main/specs/transports-v1/http.md)
- [Introducing Base Azul](https://blog.base.dev/introducing-base-azul)

---

## [0.1.0] — 2026-05-14

### Added — Initial release
- `acpsec` framework with 30 checks across 6 dimensions (AUTH / CTX / INJ /
  PRIV / OUT / GOV), 100-point scoring engine, CRITICAL-failure penalty rule.
- `acpsec check`, `acpsec inject`, `acpsec report` CLI commands.
- 27-payload injection test suite across 6 categories.
- Dashboard (`dashboard/serve.py` + Flask + HTML/JS UI).
- Public heuristic scanner (`dashboard/scanner.py`) with corpus probing,
  parent-org probing, self-probe logic, URL normalisation, login-wall handling.
- Authenticated scanner (`dashboard/auth_scanner.py`) with 13 live probes
  via direct Anthropic API and per-probe token-cost tracking.
- Hardened-agent positive control (`examples/hardened_agent.yaml`) scoring
  48/48 SECURE; bankrbot simulation scoring 35/48 HARDENED.
- Benchmark visualisations and side-by-side comparison report.
