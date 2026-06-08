# ACP-SEC Trust Score — Scoring Spec v2

Composite security rating (0-100, grade A-F) for autonomous on-chain agents in
the ACP / agent economy. v2 aligns the framework with **ACP v3.0**: the canonical
job lifecycle, Alchemy Modular Account V2 signer scoping, the official ACP Core
fee-split enforcement, and a reachability-aware Unrated model.

## Model

- Each dimension starts at 100, penalties subtract, floor at 0.
- Composite = weighted sum of the **rated** dimension scores.
- CRITICAL CAP: any single CRITICAL finding caps the composite at 39 (grade F),
  regardless of the weighted sum. CRITICAL findings carry no per-dimension
  penalty of their own — they act through the cap.
- Coverage / Unrated is two-tier:
  - **Dimension-level Unrated** — a whole dimension's data is unavailable
    (adapter failure). The dimension is excluded from the weighted sum and the
    overall result is published as Unrated (multiplier 0.50), never a passing
    grade. New agents start Unrated.
  - **Check-level Unrated** — an individual sub-check is not reachable in the
    current scan. It is recorded in that dimension's `unrated_checks` and
    contributes **zero penalty**. Unreachable data is never assumed to a default
    and never penalized.

```
composite_raw = sum(dim_score[i] * weight[i] for i in rated_dimensions)
composite     = 39 if any_critical_finding else round(composite_raw)
```

### Reachability and scan modes

Each check is classified by where its evidence lives:

- **ON-CHAIN / PUBLIC** — scoreable in any scan (bytecode, verified source,
  Slither output, registry reads, Transfer history, settlement routing).
- **PRIVATE / SELF-AUDIT-ONLY** — only available to the operator (Agent Card
  spend limits, off-chain signer policy). Unreachable in an external scan → Unrated.

Scan modes (CLI `--scan-mode`):

- `external` (default) — public/on-chain data only. Private checks are left
  Unrated rather than penalized. Signer mode is still attempted as a conditional
  on-chain read, with Unrated fallback.
- `self_audit` — operator-run scan that may supply private data (Agent Card spend
  limits, off-chain-enforced signer policy) to score otherwise-Unrated checks.

### Chain scope

Base only — no BSC. CLI `--chain` selects the network and its reference contracts:

| Chain         | id    | Default |
|---------------|-------|---------|
| base-mainnet  | 8453  |         |
| base-sepolia  | 84532 | yes     |

Reference contracts (Base Mainnet ground-truth; used by the settlement-route and
hook checks). Testnet reference addresses are not yet recorded.

- ACP Core (Job contract): `0x238E541BfefD82238730D00a2208E5497F1832E0`
- FundTransferHook:        `0x90717828D78731313CB350D6a58b0f91668Ea702`

## Weights

1. Contract Security — 0.25
2. Authority Scope & Key Management — 0.20
3. Identity & Attribution — 0.15
4. HOOK Security — 0.15
5. ACP v3 Compliance — 0.15
6. Behavioral & Wash-Resistance — 0.10

## Grade bands & trust multiplier

```
90-100 → A → multiplier 1.00
75-89  → B → multiplier 0.85
60-74  → C → multiplier 0.60
40-59  → D → multiplier 0.30
0-39   → F → multiplier 0.10
Unrated    → multiplier 0.50 (capped)
```

```
risk_adjusted_aGDP = aGDP * multiplier
```

## Dimension 1 — Contract Security (25%)

Data: verified source (Basescan API), bytecode, Slither static analysis.

CRITICAL (caps composite to 39):
- Source code unverified
- Arbitrary external call / delegatecall to caller-supplied address
- Unbounded or hidden mint authority

High penalties:
- Reentrancy: external call before state update, no nonReentrant → -30
- Missing access control on privileged fn → -25
- Upgradeable proxy, admin = single EOA → -20

Medium penalties:
- selfdestruct present → -15
- tx.origin used for auth → -15
- Unchecked low-level call return → -10
- Floating / pre-0.8 pragma without SafeMath → -10

## Dimension 2 — Authority Scope & Key Management (20%)

Data: ABI, on-chain owner reads, Alchemy Modular Account V2 session-key
allowlist, Agent Card (Virtuals) for spend limits.

CRITICAL:
- Agent can move arbitrary user funds without per-tx consent

High:
- Withdrawal gated by single EOA owner → -20 (multisig owner → -5; MPC/threshold → 0)
- **Signer key in Unrestricted mode** → -25
  - Conditional on-chain read of the MA v2 allowlist: scoped to ACP targets only
    → Restricted (0); open or reaching beyond ACP → Unrestricted (-25);
    EOA / allowlist unreadable → **Unrated**.
- No on-chain spending budget / per-period cap → -25

Medium:
- **Agent Card declares no per-transaction or per-period spend limit** → -15
  - Genuinely private: **Unrated in external mode**; scoreable in self_audit.
- Infinite token approvals requested → -15
- No timelock on privileged ops → -10
- No pause / emergency-stop → -10

Low:
- No key rotation path documented → -5

## Dimension 3 — Identity & Attribution (15%)

Data: ERC-8004 Identity/Reputation registry, Agent Card, endpoint TLS.

CRITICAL:
- Agent card owner mismatch vs on-chain identity

High:
- No ERC-8004 identity registered → -30
- Claimed handle unverified → -20

Medium:
- Endpoint TLS mismatch → -10
- Reputation Registry inconsistent → -10
- Sybil signals (fresh wallet) → -10

## Dimension 4 — HOOK Security (15%)

Scored against the ACP v3 `beforeAction` / `afterAction` callback model (and the
Uniswap v4-style before/after swap & liquidity hooks). Data: Slither findings +
on-chain owner check.

CRITICAL:
- **Hook can divert escrow / principal funds during a beforeAction/afterAction
  callback** (`hook_diverts_escrow`)
- Unauthorized caller can invoke beforeAction/afterAction callbacks

`hook_diverts_escrow` corroboration guardrail — because a CRITICAL caps the whole
composite to F, a single raw Slither signal is never mapped straight to it.
CRITICAL only when a dangerous primitive (`arbitrary-send-eth` /
`controlled-delegatecall`) is reachable from a hook callback path **and** touches
fund-moving / escrow / principal logic. A benign library `delegatecall` is
downgraded to High (-25); an indeterminate signal is **Unrated**. Bias: prefer
under-flagging CRITICAL over a false-positive F.

High:
- Hook permissions over-scoped (callback can move funds) → -25
- Hook reentrancy during callback into pool/settlement → -20

Medium:
- Hook callback can block or censor settlement → -15
- Dynamic fee manipulation in hook callback → -15
- Hook upgradeable by EOA → -15

## Dimension 5 — ACP v3 Compliance (15%)

Scored against the canonical ACP v3 job lifecycle (the conformance ground-truth):

```
open -> budget_set -> funded -> submitted -> completed
branches: funded / submitted -> rejected   (escrow returns to Client)
          any non-terminal   -> expired     (permissionless timeout -> Client)
settlement: completed -> Provider, rejected -> Client, expired -> Client
gating:     complete is Evaluator-gated and reachable only from submitted
```

CRITICAL:
- Escrow funds drainable outside the completed settlement path
- Agent can self-settle, bypassing the Evaluator-gated submitted phase

High:
- Missing ACP v3 lifecycle phase (per phase) → -15 each
- No reject path returning escrow to the Client on a rejected job → -20
- **Fee split non-conformant** → -20 (tri-state; default **Unrated**)

Medium:
- No expiry / timeout to release escrow on a stalled job → -15
- Settlement not atomic → -15
- Non-conformant job struct / missing events → -10

### Fee-split conformance (settlement routing)

The 95/5 (no Evaluator) and 90/5/5 (with Evaluator) split is enforced by the
**official ACP Core Job contract, not by the agent**. Conformance is therefore a
settlement-routing question, resolved by `SettlementRouteResolver`:

- Settles via the official ACP Core (address match, or Core referenced in source)
  → conformant **by construction**, not flagged.
- Custom / forked settlement contract → analyse the split; flag High -20 if it is
  not 95/5 or 90/5/5.
- Settlement path undeterminable → **Unrated** (e.g. external scan on a chain with
  no recorded ACP Core reference).

## Dimension 6 — Behavioral & Wash-Resistance (10%)

Data: on-chain Transfer history; off-chain job records where available.

- Historical fund-loss / exploit incident → -40
- Dispute rate: penalty = min(40, rate*200)
- Failed-delivery rate: penalty = min(30, rate*150)
- Low counterparty diversity (HHI > 0.5): HHI = sum((jobs_with_cp / total_jobs)^2) → up to -25
- Volume spike from few wallets → -15

## Output JSON schema

Each `subscores` entry is an object carrying the dimension score and the list of
sub-checks that ended up Unrated in this scan, so downstream consumers can see
exactly what was and was not verifiable.

```json
{
  "agent": "0x...",
  "erc8004_id": "...",
  "score": 52,
  "grade": "D",
  "multiplier": 0.30,
  "critical": false,
  "subscores": {
    "contract_security": {"score": 60, "unrated_checks": []},
    "authority_scope":   {"score": 45, "unrated_checks": ["signer_unrestricted", "agent_card_no_spend_limit"]},
    "identity":          {"score": 80, "unrated_checks": []},
    "hook_security":     {"score": 70, "unrated_checks": []},
    "acp_compliance":    {"score": 55, "unrated_checks": ["fee_split_nonconformant"]},
    "behavioral":        {"score": 65, "unrated_checks": []}
  },
  "top_findings": [
    {"dim": "authority_scope", "severity": "High", "detail": "withdrawal gated by single EOA owner"},
    {"dim": "acp_compliance", "severity": "High", "detail": "no reject path returning escrow to the Client on a rejected job"}
  ],
  "scanned_at": "2026-06-08T00:00:00Z",
  "scanner_version": "acpsec-v0.5.0",
  "rated": true
}
```

## CLI

```
acpsec trust-score --agent 0x... \
    [--chain base-sepolia|base-mainnet] \
    [--scan-mode external|self_audit] \
    [--no-slither] \
    [--output report.json]
```
