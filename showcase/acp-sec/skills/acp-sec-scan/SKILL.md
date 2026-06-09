---
name: acp-sec-scan
description: Run an acp-sec Trust Score scan on an on-chain ACP agent contract and interpret the result.
version: 0.1.0
---

# acp-sec Trust Score Scan

Use this skill to assess whether an on-chain agent contract is safe to transact
with, by computing an acp-sec **Trust Score** (0-100, grade A-F) across six
security dimensions. Works standalone (CLI) or as the executor behind the
acp-sec ACP Provider.

## Inputs

- A target contract address (`0x...`) on Base.
- Chain: `base-sepolia` (default) or `base-mainnet`.
- Scan mode: `external` (public/on-chain data only) or `self_audit` (operator
  may supply private data such as Agent Card spend limits).
- A `BASESCAN_API_KEY` (Etherscan V2 unified key) for contract source/ABI.

## Workflow

1. Confirm the input is a public contract address, never a private key.
2. Run the scan:
   ```bash
   acpsec trust-score --agent 0x... --chain base-sepolia --scan-mode external --output scan.json
   ```
   Or, as the ACP Provider bridge:
   ```bash
   python -m acpsec.acp_provider "scan 0x..." --chain base-sepolia
   ```
3. Read the result: `score`, `grade`, `critical`, the six `subscores`,
   `top_findings` (sorted by severity), and any `unrated_checks`.
4. Interpret against the grade bands: 90+ SECURE, 70-89 HARDENED, 50-69
   VULNERABLE, 30-49 CRITICAL, 0-29 COMPROMISED. Treat a `critical: true` result
   as a hard stop regardless of the numeric score.
5. Note Unrated dimensions: missing data is reported as Unrated and lowers the
   confidence multiplier; do not read it as "safe".

## Output

Return the Trust Score JSON (or the ACP deliverable wrapping it), including the
score, grade, subscores, top findings, the list of Unrated checks, the scanner
version, and the UTC scan timestamp so a reviewer can reproduce and audit it.

## Boundaries / stop conditions

- Read-only: never sign, transfer, or mutate the assessed contract.
- Never log, print, or include private keys, session keys, wallet material, or
  API keys in any output or proof artifact.
- If contract source is unverified or data is unavailable, report it (Unrated)
  rather than guessing.
- A Trust Score is a point-in-time assessment, not a guarantee or financial
  advice.
