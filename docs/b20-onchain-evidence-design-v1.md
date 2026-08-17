# B20 On-Chain Evidence — Design v1 (Phase 1)

> Attach verifiable on-chain evidence to scan findings. **Claims must be re-runnable,
> not asserted.** Branch `feat/b20-onchain-evidence` off `main` (`26f2dcb`).

## Principle: evidence has KINDS (never fabricate a tx for a state read)

- **`event`** — from logs we already fetch: `{kind:"event", tx_hash, block_number, log_index}`.
  Used for role grants/revokes and announcements.
- **`state`** — from an `eth_call` at a block: `{kind:"state", block_number, raw_value, confirmed}`.
  Anyone can re-run the call at `block_number` and get `raw_value`. `confirmed` carries a
  boolean cross-check (e.g. `hasRole`); `raw_value` carries the read.
- What we **couldn't read** stays in `read_diagnostics` (already shipped, #32) — evidence never
  papers over an unread value.

`supply_cap` / `decimals` / `can_freeze` / `factory_is_official` **have no tx by nature** — their
honest evidence is value-at-block, never a fabricated transaction.

## Additive schema — a new top-level `evidence` block (like `read_diagnostics`, #32)

`ScanResult.to_dict()` gains **one** key, `evidence`. Nothing existing changes.

```jsonc
"evidence": {
  "as_of_block": 49875432,                     // one eth_blockNumber anchor for all state reads
  "roles": {                                   // per role name -> current holders, each with evidence
    "DEFAULT_ADMIN_ROLE": [
      { "address": "0x38…72b1",
        "grant":  {"kind":"event","tx_hash":"0x…","block_number":49145,"log_index":3},
        "revoke": null,                        // set only if the holder was later revoked (audit trail)
        "has_role": {"kind":"state","block_number":49875432,"raw_value":null,"confirmed":true},
        "discrepancy": false }                 // true iff replay says held but hasRole()==false
    ],
    "MINT_ROLE": [ … ], "PAUSE_ROLE": [ … ], "SEIZE_ROLE": [ … ], …
  },
  "announcements": [ {"kind":"event","tx_hash":"0x…","block_number":…,"log_index":…}, … ],
  "state": {                                   // value-at-block for state-derived facts
    "supply_cap":            {"kind":"state","block_number":…,"raw_value":"340282…","confirmed":null},
    "decimals":              {"kind":"state", …, "raw_value":"8"},
    "variant":               {"kind":"state", …, "raw_value":"ASSET"},   // address-decoded; block-anchored
    "factory_is_official":   {"kind":"state", …, "raw_value":"true"},
    "can_freeze":            {"kind":"state", …, "raw_value":"<policyId(SENDER)>"},
    "policy_registry_active":{"kind":"state", …, "raw_value":"<policyId(SENDER)>"},
    "multiplier":            {"kind":"state", …, "raw_value":"<multiplier() raw>"}
  }
}
```

**Findings** also gain an additive `evidence` key: a state-derived finding (uncapped-supply High,
rebasing-multiplier, PolicyRegistry-active, freeze) carries the `state` evidence it turns on
(`Finding.to_dict()` gains `"evidence": null | <state-evidence>`). Event-derived role facts live
in `evidence.roles`, not on findings.

## New models (`models.py`, additive)
`EventEvidence{tx_hash,block_number,log_index}` · `StateEvidence{block_number,raw_value,confirmed}` ·
`RoleHolderEvidence{address,grant,revoke,has_role,discrepancy}` · `ScanEvidence{as_of_block,roles,announcements,state}`.
`Finding` gains `evidence: Optional[StateEvidence]`. `ScanResult` gains `evidence: ScanEvidence`.
`ScanInputs` gains (defaulted) `as_of_block`, `role_evidence`, `announcement_evidence`, `state_evidence`.

## Reader plumbing (the data is already in hand — we just stop discarding it)
1. **`role_holders_all`** → keep `(holders, first_grantee)` **and add** per-address event evidence
   `{addr: {grant:(tx,block,logIndex), revoke:(…)}}` (3-tuple; existing `[0]/[1]` indexing unchanged).
   The log objects already carry `transactionHash`/`blockNumber`/`logIndex` — reader sorts on the
   latter two today and drops the tx.
2. **Announcements** (`read_origin`) → retain `tx/block/logIndex` for each announcement log.
3. **State evidence** → anchor one `eth_blockNumber` (reuse the `as_of_block` pattern from
   `preflight.py`); attach `{kind:state, block, raw_value}` for the seven state facts. `read_supply`
   returns the raw `multiplier()`; `read_transfer_policy` returns the raw `policyId(SENDER)` so
   `raw_value` is the actual read, not a re-derivation.
4. **NEW `hasRole` cross-check** — for each replay-derived current holder, `hasRole(role, holder)`
   (`0x91d14854`) → `{kind:state, confirmed, block}`. Upgrades "we saw a grant event" to "grant
   seen **and** the chain confirms it still holds". Live-verified on
   `0xb2000000000000000000002d0ba3164cc74f58b7`:
   `hasRole(DEFAULT_ADMIN, 0x38467be00970af18076fd08f6b4cf38ba91572b1) == true`.
   **If `hasRole`==false while replay says held → `discrepancy:true`** on the holder **and** a loud
   `read_diagnostics["role_hasRole_discrepancy"]` entry. We never silently prefer one source.

## Invariants (non-negotiable)
- **#34 tri-state intact.** A failed evidence read is `unknown` (fields `null`), **never** the
  absence of a finding or a changed holder set. Evidence is added to whatever we already concluded.
- **Evidence never changes a verdict/score.** It only *explains* the finding. `assess()` scoring
  inputs are untouched; the `evidence` block is assembled alongside, read-only.
- **Additive.** Only new keys; `test_models.py` / `test_engine_assess.py` key-set contracts get the
  new keys added, never a removal.

## Phase 2 — PROPOSE ONLY (do not build here)
**Mint-history evidence**: "mint exercised, first at block B, tx …". Requires extra `getLogs` across
**full history** + archive state — it does not fit the creation-block-bounded single-query budget and
would blow the public-RPC range caps. It belongs behind a **flag or its own endpoint**, not the
default scan. Proof it's real (same token `0xb2…f58b7`): created @49145218 with supply 0; first mints
@49875001 (0.1) and @49879432 (1.1) via `Transfer` from `0x0`; supply now 294.9138 @ 8 decimals
against a `2^128-1` cap. Deferred: the getLogs cost + archive dependency is the real work, and it is
out of scope for Phase 1.
