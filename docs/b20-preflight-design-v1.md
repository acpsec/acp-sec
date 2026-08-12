# B20 Preflight API — Design v1 (Task 01 scaffold)

> **Status: design + RED-tests checkpoint. No implementation yet — stop for review.**
> Branch `fix/b20-preflight-scaffold` off `main` (`69cc630`, post-#38/#39).
> Grounded in the verified Cobalt surface (memory `b20-cobalt-surface`) and a live
> investigation of the `base/base-std` mocks (`/tmp/cobalt-data/base-std`, forge/anvil 1.5.1).

## 1. Purpose & scope

`POST /api/b20/preflight` answers **"will this transfer clear, and if not, why?"** for
`(token, chain_id, from, to, amount)` — a **point-in-time** authorization verdict against
current chain state, tiered by our scanner's honesty vocabulary.

**In scope (this task):** ordinary `transfer(to, amount)` (and the `transferFrom` executor
scope is noted but v1 evaluates the plain-transfer path). **Out of scope (later):** mint /
burn / seize preflight (`MINT_RECEIVER_POLICY`, `SEIZE_HOLDER_POLICY`, `SEIZE_RECEIVER_POLICY`).

**Point-in-time, not a guarantee.** A verdict is state at block *N*; a policy update / pause /
balance move before submission can invalidate it. `as_of_block` makes the staleness explicit.

## 2. Endpoint contract

**Request** (`PreflightRequest`): `{ "token": str, "chain_id": int, "from": str, "to": str, "amount": str }`
- `from` is a Python keyword → Pydantic field `from_addr` with `alias="from"`.
- `amount` is a **decimal string** (uint256 can exceed JS safe-int) → parsed to `int`.
- Validation (mirrors `/api/b20/scan`): 400 `invalid_address` (token/from/to not `0x`+40hex),
  400 `unsupported_chain` (not 8453/84532), 400 `invalid_amount` (not a non-negative int).

**Response** (`PreflightVerdict.to_dict()`), 200 for every *reachable* outcome:
```jsonc
{
  "verdict": "allow" | "deny" | "unavailable",
  "reasons": [ { "code": str, "detail": str, "scope": str|null, "policy_id": int|null } ],
  "as_of_block": int | null,          // eth_blockNumber at read time; staleness anchor
  "evidence_tier": "verified" | "unknown",
  "deny_class": "policy" | "state" | "balance" | null   // deny only; null otherwise
}
```
- `allow`/`deny` → `evidence_tier: "verified"` (every load-bearing read succeeded at block *N*).
- `unavailable` → `evidence_tier: "unknown"` (gate off, or a read failed — **never a false allow**).
- **`deny_class`** discriminates *structural power* from *transient condition* for the integrator:
  `policy` (isAuthorized false — "this address is blocked, contact the issuer") vs `state` (paused —
  transient) vs `balance` (insufficient — "top up"). `null` for allow/unavailable. Same `reasons[]` shape.
- 503 `rpc_unreachable` only for total unreachability / RPC construction failure (as in `/scan`).

## 3. Verdict algorithm — mirrors the mock's revert order

The evaluation order **must** match `MockB20Asset.transfer`'s revert order so the verdict
agrees with an `eth_call` simulation (§6). Verified order (base-std
`test/lib/mocks/MockB20.sol` + `transfer_revertOrder.t.sol`):
`ContractPaused(TRANSFER)` → sender `PolicyForbids` → receiver `PolicyForbids` → `InsufficientBalance`.

| # | Step | Read (all via `RpcClient`, non-raising → `None` on failure) | Outcome |
|---|------|------------------------------------------------------------|---------|
| 0 | **Activation gate FIRST** | `supportsInterface(0xa60bf13d)` on **token** | `None`→`unavailable`(read_failed) · `false`→`unavailable`(not_cobalt) · `true`→proceed |
| 1 | Block anchor | `eth_blockNumber()` | record `as_of_block` (may be `null`) |
| 2 | Pause | `isPaused(TRANSFER=0)` on token (`0xbc61e733`) | `None`→`unavailable` · `true`→`deny`(paused) |
| 3 | Sender policy | `policyId(TRANSFER_SENDER_POLICY)` then, if `≠0`, `isAuthorized(pid, from)` on **PolicyRegistry `0x8453…0002`** (`0x55a1179e`) | any read `None`→`unavailable` · `false`→`deny`(policy_forbids, sender) |
| 4 | Receiver policy | `policyId(TRANSFER_RECEIVER_POLICY)` then, if `≠0`, `isAuthorized(pid, to)` | `None`→`unavailable` · `false`→`deny`(policy_forbids, receiver) |
| 5 | Balance | `balanceOf(from)` (`0x70a08231`) | `None`→`unavailable` · `< amount`→`deny`(insufficient_balance) |
| 6 | Clear | — | `allow` |

**Do NOT reimplement composite policy logic** — `isAuthorized` is the exposed evaluator that
resolves BLOCKLIST/ALLOWLIST/UNION/INTERSECT internally (`policyId == 0` = always-allow,
short-circuited without a call). "Freeze/blocklist state" = `isAuthorized(policyId(SENDER), from) == false`;
there is no separate freeze getter. **Balance is included** specifically so the verdict agrees
with the full transfer simulation (a zero-balance `from` reverts `InsufficientBalance`).

## 4. Reason codes

| code | verdict | fields |
|------|---------|--------|
| `not_cobalt` | unavailable | detail: "Cobalt surface not active on this chain" |
| `read_failed` | unavailable | detail names the read (e.g. "isAuthorized(sender) read failed") |
| `paused` | deny (`deny_class: state`) | scope: "TRANSFER" |
| `policy_forbids` | deny (`deny_class: policy`) | scope: TRANSFER_SENDER_POLICY \| TRANSFER_RECEIVER_POLICY; policy_id: uint64 |
| `insufficient_balance` | deny (`deny_class: balance`) | detail: "balance {b} < amount {a}" |
| (allow → `reasons: []`) | allow | `deny_class: null` |

## 5. Module layout (to build in implementation — NOT yet created)

- `acpsec_api/b20/preflight.py` — `preflight(token, chain_id, from_addr, to_addr, amount, *, rpc=None) → PreflightVerdict`; pure over an injected `rpc`. Reuses `reader.py` helpers (`calldata`, `word`, `enc_address`, `enc_uint`, `_decode_bool`, `_decode_uint`) + `constants`.
- `acpsec_api/b20/models.py` — add `PreflightRequest`, `PreflightVerdict` (+ `Reason`), `to_dict()`.
- `acpsec_api/routers/b20.py` — add `POST /api/b20/preflight` with injection seams `get_preflight_fn` + `get_rpc_factory` (same pattern as `/scan`), sync `def` (RPC-bound → threadpool).
- `acpsec_api/b20/constants.py` — add: `B20_SELECTOR_SUPPORTS_INTERFACE = "0x01ffc9a7"`, `B20_IFACE_ERC8056 = "0xa60bf13d"`, `B20_SELECTOR_IS_AUTHORIZED = "0x55a1179e"`, `B20_SELECTOR_BALANCE_OF = "0x70a08231"` (`POLICY_REGISTRY` already pinned). `supportsInterface`'s `bytes4` arg is **left-aligned** (`a60bf13d` + 56 zeros), not `enc_uint`.

## 6. Self-checking oracle (§4/§5 of the task) — anvil + base-std mocks

**Premise:** predicted verdict ⇔ actual `eth_call` simulation of `transfer()`. If they disagree,
one is lying. Validated feasibility (from the mock investigation):
- `MockPolicyRegistry` + `MockB20Asset` are **anvil-deployable standalone** (`MockB20Factory`
  needs forge cheatcodes → avoided; deploy via `anvil_setCode` + init via `anvil_setStorageAt`).
- `MockB20Asset.supportsInterface(0xa60bf13d) → true` (Cobalt-active fixture); base `MockB20`
  omits it → the **pre-Cobalt negative** fixture.
- Blocklist recipe: `createPolicy(admin, BLOCKLIST=0)` → id `2`; `updateBlocklist(2, true, [from])`;
  `token.updatePolicy(TRANSFER_SENDER_POLICY, 2)`. Then a blocked `transfer` reverts
  `PolicyForbids(0xa43fec12)` while `isAuthorized(2, from) == false`.

**Oracle test:** boot anvil, deploy+configure the mocks, then for each of {clear, blocked-sender,
blocked-receiver, paused, insufficient-balance}: assert `preflight(...).verdict` **equals** the
`eth_call transfer(to, amount){from}` outcome (`allow` ⇔ call succeeds; `deny` ⇔ reverts). The
transfer simulation needs an `eth_call` **with `from`** — `RpcClient.eth_call` has no `from`
param, so the oracle harness issues a raw `eth_call` (harness-only; production preflight never
simulates the transfer, only reads).

## 7. Test plan (RED now; see the three test files)

- **`tests/b20/test_preflight.py`** — unit guards over the shared `FakeRpc` (no network). RED now
  (imports the absent `preflight` module). Covers: pre-Cobalt short-circuit; clear→allow;
  blocked sender/receiver deny **naming the scope + policy_id**; pause precedence; balance-after-policy
  order; **read-failure→unavailable (never allow)**; gate-read-failure→unavailable; response shape +
  evidence_tier mapping.
- **`tests/api/test_b20_preflight.py`** — endpoint: openapi exposure, address/chain validation,
  and a verdict body via the `get_preflight_fn` seam. RED now (route + seam absent → 404).
- **`tests/b20/test_preflight_oracle.py`** — the anvil + base-std-mock oracle (§6), marked
  `@pytest.mark.oracle`. **`importorskip`-guarded**: it *skips* cleanly today (preflight absent)
  and **activates in implementation**. CI fast lane runs `-m "not oracle"`.

## 8. Decisions flagged for review (no silent scope reduction)

1. **Balance is in v1** (not just policy/pause) — required for the oracle to agree with a real
   `transfer` simulation. If you want auth-only (ignore balance), the oracle must simulate
   `isAuthorized`-only, not `transfer`.
2. **Oracle harness deferred to implementation** — the recipe is validated (mocks deploy, forge
   builds, selectors confirmed) but the anvil fixture is *stood up during GREEN*, not at this
   checkpoint. The oracle test is written + marked + skips today. Say the word if you want the
   full anvil harness stood up now instead.
3. **Gate is per-token** (`supportsInterface` is ERC-165 on the token), surfaced as the
   chain-level "Cobalt not active" message per the task's framing.
4. **`0xa60bf13d` is the ERC-8056 *core* id used only as a Cobalt PROXY** — NOT proof the policy
   surface is live. Weakened claim (confirmed): if the gate PASSES but `policyId`/`isAuthorized`
   then revert, preflight MUST fall through to `unavailable(read_failed)` with a diagnostic —
   never `allow`, never `not_cobalt` (guarded by `test_gate_passes_but_policy_read_reverts_*`).
   **Assumption to re-verify live on Sepolia at Cobalt activation:** that `supportsInterface(0xa60bf13d)`
   truly co-activates with the policy surface. If the policy/seize surface gets its own interface
   id, tighten the gate to probe that instead.
5. **Executor/seize scopes excluded** from v1 (ordinary transfers only), per task scope.
