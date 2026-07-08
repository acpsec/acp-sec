# B20 scan endpoint — schema (Task 7.1)

The standalone `acp-sec-b20` `/scan` endpoint is **merged into `acpsec_api`** as
`POST /api/b20/scan` (Opsi A — single origin, no second service, no
`NEXT_PUBLIC_B20_API_URL`). This document is the contract that seeds **7.2b**
(the acpsec-web API client).

## Endpoint

`POST /api/b20/scan` — same origin as the rest of `acpsec_api`.

> **Method change (deliberate).** The standalone service exposed
> `GET /scan?address&chain_id`. Merged here as **POST with a JSON body**, matching
> acpsec_api's other scan endpoints (`/api/scanner/scan` etc.). The **response
> body is byte-identical** to the standalone service — only the method + input
> location changed. 7.2b must call POST same-origin (drop the scaffold's GET +
> `NEXT_PUBLIC_B20_API_URL`).

### Request body
```json
{ "address": "0x…(40 hex)", "chain_id": 8453 }
```
| Field | Type | Rule |
|---|---|---|
| `address` | string | must match `^0x[0-9a-fA-F]{40}$` |
| `chain_id` | int | one of `8453` (Base mainnet) · `84532` (Base Sepolia) |

Validation runs **before** any RPC read; a bad address/chain never touches the
network.

### Success — `200`
Body is `ScanResult.to_dict()` — **one payload serving all three disclosure
layers** (holder / trader / researcher):

| Field | Type | Notes |
|---|---|---|
| `token` | string | scanned address |
| `chain_id` | int | 8453 / 84532 |
| `variant` | string \| null | `"ASSET"` / `"STABLECOIN"` |
| `name` / `symbol` | string \| null | |
| `decimals` | int \| null | |
| `currency_code` | string \| null | |
| `trust_score` | int | final, confidence-adjusted (Layer 1) |
| `raw_score` | int | composite before the unrated multiplier (Layer 3) |
| `grade` | string | `A`–`F` |
| `rated` | bool | false if any dimension unrated |
| `multiplier` | float | `1.0` all-rated, else `0.5` |
| `unrated_dimensions` | string[] | |
| `is_critical` | bool | Layer 1 |
| `critical_reasons` | string[] | |
| `dimensions` | object | `{ <name>: { score, weight, findings[] } }` (Layer 2); `findings[] = { severity, detail }` |
| `issuer_powers` | object | `can_freeze/can_seize/can_pause/can_mint_unbounded` (bool\|null), `supply_cap` (str\|null), `admin_addresses` (str[]), `admin_is_multisig` (bool\|null), `mint_role_holders` (str[]), `pause_role_holders` (str[]) |
| `deployed_via_factory` | string \| null | |
| `scanner_version` | string | e.g. `"0.1.0"` |
| `scanned_at` | string | ISO-8601 UTC |

TypeScript mirror already exists in the scaffold (`acpsec-app/src/lib/types.ts`)
— port it verbatim in 7.2b.

### Errors — `{ "error": <code>, "detail": <message> }`
| Status | `error` | When |
|---|---|---|
| 400 | `invalid_address` | address fails the 0x-40-hex regex |
| 400 | `unsupported_chain` | `chain_id` not in {8453, 84532} |
| 400 | `not_b20` | target is not a B20 token / not initialised / feature off |
| 503 | `rpc_unreachable` | RPC factory init failed, **or** the node returned no response to any call |

(Bodies are exactly `{error, detail}` — no envelope, distinct from acpsec_api's
`{ok, data}` endpoints.)

## `/health` — intentionally NOT added
The standalone `GET /health` returns `{"status": "ok"}`, a strict subset of
acpsec_api's existing `GET /api/health`
(`{ok, service, acpsec_available, scanner_protected}`). No unique information →
**skipped** (no `/api/b20/health`). Liveness is covered by `/api/health`.

## Implementation pointers (7.1)
- Engine vendored at `acpsec_api/b20/` (pure-stdlib, byte-identical to source).
- Router `acpsec_api/routers/b20.py`; registered in `acpsec_api/main.py`.
- Handler is **sync `def`** (RPC-bound → FastAPI threadpool).
- DI seams `get_read_fn` / `get_scorer` / `get_rpc_factory` — override in tests.
- CORS/cookie flags unchanged (Task 2.8, `af85238`); no new pip deps.
