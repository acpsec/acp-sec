# Deploy runbook — `api-prod` (Railway) + Dockerfile builder

Operational runbook for the FastAPI backend Railway service **`api-prod`**, which
builds from the committed [`Dockerfile`](../Dockerfile) (issue #48 — migrated off
nixpacks, which baked build-time secrets into image layers).

---

## Builder configuration (`dockerfilePath`)

**The Dockerfile builder is not selected by anything in this repo.** There is a
Dockerfile and `railway.prod.json`, but:

- `railway.prod.json` carries **no** `build.builder` and **no** `dockerfilePath`.
- Railway's `Builder` enum has no `DOCKERFILE` value.

The builder is switched to Dockerfile mode purely by an **instance-level
`dockerfilePath` setting on the `api-prod` service**, applied once via a GraphQL
mutation against the Railway API. **That state lives only in Railway, never in
git.**

> ⚠️ **Consequence:** if the `api-prod` service instance is recreated, reset, or
> moved to a **new environment**, it falls back to **nixpacks** — reintroducing
> the #48 build-time secret leak — until the mutation below is re-run. Re-running
> this mutation is a **required** step of recreating the service, not optional.

### The mutation

Railway public GraphQL API — `https://backboard.railway.com/graphql/v2`:

```graphql
mutation SetDockerfilePath($environmentId: String!, $serviceId: String!) {
  serviceInstanceUpdate(
    environmentId: $environmentId
    serviceId: $serviceId
    input: { dockerfilePath: "Dockerfile" }
  )
}
```

```jsonc
// variables — fill in the real IDs from the Railway dashboard / `railway status`
{
  "environmentId": "<api-prod prod environment id>",
  "serviceId":     "<api-prod service id>"
}
```

As a single `curl` (`RAILWAY_TOKEN` = an account/team token with project access):

```bash
curl -s https://backboard.railway.com/graphql/v2 \
  -H "Authorization: Bearer $RAILWAY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation($e:String!,$s:String!){serviceInstanceUpdate(environmentId:$e,serviceId:$s,input:{dockerfilePath:\"Dockerfile\"})}",
    "variables": { "e": "<environment-id>", "s": "<service-id>" }
  }'
```

Success returns `{"data":{"serviceInstanceUpdate":true}}`. The next deploy builds
via the Dockerfile. Verify with a fresh deploy + `GET /api/health` → `{"ok":true}`.

---

## Emergency revert procedure (back to nixpacks)

Reverting the Dockerfile builder is a **two-part** operation — the git side alone
is not enough, because the instance `dockerfilePath` set in Railway persists
independently of the repo. Both parts are required (this is the procedure used
during #48).

**Part 1 — git: restore the nixpacks build config.**

```bash
# Revert the Dockerfile-migration change on main (use the actual commit/PR range).
git revert --no-edit <dockerfile-migration-commit>
```

If `railway.prod.json` needs its nixpacks `build` block restored (this runbook's
PR also removed the historical `railway.prod.nixpacks.bak`; recover it from git
history with `git show <old-commit>:railway.prod.nixpacks.bak` if needed), the
block is:

```jsonc
"build": {
  "builder": "NIXPACKS",
  "buildCommand": "pip install -r requirements/prod.txt && pip install . --no-deps"
}
```

Commit and push so the next deploy has a valid nixpacks config.

**Part 2 — Railway: reset the instance `dockerfilePath` to `null`.**

Same mutation as above, with `dockerfilePath: null` — this clears the
Dockerfile-builder override so Railway falls back to nixpacks:

```bash
curl -s https://backboard.railway.com/graphql/v2 \
  -H "Authorization: Bearer $RAILWAY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation($e:String!,$s:String!){serviceInstanceUpdate(environmentId:$e,serviceId:$s,input:{dockerfilePath:null})}",
    "variables": { "e": "<environment-id>", "s": "<service-id>" }
  }'
```

After both parts, trigger a redeploy and confirm `GET /api/health` → `{"ok":true}`.
Skipping Part 2 leaves `dockerfilePath` pointing at a now-reverted (absent)
Dockerfile → the build breaks.

---

## Local build verification

Reproduce the CI secret-leak gate locally before pushing:

```bash
# Build the image exactly as CI does.
docker build . -t acpsec-ci-verify

# Fail if any secret VALUE was baked into layer history.
# Variable NAMES are expected (they appear in CMD/ENV); only VALUES indicate a
# leak via ARG or build-time ENV.
docker history acpsec-ci-verify --no-trunc \
  | grep -iE "SCANNER_TOKEN=[^ ]|LEADERBOARD_PASSWORD=[^ ]|ANTHROPIC_API_KEY=[^ ]|CDP_API_KEY=[^ ]|B20_RPC_URL.*=https" \
  && echo "FAIL: secret values in layers" \
  || echo "PASS: no secret values in image layers"
```

> This is **run automatically by CI** — the `docker-build` job in
> [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) builds the image and
> runs the same `docker history` grep on **every PR touching the Dockerfile**
> (it graceful-skips green when no Dockerfile is present). `docker-build` is a
> required status check in branch protection, so a leak blocks the merge — the
> local run above is a fast pre-flight, not a substitute.

## scanner 0.7.0 — B20 capability doctrine shift (#70)

**What changed.** The B20 reader's `capability()` (roles → `can_seize` / `can_pause`
/ `can_burn_blocked` / `burn_enabled`) previously returned a **tri-state**:
`True` (held), `False` (granted-then-revoked), `None` (never-granted — treated as
*unknown*, per the #34 premise that B20 sets initial roles event-lessly). From
**0.7.0** a **successful** role read is authoritative:

| role getLogs result | pre-0.7.0 | 0.7.0+ |
|---|---|---|
| read FAILED (`holders is None`) | `None` | `None` (unchanged — still "unknown") |
| read succeeded, **empty** | `None` | **`False`** (proven absence) |
| read succeeded, held | `True` | `True` |

`None` now means **only "read failed"** (a `read_diagnostics` entry is present).

**Why.** On event-emitting tokens (verified: base-forge v1.1.0 emits
`RoleGranted`/`RoleRevoked` for creation-time grants too), a never-granted SEIZE
made `can_seize=None` → `transfer_policy` UNRATED → the 0.5 unrated multiplier
floored **every fresh token** to ~F/38 regardless of real risk. Restoring the
doctrine lets `transfer_policy` rate.

**Score impact — same token, same chain state, re-read across the boundary:**

| adversarial token | pre-0.7.0 | 0.7.0 |
|---|---|---|
| T4 (name/symbol "NVDAc", `0x…33379Ddc`) | F / 38 / unrated | **A / 96 / rated** |
| T3 (5 empty announcements, `0x…372c579C`) | F / 38 | **A / 97** |
| T2 (2nd MINT holder, `0x…928b3258`) | F / 38 | **A / 96** |
| T1 (cap = uint128.max−1, `0x…D6993089`) | F / 38 | **A / 96** |

Regression contract = the fixture pair
`tests/b20/fixtures/live/T4-nvdac-impersonation-2026-09-09.json` (pre-fix) vs
`T4-nvdac-post-70-fix.json` (post-fix). The floor lift is what makes the
impersonation (#66), cap knife-edge (#67), announcement (#68) and mint-distribution
(#69) findings visible as **grade-A** false-safes rather than F-floored.

**Migration note — archived scans.** A pre-0.7.0 scan recording `can_X: null` may
mean **either** "unread" **or** "never granted". From 0.7.0, `null` means **only
"unread"** (a `read_diagnostics` entry accompanies it) and never-granted resolves
to `false`. Any persisted/leaderboard B20 result from before 0.7.0 carries the old
semantics and a lower (floored) grade until **re-scanned**. Distinguish by
`scanner_version` in the payload.

**KNOWN tradeoff (Option A).** The fix is unconditional: a **successful empty**
read → `False`, even for a genuinely *silent* token (no role events at all). A
silent token that actually holds seize/pause in precompile-internal state would be
mis-read `can_seize=false`. Mitigation in practice: on real large-history tokens
(fixb20/BRIAN) the public-RPC `getLogs` range cap makes the role read **fail**
(`holders=None` → `null`), not return empty, so the mis-read does not trigger there.
Residual asymmetry: `#70` touches `capability()` only, **not** the parallel
`admin_roles_revoked` path — so `issuer_authority` still goes UNRATED on a silent
token while `transfer_policy` now rates. Aligning the admin path is a follow-up.

## scanner 0.8.0 — tokenized-stock impersonation critical (#66/#55)

**New critical condition** `CRITICAL_IMPERSONATION`. The reader now reads `name()`/
`symbol()` (previously never read — #66 gap) and derives a tri-state
`official_ticker_status` by a **symbol-only, case-insensitive** match against a
**hardcoded, chain-scoped allowlist** (`constants.OFFICIAL_TOKENIZED_STOCKS`, the 10
official Coinbase tokenized stocks from base.org/stocks, Base mainnet 8453 only):

- `symbol` = an official ticker **and** address == its pinned address → **`verified`** (variant_config emits a positive "official tokenized stock" signal; no penalty).
- `symbol` = an official ticker **but** a non-official address, or a chain with no pinned entry (e.g. any official ticker on Sepolia) → **`impersonation`** → `CRITICAL_IMPERSONATION` caps the composite at `CRITICAL_CAP` (grade **F**), same mechanism as `uncapped_mint`/`single_eoa_admin`; variant_config emits a High finding naming the claimed ticker + expected official address.
- `symbol` not an official ticker → `None` (no flag). `name()` is surfaced but **not** used for the verdict.

**Hard rule (scan-path isolation):** the allowlist is CODE; the scan path reads only
the constant and **never** fetches base.org. Freshness is handled out-of-band by
`scripts/refresh_tokenized_stocks.py` (fetch → diff → PR-ready code block, exits
non-zero on drift). If base.org is down, only the refresh script fails; scans are
unaffected. Refresh cadence: run when Coinbase lists new stocks (or on a schedule).

**Migration note.** Pre-0.8.0 scans never carried `official_ticker_status` and never
flagged impersonation — a fake tokenized stock could score up to grade A. From 0.8.0
a fake (`impersonation`) is capped at F. `name`/`symbol` are now populated in every
scan (previously always `null`). Distinguish by `scanner_version`.

**Severity demonstration (live):** the T4 fake "NVDAc" dropped **A/96 → F**; the real
Coinbase NVDAc stays F (its own findings) but now carries `official_ticker_status:
verified`. A non-stock B20 (BRIAN) is unaffected (`status: null`).

### RPC quality is load-bearing for the impersonation check + role reads

Both the #66 impersonation defense (`symbol()` read) and the role/announcement
reads (`getLogs`) depend on a **getLogs-capable, non-throttled** RPC. The public
`mainnet.base.org` (8453) is throttled enough that, during a full scan, it
intermittently drops `symbol()` and rate-caps `getLogs` — which honestly degrades
the scan (symbol unreadable → `variant_config` UNRATED + `read_diagnostics`
entry; roles unreadable → `issuer_authority`/`transfer_policy` unrated) but is
**not a false-safe** (never a false `verified`/`impersonation`, never a guessed
capability). `symbol()` is retried 3× with backoff (metadata-only) to blunt this,
but retries cannot fix a persistently-throttled endpoint.

**Production MUST set `B20_RPC_URL_8453`** (and `B20_RPC_URL_84532`) to a paid,
getLogs-capable provider (Alchemy PAYG / QuickNode / CDP / etc.) so the
impersonation check and role reads are deterministic. Same conclusion as #24. This
is Railway service config (`serviceInstance` env var), **not** code — set it in the
Railway dashboard, do not hardcode a provider URL/key in the repo.

### scanner 0.8.1 — getLogs full-range failure now falls back to chunking (robustness)

**Reader-only robustness (no scoring change).** Root cause of NVDAc reading F/12 on
prod (CDP): its history spans ~2M blocks, the single full-range `getLogs` **timed
out**, and the chunk-walk fallback was gated on `RANGE_CAP_KIND` only — so a timeout
dead-ended at `None` and the 100k chunk budget was never used, leaving roles unread
(and the diagnostic said the generic "no read diagnostic recorded").

Fixes in `reader.py`:
1. `_get_logs_full_or_chunked`: after the full-range query fails for **any** reason
   (range cap, **timeout**, oversized, transient), fall back to the chunk walk —
   not only on `RANGE_CAP_KIND`. Preserves the full-first fast path (ungated / small
   span) and the existing range-cap chunking (#32/#33).
2. `read_roles`: when the role read fails, surface the **verbatim** `rpc.last_error`
   (e.g. "Role reads failed: TimeoutError…") instead of discarding it — the scan now
   SAYS why roles are unreadable.

Effect: long-history B20s (NVDAc, GOOGLc, …) now read roles via the chunk walk on a
getLogs-capable RPC. A very long history costs one doomed full-range query (its
timeout) before chunking — acceptable; correctness over ~one timeout of latency.
Still depends on a getLogs-capable `B20_RPC_URL_8453` (public base.org caps too low).

**⚠️ Chunk size matters (live finding).** With `B20_GETLOGS_CHUNK_8453=100000`, a
single 100k-block `getLogs` **persistently times out** on CDP for a dense-history
token (NVDAc, ~2M blocks / 20 chunks) — the per-chunk retry can't rescue a
persistent timeout. Measured live: chunk `100000` → FAIL (TimeoutError); chunk
`20000` → **7 roles read**, full scan F/39 (uncapped_mint + single_eoa_admin, all
dims rated, multiplier 1.0). **Set `B20_GETLOGS_CHUNK_8453=20000`** (Railway) — 100k
is too aggressive for CDP. The reader changes (fallback + honest diagnostic +
per-chunk retry) are necessary but NOT sufficient without a chunk size the provider
can actually serve. (A future code option: adaptive halving on a chunk timeout so
the size auto-adapts — deliberately not done here per the existing no-halving design.)

## scanner 0.9.0 — effectively-uncapped supply + verified-stock context (#67 + #55)

**Scoring semantics change (contract change → minor bump).**

1. **Effectively-uncapped detection** — the uncapped-mint critical now fires on
   `supply_cap >= EFFECTIVELY_UNCAPPED_MIN` (`UINT128_MAX // 2`, tunable via
   `EFFECTIVELY_UNCAPPED_FRACTION`), not just the exact `UINT128_MAX` sentinel. This
   closes the T1 evasion (cap = `max-1` ≈ 3.4e38 previously scored A/100). Data:
   all 10 official stocks sit at the exact sentinel; every real fixed-cap token is
   ~1e27 (11 oom below), so half-of-max cleanly separates them, decimals-agnostic.

2. **Verified-stock context** — severity is gated on `official_ticker_status`:
   - **unverified + effectively-uncapped** → `CRITICAL_UNCAPPED_MINT` (grade F cap)
     + `supply_integrity` High "uncapped supply … effectively infinite mint" (−60),
     as before (now catching the near-sentinel range too).
   - **verified + effectively-uncapped** → **no critical, no penalty**;
     `supply_integrity` emits an **INFO** finding "uncapped supply — expected for a
     verified 1:1-backed tokenized stock (supply floats with custody)". Honesty: the
     fact is surfaced + contextualized, never hidden. `issuer_powers.can_mint_unbounded`
     stays `true` (the fact is ungated).

**Migration note.** All 10 official Coinbase tokenized stocks are uncapped by design;
pre-0.9.0 they took the uncapped-mint critical (a false-positive on legit design).
From 0.9.0 a verified stock is no longer penalized for uncapped supply — its score
rises (raw_score up; a stock with a single-EOA admin still hits that critical, so its
grade may stay F for the honest reason). Any archived score for a verified stock
pre-0.9.0 understated it; re-scan. Distinguish by `scanner_version`.

## scanner 0.10.0 — announcement content, not just presence (#68)

**Scoring semantics change.** Announcements are issuer self-attestation the scanner
cannot verify, so they are NEVER a bonus above baseline — a **substantive** one only
lifts the "no disclosure" penalty.

- **classify_announcement**: substantive ⟺ `len(description.strip()) >= MIN_ANNOUNCEMENT_CHARS`
  (8, data-justified — shortest real on-chain announcement "Stock Split" = 11) **AND**
  not an exact duplicate of an earlier-seen stripped description on the same token.
  Junk (empty/whitespace/under-floor/duplicate) is **neutral** — not counted, not
  extra-penalized (can't distinguish gaming from a dev testing `announce()`).
- **origin_transparency**: ≥1 substantive → absence penalty lifted (as "present" was);
  0 substantive + unverified → Low, text distinguishes "no on-chain announcements"
  (0 total) vs "N announcements, none substantive (empty/duplicate/too short)";
  0 substantive + **verified** → **Info** "discloses via regulated off-chain channels"
  (no penalty — #55 gate; Q4 confirmed official stocks are true 0-announcement by design).
- **evidence.announcements** now populated (was always `[]`): per announcement —
  `description, uri, block, tx, substantive, reason, uri_format_ok`. Consumers can READ
  what the issuer claimed (the scanner can't verify truth). **URIs are format-validated
  only, NEVER fetched** (Cloudflare/Nitter lesson — no network in the scan path).

**Migration note.** Pre-0.10.0, *any* announcement lifted the penalty (gameable with
empty posts — the T3 finding). From 0.10.0 only substantive disclosure counts, and a
verified stock with no on-chain announcements is Info not Low. Re-scan for accurate
origin_transparency. Distinguish by `scanner_version`.

## scanner 0.11.0 — mint-role distribution scored (#69)

**New scoring signal.** `mint_role_holders` was read and surfaced in
`issuer_powers` but scored in NO dimension — a second/unaccountable MINT_ROLE
holder was invisible. From 0.11.0 mint distribution is scored inside
**issuer_authority** (mint is an authority question — a MINT_ROLE holder can
dilute holders up to the cap — so it composes with the admin governance ladder).

- The signal is **EOA-ness + admin∩mint overlap, NOT count** (all 10 legit
  tokenized stocks have a single *separated CONTRACT* mint holder, so count does
  not discriminate). New reader field `mint_holders_eoa` classifies each mint
  holder via `eth_getCode` (tri-state: `None`=unclassified/unreadable, `[]`=all
  contracts, `[..]`=bare EOA keys).
- **issuer_authority** additions: a non-multisig **EOA mint key** → **High**
  (−25, a bare key can dilute to the cap); **≥2** EOA mint keys → **Medium**
  (−10, larger key surface); a mint holder that **also holds admin** (no
  separation of duties) → **Medium** (−15, or −25 when the shared address is a
  bare EOA). `official_ticker_status == "verified"` + a *separated contract*
  mint → **Info**, no penalty (#55 gate) — but verified does **NOT** excuse a
  bare-EOA mint key or an admin overlap (still graded).
- **Honesty (same caveat as `admin_is_multisig`):** classification says
  "non-multisig EOA" / "not a bare EOA", never "safe" — a contract can be a
  single-key proxy.
- **Rated unchanged.** Mint contributes only when mint holders are readable; a
  silent zero-event token (mint empty from silence) emits no mint finding and is
  NOT newly unrated (#70 doctrine: silent ≠ unread).

**Migration note.** Re-scan tokens with extra/EOA mint authority — pre-0.11.0
they scored identically to a single-contract-mint token. Distinguish by
`scanner_version`.
