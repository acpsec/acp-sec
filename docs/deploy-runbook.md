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
