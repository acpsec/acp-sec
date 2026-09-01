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
