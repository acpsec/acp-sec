# Session Summary v16 — Group 8 complete

> Seed for a fresh chat. Written from verified repo state (git logs + targeted
> test runs, 2026-07-13). Supersedes v15.

**Status:** Group 8 (staging deploy) closed. Group 9 (production cutover)
next up.

## Ground truth at v16

### acp-sec (backend)
- Branch: `deploy/staging`, HEAD: `6368b1e`
- Author of top-2 commits (8.6 artifacts): `acpsec <turkvengeance@gmail.com>`
  (rebased via 8.6-authorship-fix after the initial commits landed under
  `claudyaaprilia123-cmd`; content byte-identical, metadata-only rewrite)
- Full pytest suite: **not run in this close-out** (record-keeping task). Last
  green full run was **1117 passed / 2 skipped** (Group 7.3 / v15 ground truth).
  Re-running the full suite on `deploy/staging` is deferred — the branch's
  `conftest.py` couples to `dashboard.serve` (Flask); tracked for Group 9
  cleanup (see Tracked items #2).
- Targeted `tests/api/test_b20.py` result: **10 passed**

### acpsec-web (frontend)
- Branch: `deploy/staging`, HEAD: `58b73b1`
- Vitest: **314 passed / 62 files**
- Vercel env vars point to the Railway generic URL after the incident (see
  Incident section)

### acpsec-app (scaffold)
- Status: **archival — no active development**
- Superseded by `acpsec-web` (which ported all functional UI in Group 7.2c)
- Retained read-only for reference
- Tagged `archived-post-staging` — **local-only** (repo has no `origin` remote)

### acp-sec-b20 (standalone engine)
- Status: **archival — no active development**
- Superseded by `acp-sec/acpsec_api/b20/` (vendored via Group 7.1a)
- Retained read-only for reference
- Tagged `archived-post-staging` — **local-only** (repo has no `origin` remote)

## Gate decisions (Group 8, locked by Fadhlan)

- **8.0a Origin strategy → SPLIT ORIGIN.** Frontend on Vercel, backend on
  Railway, cross-origin with CORS allowlist + `SameSite=None; Secure` cookie +
  `X-Scanner-Token`. **This supersedes the v15 "single origin" note** — the
  split-origin machinery (`af85238`) and the frontend client already
  implemented it end-to-end.
- **8.0b Persistence → EPHEMERAL** (no Railway volume). The `dashboard/*.json`
  file stores reset on redeploy; acceptable for staging. Durable persistence
  (volume or managed DB) is a Group 9 production requirement.
- **8.0c RPC → public Base endpoints** (sepolia.base.org / mainnet.base.org),
  proven in Group 7.3 live tests. Alchemy + env override deferred to Group 9.

## Group 8 outcomes

**Section 8.1** — Backend deploy config committed (`railway.staging.json` on
`deploy/staging`). **Premise correction:** prod `acpsec.app` deploys *this same
repo* (`fdlr28/acp-sec@main`, service `web`, `python dashboard/serve.py`), so no
shared root deploy file (`railway.json` / `Procfile` / `requirements.txt` /
`runtime.txt` / `.railwayignore`) was touched. Staging is isolated via a
separate service + `deploy/staging` branch + its own `railway.staging.json`
(FastAPI start, `/api/health` healthcheck, `pip install '.[api]'` buildCommand,
`watchPatterns` excluding Process B / contracts / legacy HTML).

**Section 8.2** — Frontend Vercel project created (`acp-sec-app` under personal
team `agentz`). Split-origin ⟹ no `vercel.json` / no rewrites; env documented
in `acpsec-web/docs/staging-deploy.md`.

**Section 8.3** — Railway backend service `web-staging` live at
`web-staging-production-e201.up.railway.app`. FastAPI serving; secret env vars
(`SCANNER_TOKEN`, `LEADERBOARD_PASSWORD`) entered by Fadhlan directly;
`scanner_protected: true` confirmed.

**Section 8.4** — Vercel frontend deployed. Auto-redeploy on env var change.

**Section 8.5** — DNS records at Namecheap:
- `@` CNAME → `azr14sm6.up.railway.app` (prod, unchanged)
- `staging` CNAME → `f44e9807f110e647.vercel-dns-017.com` (Vercel)
- `_railway-verify` TXT → `railway-verify=84ae4a43…` (prod, rotated after
  incident recovery)

**Section 8.6** — Smoke script `scripts/staging-smoke.sh` + report at
`docs/staging-smoke-2026-07-11.md`, **16/16 pass**. Commits re-authored to
`acpsec` (8.6-authorship-fix).

## Incident: Railway custom-domain limit (2026-07-13)

**Symptom:** `acpsec.app` returned Railway edge 404 ("The train has not arrived
at the station"). Prod down.

**Root cause:** Railway Hobby plan has a project-level custom domain limit.
Attaching `api-staging.acpsec.app` to service `web-staging` during Group 8
consumed the last slot. At some point after that, the `acpsec.app` binding on
service `web` was silently detached — Railway did not surface a warning that a
prior binding had been evicted.

**Recovery (~25 minutes total downtime):**

1. Verified DNS at Namecheap intact — `@ CNAME` still pointed to
   `azr14sm6.up.railway.app`. Not a DNS issue.
2. Verified service `web` Online, deploy from `main` unchanged. Not a build
   issue.
3. Found `acpsec.app` missing from `web`'s Public Networking, and Railway
   refused to re-add it ("Not available") due to the plan-limit ghost.
4. Trade-off chosen (**Opsi A**, prod-first): detached
   `api-staging.acpsec.app` from `web-staging`, freeing the slot.
5. Re-added `acpsec.app` to `web`. Railway generated a fresh `_railway-verify`
   TXT value; updated at Namecheap (verified via UI — local `dig`/`ping` failed
   due to a laptop DNS-resolver hiccup, but Railway's own validator succeeded).
6. Deleted stale records at Namecheap: CNAME `api-staging`, TXT
   `_railway-verify.api-staging`.
7. Updated Vercel `NEXT_PUBLIC_API_URL` from `https://api-staging.acpsec.app` →
   `https://web-staging-production-e201.up.railway.app` (Railway generic URL).
   Vercel auto-redeployed.
8. Re-ran smoke test with `BACKEND_URL` override →
   **16/16 pass**.

**Accepted trade-off:** staging backend no longer has a branded URL. Frontend
custom domain (`staging.acpsec.app`) is preserved. Functionally identical.

**How to run the staging smoke test post-incident:**

    cd ~/sentrak/acp-sec
    BACKEND_URL=https://web-staging-production-e201.up.railway.app \
      SCANNER_TOKEN=<value_from_railway_console> \
      ./scripts/staging-smoke.sh

Script defaults are unchanged; the `BACKEND_URL` override is the documented way
to point at the Railway generic URL until/unless the custom domain is restored.

## Tracked items (Group 9 candidates)

1. **Railway plan decision.** Options: (a) upgrade to Pro for unlimited custom
   domains, restore `api-staging.acpsec.app`; (b) split staging into a separate
   Railway project (own domain-slot budget); (c) stay on Hobby, accept the
   generic backend URL for staging. No action required to keep staging
   functional as-is.
2. **`conftest.py` Flask coupling.** The `deploy/staging` `conftest.py` imports
   `dashboard.serve`, which requires Flask, so the full pytest suite can't be
   run on the migration `.venv` without Flask installed. Fix: relocate scanner
   logic out of `dashboard/` (planned for Group 9), or split conftests per
   subpackage.
3. **`SCANNER_TOKEN` rotation.** The current value was exposed in an assistant
   chat during smoke-test debugging. Rotate before production
   (`openssl rand -hex 16`), updating Railway + Vercel simultaneously. (Variable
   named only here — never the value.)
4. **tsc 5 pre-existing errors** in `useScanFlow.test.tsx` /
   `useScoreMutation.test.tsx` (recorded in v15). Opportunistic cleanup.
5. **Production DNS cutover.** Group 9: point `acpsec.app` at Vercel (Next.js),
   point `api.acpsec.app` at the Railway backend, decommission Flask on `web`
   prod. Also: durable persistence (Tracked #1/8.0b) and Alchemy RPC wiring
   (8.0c).

## Scaffold archival

`acpsec-app` and `acp-sec-b20` are tagged `archived-post-staging` in their
respective repos (local-only — neither has an `origin` remote). Not deleted;
retained read-only for reference. Deletion, if ever, is a Group 9 decision.
