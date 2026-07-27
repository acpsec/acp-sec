# Session Summary v18 — Migration Groups 1–9 COMPLETE; F1 shipped

> Seed for a fresh chat. Written from verified repo + live-Railway state
> (2026-07-26). Supersedes v17. Facts re-checked this session, not carried
> forward — the lineage drifted once before.

## Ground truth at v18

- **acp-sec** `main` HEAD: **`aefeaf2`** (#10, "delete root requirements.txt").
- **Full pytest suite: 1150 passed / 2 skipped** (flask uninstalled locally,
  mirrors the clean CI runner). The 2 skips are the B20 live-RPC tests
  (skipif-gated on `B20_LIVE_RPC`).
- **CI:** GitHub Actions pytest gate on push/PR to `main` (`.github/workflows/ci.yml`),
  ubuntu-latest, Python 3.12, `checkout@v7`/`setup-python@v7`, installs
  **`.[dev,api]` only** (the flask install + `import dashboard.serve` guard were
  removed in A2a, since the parity tests they supported are gone). Branch
  protection on `main`: requires the `test` check, strict, no reviews,
  admin-bypass on.
- **Prod:** Railway project `sublime-truth`, env `production`. `api-prod`
  (FastAPI, tracks `main`) runs **`aefeaf2`** (deployment `a1091af6`, Online,
  `/api/health` 200).

## Track 1 — Migration Groups 1–9: **COMPLETE**

The bounded deploy/migration epic (Flask → FastAPI+Vercel) is done. Groups 1–8
closed at v16; Group 9 (production cutover + Flask decommission) is now closed.
Final steps this session, all merged to `main`:

| PR | What landed |
|---|---|
| #6 (A1) | Prep: relocate x402/mcp/auth_scanner test doubles out of `dashboard/` → `tests/mocks/`; **freeze 3 golden-value tests** (`/api/health`, `/api/controls`, `/api/score/manual`) while the Flask parity oracle still passed — so its contracts survive its deletion. |
| #7 (A2a) | **Delete the Flask service + parity oracle:** `dashboard/`, `Procfile`, `railway.json`, the 13 FastAPI-vs-Flask parity tests + `flask_client` + `assert_parity`, `auth_scanner.py` + `TestX402LiveProbes`, and the flask install + guard in `ci.yml`. Pre-deletion SHA `2ee4813`. |
| #8 | **Orphaned-mock cleanup:** delete `tests/mocks/{mock_facilitator,mock_mcp_server}.py` + `TestMockFacilitator`/`TestMockMCPServer` — test doubles whose only consumer was their own self-test (same island as auth_scanner). Verified `run_mcp_checks`/`run_x402_checks` are static and use neither. |
| #9 (A2b-1) | **De-watch** `requirements.txt` from `watchPatterns` in `railway.prod.json` + `railway.staging.json` (file kept). Makes the next deletion deploy-silent. |
| #10 (A2b-2) | **Delete root `requirements.txt`** (Flask deploy manifest). Deploy-silent (unwatched); validated by a manual `--from-source` redeploy. |

**Result: api-prod runs `aefeaf2` with no Flask stack** — `flask`, `gunicorn`,
`werkzeug`, `itsdangerous`, `blinker` are gone from the build; deps come from
`pip install '.[api]'` + pyproject base.

## Track 2 — Features: **F1 (scan-skill) shipped** (#1)

`acpsec scan-skill <path> [--json]` — static pre-install audit of agent skills
(SKILL.md manifest + instruction + bundled-code layers), 19 `SKILL-*` rules,
verdict PASS/WARN/FAIL, exit 0/1/2. Supporting PRs: #2 (CI gate), #3 (F821
`Callable` fix in `acpsec_api/scanner.py`), #4 (CI actions→v7), #5 (catalogue
severity-drift guard). Detail: `docs/session-summary-v17.md`, `docs/scan_skill/`.

**F1 follow-ups still OPEN (deferred, not started):**
- Optional `POST /api/skill/scan` endpoint reusing the `scan_skill` core.
- Filesystem watcher on `~/.claude/skills/`.
- Widen exfil detection beyond the ±2-line window; more obfuscation forms;
  reduce the ±2-window over-flag (documented CRITICAL false-positive case).
- If live x402 probes are ever wanted back, they return as **F2** (prober +
  probed + tests together, written against FastAPI) — not resurrected from the
  deleted Flask `auth_scanner`.

## What was VERIFIED IN PRODUCTION (and how)

A2b-2 was not assumed — it was validated live on `api-prod`:

- **NIXPACKS did NOT drop the install phase — my prediction was wrong.** With
  `requirements.txt` gone, NIXPACKS re-planned the install phase from
  `pip install -r requirements.txt` to **`pip install --upgrade build setuptools
  && pip install .`** (stage 6/10), then `pip install '.[api]'` (stage 8/10).
  Still two pip runs; the first is now a bare `pip install .`. Build log of
  deployment `a1091af6` confirms **zero** `requirements.txt` references.
- **Same-day control isolated the deletion.** An accidental plain
  `railway redeploy` had just rebuilt `7a366bc` (deployment `a344d14c`) minutes
  earlier — same commit content except the deletion. Diffing `a1091af6`
  (aefeaf2) against `a344d14c` instead of the 2-day-old `eb595816` removed
  time-based re-resolution as a variable. Result: **zero runtime version drift**
  (no `CHANGED`). Only differences: **removed** flask/gunicorn/werkzeug/
  itsdangerous/blinker (all unused by the app); **added** build/setuptools/
  pyproject-hooks (PEP517 tooling from the new `pip install .`).
- **Functional endpoint checks matched A1's golden contracts** (not just import
  + `/api/health`): `GET /api/controls` → 200 (`source: acpsec`, 30 checks + 8
  asf_controls — exercises the full acpsec import chain); `GET /api/score` → 200
  `{"ok": false, "data": null}`; `POST /api/scanner/lookup` (no token) → **401**
  with the exact `SCANNER_DENIED_ERROR` body — the auth gate, **not** a 500.
  Nothing the flask stack silently provided is missing at runtime.
- **Local pre-flight rehearsal** (before any merge): a throwaway venv with only
  `pip install '.[api]'` imported every module, ran the CLI, served
  `/api/health` 200 — predicting the functional guarantee that prod confirmed.

## OPEN ITEMS (honest state)

1. **No lockfile → prod builds are not reproducible.** Every build re-resolves
   from floors. Concrete drift observed: **fastapi 0.139.2 → 0.140.0** between
   `eb595816` (07-24) and the 07-26 builds — two builds, two days, different
   fastapi. A lockfile is the fix if reproducibility is wanted; out of scope so
   far.
2. **RESOLVED (2026-07-27) — the dead `web` (Flask) Railway service is DELETED.**
   Sequence (two steps, not atomic): `acpsec.app`'s custom domain was **detached**
   first (it resolves via Vercel, `216.198.79.1`, so zero downtime), freeing the
   plan's custom-domain slot; then the `web` service itself was deleted. No Flask
   service remains — reviving Flask is a **cold rebuild** (not a restart). Three
   candidate commits, by what each is actually for:
   - **`5ca798c`** — **proven to run in production**: `web`'s last successful deploy
     (`bba131bd`, created 2026-07-14T01:35:43Z, RUNNING until the 07-16 stop). The
     honest starting point for a revive — it is what actually served prod. (This is
     what the deploy/staging "9.6 docs" pinned; it answered "what is proven to run,"
     not "what is newest." It happens to be the Group 8/9 "9.3" merge.)
   - **`544b87b`** — **last fully self-contained tree**: serve.py's imports are
     intact, but it predates the SentryAgent chat/playground/profile features.
   - **`2ee4813`** — **last commit with serve.py** (parent of the A2a deletion
     `abb7e0c`/#7): newest features, but the 9.6 refactor `446e627` had already moved
     `scanner.py` / `leaderboard.json` / `reports/` to `acpsec_api/` + `data/`
     without repointing serve.py, so three import paths need fixing before it runs.
   Cross-service refs auto-cleaned (`RAILWAY_SERVICE_WEB_URL` dropped from api-prod).
3. **RESOLVED (2026-07-27) — the entire staging line is DELETED.** All three
   pieces are gone: the `web-staging` Railway service, the `deploy/staging` git
   branch (remote **and** local), and the `acp-sec-app` Vercel project at
   `staging.acpsec.app` (plus its DNS record). Basis for deletion: zero *remote*
   branch divergence, no organic traffic (bots/scanners only), no unique config,
   an idle container burning trial credit. **Caveat surfaced during teardown:**
   the remote-only divergence checks (`origin/main..origin/deploy/staging`) could
   not see that the **local** `deploy/staging` ref held one unpushed commit — a
   comment-only b20 mainnet-activation fix — which was rescued to `main` via
   **PR #12** *before* the branch was force-deleted. `staging.acpsec.app` is also
   dropped from the default CORS allowlist (this PR). **There is no staging /
   pre-prod rehearsal environment now** — main-targeted changes go straight to
   `api-prod`.
4. **Railway `checkSuites` reports `true` on api-prod but does NOT gate.**
   Verified empirically: for `abb7e0c` the Railway build started 18:10:36Z,
   ~28s **before** the GitHub Actions run went green (18:11:04Z). A merge to
   `main` deploys api-prod **immediately, ungated** — the manual redeploy is the
   only real safeguard. Don't trust the flag.

## Notes for next session
- gh CLI active account drifted to `claudyaaprilia123-cmd` (no write access)
  mid-session, causing 403s on merge/push; switched back to `acpsec` (authorized).
  git authorship stayed correct (`acpsec <turkvengeance@gmail.com>`) throughout.
  UI merge failures were incomplete "Confirm squash and merge" clicks, NOT
  permissions.
- Railway CLI is authenticated (`acpsec`) and the repo is linked to project
  `sublime-truth` — read-only queries (deployments, `repoTriggers`, build logs)
  work directly.
