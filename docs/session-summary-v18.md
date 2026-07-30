# Session Summary v18 — Migration Groups 1–9 COMPLETE; F1 shipped

> Seed for a fresh chat. Written from verified repo + live-Railway state
> (2026-07-26). Supersedes v17. Facts re-checked this session, not carried
> forward — the lineage drifted once before.

## Ground truth at v18

> ⚠️ **Point-in-time snapshot — verify, don't trust.** The HEAD / deployment /
> test facts in this section are as of **2026-07-29** (re-verified live that day;
> this section has been amended several times since the 2026-07-26 write). They
> drift on every merge and redeploy — before relying on any SHA or deployment ID
> below, re-check it (`git log origin/main -1`, `railway status`) rather than
> trusting this text.

- **acp-sec** `main` HEAD: **`043a304`** (#15, "wire api-prod to install from the
  compiled lock") — snapshot-date value; advances on every merge, including this
  doc's own.
- **Full pytest suite: 1150 passed / 2 skipped** (flask uninstalled locally,
  mirrors the clean CI runner). The 2 skips are the B20 live-RPC tests
  (skipif-gated on `B20_LIVE_RPC`).
- **CI:** GitHub Actions pytest gate on push/PR to `main` (`.github/workflows/ci.yml`),
  ubuntu-latest, Python 3.12, `checkout@v7`/`setup-python@v7`, installs
  **from the compiled dev lock** (`pip install -r requirements/dev.txt` +
  `pip install -e . --no-deps`, #14) and **asserts every prod-lock pin == the
  installed version** each run (#16). (Earlier it installed `.[dev,api]`; the
  flask install + `import dashboard.serve` guard were removed in A2a.) Branch
  protection on `main`: requires the `test` check, strict, no reviews,
  admin-bypass on.
- **Prod:** Railway project `sublime-truth`, env `production`. `api-prod`
  (FastAPI, tracks `main`) runs commit **`043a3045`** (deployment `2abd0c56`,
  Online, `/api/health` 200) — snapshot-date value; changes on each deploy/redeploy.

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

**Result: api-prod runs with no Flask stack** — `flask`, `gunicorn`, `werkzeug`,
`itsdangerous`, `blinker` are gone from the build. (At v18 write time deps came
from `pip install '.[api]'` + pyproject base; as of 2026-07-29 the buildCommand
is lock-based — see Open-item #1.)

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

1. **RESOLVED (2026-07-29) — prod builds are now reproducible for runtime deps
   (compiled lockfile).** Was: no lockfile → every build re-resolved from floors
   (observed drift: **fastapi 0.139.2 → 0.140.0 → 0.140.7 → 0.140.10** across
   ungated rebuilds). Fixed across three PRs: **#14** added the compiled locks
   (`requirements/prod.txt`, base+api, 38 pins; `requirements/dev.txt`, 44);
   **#15** wired api-prod's buildCommand to `pip install -r requirements/prod.txt
   && pip install . --no-deps` and added `requirements/prod.txt` to
   `watchPatterns`; **#16** added a CI step that asserts every prod-lock pin ==
   the installed version on every run (fails the build otherwise — proven to
   bite). **Verified in prod:** two consecutive builds on the SAME commit
   `043a3045` (`1c9db8aa` = the #15 merge, `2abd0c56` = a `railway redeploy`)
   installed **identical versions across all 38 locked packages** — empty diff.
   The lock-phase visibly corrects floor drift: build A's auto-phase floated
   `anthropic 0.120.2`, the lock pinned it back to `0.120.0`.
   **Scope boundary (honest):** only *runtime* deps are locked. NIXPACKS's
   auto-phase still floor-resolves **build tooling**
   (`build`/`setuptools`/`packaging`/`pyproject_hooks`) *before* the lock-phase
   pins the runtime set on top — that tooling is not covered by the lock (PEP517
   build infra, not an app import). **Methodology (for whoever re-runs this
   check):** diff the **lock-phase provenance lines** (`Collecting X==` +
   `Requirement already satisfied: X==`, both tagged `(from -r
   requirements/prod.txt)`), **not** the `Successfully installed` lines — build B
   hit a warm pip cache (222 vs 511 log lines), so a naive `Successfully
   installed` diff shows spurious differences while the pinned versions are in
   fact identical.
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
   dropped from the default CORS allowlist (PR #13). **There is no staging /
   pre-prod rehearsal environment now** — main-targeted changes go straight to
   `api-prod`.
4. **Railway `checkSuites` reports `true` on api-prod but does NOT gate.**
   Verified empirically: for `abb7e0c` the Railway build started 18:10:36Z,
   ~28s **before** the GitHub Actions run went green (18:11:04Z). A merge to
   `main` deploys api-prod **immediately, ungated** — the manual redeploy is the
   only real safeguard. Don't trust the flag.
5. **Secrets baked into image layers — INVESTIGATED (2026-07-30), accepted as a
   low-severity residual.** The original framing (below) was partly wrong; what
   the investigation actually found:
   - **It's the mechanism, not those two names.** NIXPACKS emits a single `ARG`
     (line 11) + `ENV` (line 12) block for *every* variable Railway passes to the
     build; the Docker linter's `SecretsUsedInArgOrEnv` only *warns* on names
     matching its secret heuristic (password/token), so only `LEADERBOARD_PASSWORD`
     and `SCANNER_TOKEN` are flagged — while `CORS_ALLOWED_ORIGINS` + the 11
     `RAILWAY_*` vars are baked the same way, just unflagged (non-secret names).
   - **Values persist in the final image, not a traceless build-time ARG.** The
     build is single-stage (`stage-0` only), so the `ENV` at line 12 is in the
     final image config — retrievable via `docker inspect` by anyone with pull
     access to Railway's **private** registry. (Determined structurally from the
     Dockerfile shape; NOT verified by pulling the private image.)
   - **Railway has NO native build-vs-runtime variable scoping** (CLI-confirmed:
     `railway variable` is only list/set/delete; no sealed / build-exclude flag),
     and `railway.prod.json` has no `build.args`. So the original note — "keep them
     as Railway *runtime* env vars, not baked at build" — **was wrong: that control
     does not exist.** The only real fix is a custom Dockerfile with BuildKit
     build-secrets, which abandons NIXPACKS and unwinds the lockfile buildCommand.
   - **The build doesn't need them:** all three reads are runtime handlers
     (`leaderboard.py`, `health.py`, `scanner_auth.py`, via `os.environ`); the
     buildCommand (`pip install …`) and the setuptools backend read neither.
   - **Decision: accepted as a low-severity residual.** Marginal exposure is
     near-zero — anyone who can pull the image can already read the variables in
     the Railway dashboard. The one real residual: **stale values persist in old
     image history after a rotation.** So *if an image is ever treated as
     compromised, rotate BOTH secrets AND prune the old images* — runtime reads,
     so a Railway **restart** applies new values (not a rebuild), keeping
     `SCANNER_TOKEN` in lockstep with the frontend's `NEXT_PUBLIC_SCANNER_TOKEN`.

   *(Original framing, kept for the record — the ARG/ENV `SecretsUsedInArgOrEnv`
   warnings for `LEADERBOARD_PASSWORD`/`SCANNER_TOKEN` are real, but the fix
   proposed here — "keep as runtime env / use Docker build secrets" — overstated
   what Railway supports natively.)*
6. **RESOLVED (2026-07-30) — identity hygiene.** Four identities coexist (gh:
   `acpsec`/`fdlr28`/`claudyaaprilia123-cmd`; Railway: `turkvengeance` /
   `cryptosun81`), all in active use — drift is structural, so **pinned rather than
   removed**. What actually shipped (superseding the original "repo-local gh /
   Railway CI token" guess):
   - **acp-sec push pinned via SSH host-alias** `github-acpsec` → key
     `~/.ssh/id_ed25519_acpsec`, independent of gh's active account **by
     construction** (SSH bypasses the credential helper; verified with gh switched
     to `fdlr28`). Rollback: `git remote set-url origin https://github.com/acpsec/acp-sec.git`.
   - **gh operations still follow the active account** — no per-repo gh pin exists
     (gh config is global-only; `GH_TOKEN`/`GH_CONFIG_DIR` rejected). Pre-flight =
     the `git who` global alias (prints `git author | gh active`).
   - **Global git identity cleared + `user.useConfigOnly=true`** → repos without an
     explicit local identity **hard-refuse** commits. (Clearing global alone was
     NOT enough — git auto-detected `Fadhlan@hostname`; `useConfigOnly` forces the
     refusal.) acpsec-family + hoodstate pinned; fdlr28 repos deliberately left to
     refuse until pinned to a fdlr28 email.
   - The Railway **project-token-for-CI** idea was **dropped** (this repo's CI
     doesn't use the Railway CLI; a prod-scoped token in a profile isn't worth it).
     Full detail: the `identity-git-push-pinning` memory.
7. **SentryAgent chat is DEAD in prod (verified 2026-07-30) — an upstream spend
   cap is the real bound.** `ANTHROPIC_API_KEY` is unset on api-prod, so
   `POST /api/chat/sentryagent` returns **503** (`AI chat not configured`) — env
   is checked before any Claude call (`chat.py:77`). **Not a migration
   regression:** the 2026-07-16 web-stop audit shows the key was **Unset on the
   old Flask `web` too** (chat 503 there as well); 9B set the other two secrets on
   api-prod but missed this one, so it has been 503 the whole time on both stacks.
   - **User-reachable:** `acpsec.app/agents/sentryagent` is live (HTTP 200) and
     wired to the endpoint (`src/app/agents/sentryagent/page.tsx` → `useChat` →
     `chatSentryAgent` → `POST /api/chat/sentryagent`), so real visitors hit the
     broken chat. `docs/prod-env-inventory.md` lists the key as **required** in
     prod — the intent was "chat on."
   - **⚠️ The endpoint is UNGATED.** Unlike `/api/scanner/*` and `/api/onchain/*`
     (which use `Depends(require_scanner_access)`), chat has **no auth gate** —
     only `Depends(get_anthropic_client)`. CORS is browser-enforced only (a
     `curl`/script ignores it), and the frontend's `X-Scanner-Token` is added only
     for the `/api/scanner/` + `/api/onchain/` prefixes, **not** chat. There is
     **no rate limiting** anywhere. So setting the key on the endpoint as-is makes
     it a **public, ungated Claude proxy — anyone can loop it and drain credits.**
   - **Per-call cost IS bounded** (model pinned `claude-sonnet-4-6`, `max_tokens`
     1024, history capped to 20 messages × 4000 chars) — a single call is cheap;
     the unbounded axis is **call volume**.
   - **Lightest bound (reuses existing code):** add `Depends(require_scanner_access)`
     to the chat route (backend one-liner) **and** add `/api/chat/` to the
     frontend's `SCANNER_TOKEN_PREFIXES` in `client.ts` (frontend one-liner) so the
     browser keeps working. ⚠️ Caveat: `NEXT_PUBLIC_SCANNER_TOKEN` is **public**
     (inlined in the client bundle), so this is a **speed-bump** — it stops
     anonymous `curl` abuse but a determined caller can read the token from the
     bundle and replay it. Real cost protection needs per-IP rate limiting (not in
     the codebase) or proper auth.
   - **The real spend bound is UPSTREAM, not the app gate (verified 2026-07-30).**
     The Anthropic Console supports **per-Workspace monthly spend limits + per-Workspace
     rate limits** (RPM/ITPM/OTPM) — a key created in a dedicated **non-default**
     Workspace is hard-capped by them regardless of the app ("API usage pauses"
     once the cap is hit); the tier also carries an org-wide monthly spend cap
     (Start = $500). And **nothing upstream limits request volume:** the frontend
     calls Railway **directly** (`NEXT_PUBLIC_API_URL`; no `vercel.json`/next
     rewrite), and Railway exposes no rate-limit knob. **So the sequence inverts to:
     set a Workspace spend+rate cap → set the key in that Workspace → gate at
     leisure** — the scanner-token gate (and/or slowapi) become defense-in-depth,
     not the sole bound. The fix is Fadhlan's (prod-scoped key); or hide
     `/agents/sentryagent` if chat isn't meant to be live. *slowapi* is feasible for
     the app-side limit (FastAPI-native; the chat route already takes
     `request: Request`; in-memory storage is fine for the single Railway replica —
     needs Redis if scaled, and an `X-Forwarded-For` `key_func` to see real client
     IPs behind Railway's proxy), but it touches the lockfile (recompile).
   - **Testing lesson:** the golden-contract tests (A1) could not catch this —
     "503 when `ANTHROPIC_API_KEY` unset" **is** the contract they froze (`chat.py`
     mirrors Flask's 503 exactly). A frozen contract verifies the code path, not
     whether the prod environment satisfies its precondition; catching this needs
     an env-presence / live-smoke check, a different class of test.

## Notes for next session
- gh CLI active account drifted to `claudyaaprilia123-cmd` (no write access)
  mid-session, causing 403s on merge/push; switched back to `acpsec` (authorized).
  git authorship stayed correct (`acpsec <turkvengeance@gmail.com>`) throughout.
  UI merge failures were incomplete "Confirm squash and merge" clicks, NOT
  permissions.
- Railway CLI auth drifts across accounts (see Open-item #6); a re-auth cleared
  the project link (`railway status` → "No linked project found"). Pass
  `-p <project> -e production -s api-prod` explicitly on `railway` commands (or
  re-run `railway link`) rather than assuming a linked project.
