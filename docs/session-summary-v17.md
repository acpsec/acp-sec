# Session Summary v17 — Feature F1: `scan-skill`

> Seed for a fresh chat. Written from verified repo state (git logs + full test
> run, 2026-07-23). Supersedes v16. The linear version lineage (v11…v17) is the
> single continuous spine and is independent of which *track* the work sits on.

**Status:** Feature **F1 (`scan-skill`)** complete on branch `feat/scan-skill`
(off `main`). Independent of the migration Group series — see Tracks below.

## Tracks

Two parallel tracks now share one version lineage:

- **Migration Groups (1–9.x)** — the bounded deploy/cutover epic. Groups 1–8
  closed at v16 (Group 8 = staging deploy). Group **9.x** (production cutover:
  9C web decoupling, 9.6 scanner-engine relocation out of the Flask tree,
  Railway repointing, rollback recipes) lives on `deploy/staging` / `main` and
  is **not** part of F1. Untouched by this session.
- **Features (F1…)** — new capability work parallel to the migration. This
  session opens the track with **F1: `scan-skill`**. It is deliberately *not*
  labeled "Group 9" — that number already denotes migration work on `main`, so
  reusing it would falsely imply a dependency on Group 8.

## Ground truth at v17

### acp-sec (backend)
- Branch: `feat/scan-skill`, based on `main` @ `e787938`.
- HEAD: `eff2c31`. 11 commits, all authored `acpsec`.
- **Full pytest suite: 1166 passed / 2 skipped** (~28 s). Baseline before F1
  was 1122 passed / 2 skipped; F1 added **44 tests** across 6 modules.
- `scan-skill` runtime on a real skill: **~0.36 s** (well under the <1 s budget
  set in Phase 0).
- **Zero changes to Group 8 / deploy files** — F1 touched only new files plus
  additive edits to `models.py`, `config_loader.py`, `reporter.py`, `cli.py`,
  `README.md`.

### What F1 shipped

`acpsec scan-skill <path> [--json]` — a static, pre-install security audit for
agent skills (a `SKILL.md` + optional bundled scripts). CLI-only by design; the
interception point is local, before `cp -R skill ~/.claude/skills/`. **Never
executes** anything in the skill folder.

New modules:
- `acpsec/config_loader.py::load_skill_manifest` → `SkillManifest` (frontmatter
  + body + file inventory).
- `acpsec/skill_manifest.py` — manifest-layer checks (`SKILL-MANIFEST-01/02`).
- `acpsec/injection/skill_patterns.py` — instruction-layer detection,
  quote/fence-aware (`SKILL-INSTR-EXFIL/OVERRIDE/SECRECY/SCOPE/FETCHEXEC/HIDDEN`).
- `acpsec/checks/skill_code.py` — code static analysis (`SKILL-CODE-*`,
  `SKILL-AUTORUN-*`); regex + light Python `ast`.
- `acpsec/skill_findings.py` — `make_finding()` (findings as `CheckResult`).
- `acpsec/skill_scan.py` — verdict + score derivation + orchestrator;
  `SkillScanResult` model is the stable `--json` schema.
- `acpsec/reporter.py::print_skill_scan` — grouped-by-layer human output.

Verdict logic: PASS (nothing ≥ MEDIUM) / WARN (mediums only) / FAIL (any
HIGH/CRITICAL). Exit codes 0/1/2. Score = 100 − severity deductions, fully
derivable from listed findings. Thresholds live in `skill_scan.py` constants.

### Design decisions worth remembering
- Reused **leaf primitives only** (`Severity`, `CheckStatus`, `CheckResult`,
  `make_check`/`make_finding`) — no `DimensionResult`/`AssessmentResult`, no
  `DIMENSION_WEIGHTS` entry (the max-score contract + agent penalties in
  `build_assessment` don't apply to skills).
- `injection/` is an **active** tester (sends payloads to a live agent);
  scan-skill needed the **inverse** (static detection in text), so the payload
  taxonomy seeded new static rules rather than reusing `InjectionRunner`.
- Used `scorer.py` conventions, **not** `trust_score/` (that subsystem is
  on-chain-specific).
- **SENSPATH split into two tiers** (reviewer decision): Tier A
  (`-KEY`, private-key/live-credential material) = HIGH → FAIL alone; Tier B
  (`-CFG`, ambiguous config like bare `.env`) = MEDIUM, escalates to HIGH only
  via the SENSPATH+NET / ENVEXFIL combo. Rationale: for an installable skill the
  dominant exfil channel is out-of-file, so gating FAIL on a same-file network
  sink under-catches raw key reads.
- Autorun rules prefixed `SKILL-AUTORUN-*` (not `-HOOK-*`) to avoid collision
  with the ERC-8183 HOOK dimension.

### Dogfooding
Scanned three real installed skills (`docs/scan_skill/dogfood-results.md`):
graphify PASS, vercel/deploy PASS, ui-ux-pro-max/ui-styling WARN (two bundled
test scripts unreferenced in `SKILL.md`). Dogfooding also surfaced and fixed two
instruction-rule false positives (bare "silently"; doc-global secret + `verbatim`
combining into a false EXFIL) — both now have regression tests.

### Known blind spots (documented in README)
Static-only: no runtime behavior, novel obfuscation, paraphrased injection
outside the rule set, **multi-line** exfil phrasing (same-line rule is a
precision choice), or compiled/fetched-at-runtime payloads. A PASS means "no
known-pattern red flags," not "proven safe."

## Next up (F1 follow-ons, all deferred)
- Optional `POST /api/skill/scan` endpoint reusing `scan_skill` core (Phase-0
  non-goal for v1).
- Filesystem watcher on `~/.claude/skills/` (non-goal for v1).
- Broaden code-layer coverage (multi-line exfil window; more obfuscation forms).
- Merge `feat/scan-skill` → `main` when ready (independent of Group 9.x).
