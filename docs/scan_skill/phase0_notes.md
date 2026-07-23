# Phase 0 — Discovery notes: `acpsec scan-skill`

Feature **F1 (`scan-skill`)**. Read-only inventory of the existing pipeline and
the interfaces this feature will reuse or extend. Branch `feat/scan-skill` off
`main` (tip `e787938`). Baseline: `1122 passed, 2 skipped` (24.4s).

## Package root

`acpsec/` (installed as `acpsec`, console script `acpsec = acpsec.cli:main`,
click-based). Python `>=3.12`. Relevant modules:

```
acpsec/
  cli.py            click group `main`; commands: check, inject, report,
                    monitor (group), trust-score
  models.py         Pydantic models + Severity / CheckStatus enums
  config_loader.py  YAML → AgentConfig (env-var expansion)
  scorer.py         ScoringEngine, make_check(), bands, penalties
  reporter.py       rich terminal + save_json()
  catalogue.py      static check metadata (no live probes)
  injection/        payloads.py + runner.py (LIVE attack suite)
  checks/           12 dimension modules (auth, context, …, hook, plugin)
  trust_score/      separate on-chain trust-scoring subsystem
```

## 1. How a check is registered & executed (`checks/`)

Not a registry/decorator system — it's **explicit functions**. Each dimension
module exposes `run_<dim>_checks(config, client) -> DimensionResult`. Internally
it builds a `list[CheckResult]` via the `make_check(...)` helper
(`scorer.py:268`), asserts the per-dimension max-score consistency contract
(`sum(max_score) == DIMENSION_WEIGHTS[DIM]`), sums scores, and returns a
`DimensionResult`. `cli.py` wires runners through the `DIMENSION_RUNNERS` /
`OPTIONAL_DIMENSION_RUNNERS` dicts and appends each `DimensionResult`.

`make_check(check_id, name, dimension, severity, max_score, passed, evidence=[],
recommendations=[], details={}, partial_score=None)` → `CheckResult`. `passed`
⇒ PASS/full; `partial_score>0` ⇒ WARN/partial; else FAIL/0.

**Implication for F1:** the scan-skill layers (manifest / instruction / code)
should each emit `CheckResult`s via `make_check` and roll up into
`DimensionResult`s so scoring + reporter reuse is free. But note: existing
checks require a live `AgentClient`. Skill scanning is **static** — the code
layer and manifest layer take no client; the instruction layer detects patterns
*in text* rather than sending probes (see §2 mismatch).

## 2. Input/output of `injection/` detection — INTERFACE MISMATCH

`injection/runner.py::InjectionRunner.run()` is an **active** tester: it *sends*
each `Payload` to a live agent via `AgentClient.send()` and evaluates the
*response* for `success_signals`. Output: `InjectionSuiteResult`.

Skill scanning needs the **inverse**: static detection of malicious authoring
*inside* the SKILL.md text — no agent, no response. So:

- **Reusable:** the payload *taxonomy* (`payloads.py` categories A–F:
  direct_override, role_confusion, indirect, encoded, multiturn, extraction)
  and the phrasings themselves as seed regexes.
- **NOT reusable as-is:** `InjectionRunner` (needs a live client),
  `success_signals` (they detect a compromised *response*, not malicious source).
- **New code needed:** a static instruction-scanner that pattern-matches the
  SKILL.md body/description and emits findings with `file:line` evidence. Place
  under `injection/` (e.g. `injection/skill_patterns.py` + a static scan fn) to
  keep the taxonomy co-located.

## 3. Scoring aggregation & severity levels (`scorer.py`)

- `Severity` enum (`models.py:11`): **CRITICAL, HIGH, MEDIUM, LOW, INFO**.
- `CheckStatus` (`models.py:20`): pass, fail, warn, skip, error.
- `ScoringEngine.score_dimension` sums check scores; `build_assessment` sums
  dimensions, applies penalties (`CRITICAL_PENALTY=-5` each; custodial / fund-
  transfer caps — agent-specific, not relevant to skills), computes `score_pct`,
  maps to a band via `band()`. Bands are percentage thresholds:
  EXEMPLARY 90 / SECURE 70 / HARDENED 50 / VULNERABLE 30 / CRITICAL 10 /
  COMPROMISED 0.
- There is a **second** scorer in `trust_score/` (on-chain agent trust,
  `Finding{dim,severity,detail}` with severities CRITICAL/High/Medium/Low). It's
  purpose-built for ERC-8004/on-chain data and is **not** the right fit for a
  local static skill scan.

**Decision for F1 (Phase 5):** reuse the **main** `scorer.py` conventions
(Severity + CheckResult + make_check). The spec's PASS/WARN/FAIL verdict maps
cleanly onto CheckStatus and severity: PASS = nothing ≥ MEDIUM; WARN = MEDIUM
present, none HIGH/CRITICAL; FAIL = any HIGH/CRITICAL. This is a *verdict*
derived from findings, distinct from the numeric percentage band. Thresholds
will live in a small config constant block (per spec "thresholds in config, not
hardcoded"), mirroring how `scorer.py` centralises `SCORE_BANDS`/weights.

## 4. How `reporter.py` formats results; JSON output?

`reporter.py` renders `AssessmentResult` with rich `Panel` + per-dimension
`Table` (`print_assessment`) and has `save_json(result, path)` →
`json.dumps(model.model_dump(), default=str)`. So **JSON output already exists**
for the assessment model. For scan-skill we add a dedicated
`print_skill_scan()` (findings grouped by layer, each with `file:line`) and a
stable `--json` schema. `console.print_json` is already used by `report`.

## 5. CLI entry — exists

`cli.py` is a click group (`main`). Adding `acpsec scan-skill <path> [--json]`
is a new `@main.command("scan-skill")`. **No new dependency needed** (click +
rich already present). Exit codes: click commands call `sys.exit(...)`
directly (see `report` at cli.py:420). We'll set 0=PASS, 1=WARN, 2=FAIL.

## 6. `checks/hook.py` is NOT skill-hook detection

`checks/hook.py` covers **ERC-8183 Solidity hook *contracts*** (FundTransferHook
.sol etc.), gated on `config.hook.enabled`. Unrelated to skill install/load
hooks (launchctl/cron/rc-file autorun). The `hook_autorun` fixture is therefore
detected by the **new code layer** (Phase 4), not this module. Naming overlap
only.

## 7. Realistic runtime expectation

Static scan of a typical skill folder (1 SKILL.md + a handful of small
scripts, < ~50 files, < ~5k LOC total): regex line-scan + optional Python `ast`
parse. Expectation: **well under 1 second** on the fixtures; **< 2 s** worst
case for a large skill. No network, no code execution, no LLM calls. This is the
runtime budget the Definition-of-Done will be checked against.

## Proposed module placement (for Phases 2–6)

- `acpsec/skill_manifest.py` (or extend `config_loader.py`) — `SkillManifest`
  parse (frontmatter + body + `files[]`). Spec says extend `config_loader.py`;
  will add a `load_skill_manifest(path)` there to honour "extend, not rebuild".
- `injection/skill_patterns.py` — static instruction-layer patterns + scan fn.
- `checks/skill_code.py` — new static-analysis engine (shell/py/js/ts).
- `acpsec/skill_scan.py` — orchestrator: manifest → instruction → code →
  findings → verdict/score (reuses ScoringEngine conventions).
- `reporter.py` — add `print_skill_scan()` + JSON schema.
- `cli.py` — `scan-skill` command.

## Interface mismatches vs. spec (summary)

1. **`injection/` is active, not static.** Spec says "feed the body through
   `injection/`". We reuse the *taxonomy* but must add a static detector; we
   cannot literally run `InjectionRunner` (it needs a live agent). Documented,
   adapting to the codebase.
2. **Two scorers.** Spec says "map through `trust_score/` + `scorer.py`". The
   right fit is `scorer.py` (+ `models.py` Severity/CheckResult). `trust_score/`
   is on-chain-specific; will not be used. Documented.
3. **`config_loader.py` is YAML/AgentConfig-shaped.** SKILL.md is markdown +
   YAML frontmatter — a genuinely new parse target, added alongside (not
   replacing) `load_config`.
4. **`checks/hook.py`** naming collision — not reusable for skill autorun hooks.

## Approved amendments (post-Phase-0 review)

1. **Scoring — leaf primitives only.** Reuse `Severity`, `CheckStatus`,
   `CheckResult`, `make_check`. Do **not** build `DimensionResult` /
   `AssessmentResult`, do **not** add a `DIMENSION_WEIGHTS` entry (the max-score
   contract + agent-specific penalties in `build_assessment` don't apply to
   skills). Emit a new **`SkillScanResult`** model grouped by layer
   (manifest / instruction / code); that model defines the stable `--json`
   schema.
2. **Injection taxonomy is a seed, not the rule set.** Categories A–F seed only
   the override / extraction rules. Secrecy directives, scope escalation, and
   hidden/encoded content have no payload analogue — written directly from the
   Phase 3 list.
3. **10th fixture `benign_security_doc/`** — a skill that legitimately documents
   injection patterns (attack phrasings inside fenced code blocks / block
   quotes). Expected **PASS**. Instruction-layer rules must be **quote/fence-
   aware**: a documented example is not a directive.
4. **Autorun rule ids `SKILL-AUTORUN-*`** (not `SKILL-HOOK-*`) to avoid
   collision with the ERC-8183 HOOK dimension.
5. **Phase 7:** verify the actual latest session-summary version (don't assume
   v17) and report what the `9.x` series on `main` refers to before writing.
