# scan-skill dogfood results

Ran `acpsec scan-skill` against three real, locally-installed public skills on
2026-07-23. Raw JSON outputs are alongside this file.

| Skill | Verdict | Score | Findings |
|---|---|---|---|
| `graphify` (`~/.claude/skills/graphify`) | PASS | 100 | — |
| `vercel/deploy` (official plugin) | PASS | 100 | — |
| `ui-ux-pro-max/ui-styling` | WARN | 76 | 2× `SKILL-MANIFEST-02` |

Files: [`dogfood-graphify.json`](dogfood-graphify.json),
[`dogfood-vercel-deploy.json`](dogfood-vercel-deploy.json),
[`dogfood-ui-styling.json`](dogfood-ui-styling.json).

## What the dogfood caught

**`ui-styling` (WARN)** — two bundled test scripts
(`scripts/tests/test_shadcn_add.py`, `scripts/tests/test_tailwind_config_gen.py`)
are shipped in the skill folder but never referenced in `SKILL.md`. This is a
real, defensible signal: unreferenced executables are how a malicious skill
smuggles a payload past a reviewer who only reads the manifest. MEDIUM → WARN is
the right altitude — it flags the file for review without failing an otherwise
clean skill.

## False positives found and fixed during dogfooding

An earlier rule pass flagged `graphify` as FAIL. Both were rule-precision bugs,
now fixed (commit "tighten secrecy/exfil rules after dogfooding false
positives") with regression tests:

1. **`SKILL-INSTR-SECRECY` on the bare word "silently".** graphify says "read it
   silently and present a summary" — an operational instruction to avoid dumping
   verbose output, not concealment from the user. Fixed: "silently" now only
   counts when tied to the user (`silently … from/without/so the user`);
   `secretly`/`covertly` were added as the standalone signals instead.
2. **`SKILL-INSTR-EXFIL` from a decoupled secret + output mention.** A
   `GEMINI_API_KEY` reference on one line and an unrelated "print the Usage
   section verbatim" on another combined into a false exfil finding because the
   sensitive-token check was document-global. Fixed: the sensitive token and the
   output-inclusion directive must now appear on the **same line**.

The trade-off is documented in the README: same-line matching is a
high-precision choice that can miss exfil phrasing split across multiple lines.
