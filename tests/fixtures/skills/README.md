# scan-skill test fixtures

Each subfolder is a complete, realistic agent-skill folder used by the
`acpsec scan-skill` test suite. Expected verdicts and the finding id that each
fixture must surface:

| Fixture | Verdict | Key finding id(s) |
|---|---|---|
| `benign_basic/` | PASS | — (no finding ≥ MEDIUM) |
| `benign_network/` | PASS or WARN | `SKILL-CODE-NET` (declared domain → LOW/INFO) |
| `benign_security_doc/` | PASS | — (attack phrasings are quoted/fenced, not directives) |
| `inj_exfil/` | FAIL | `SKILL-INSTR-EXFIL` |
| `inj_hidden/` | FAIL | `SKILL-INSTR-HIDDEN` |
| `inj_override/` | FAIL | `SKILL-INSTR-OVERRIDE` (+ `SKILL-INSTR-SECRECY`) |
| `code_obfuscated/` | FAIL | `SKILL-CODE-OBFUS` (+ `SKILL-MANIFEST-02` for unreferenced `run.sh`) |
| `code_netexfil/` | FAIL | `SKILL-CODE-NET` (exfil sink) + `SKILL-CODE-ENVEXFIL` |
| `code_sensitive_path/` | FAIL | `SKILL-CODE-SENSPATH-KEY` (Tier A, HIGH) |
| `hook_autorun/` | FAIL | `SKILL-AUTORUN-*` |

`benign_network` is a precision case whose exact verdict is tuned in Phase 5
(never FAIL). `SKILL-CODE-SENSPATH` is split into two tiers: **Tier A**
(`-KEY`, private-key / live-credential material) is HIGH and fails on its own;
**Tier B** (`-CFG`, ambiguous config such as bare `.env` / `~/.aws/config`) is
MEDIUM alone and escalates to HIGH only via the SENSPATH+NET / ENVEXFIL combo.
`code_sensitive_path` reads `id_rsa` + `~/.aws/credentials` + gcloud creds →
Tier A present → verdict FAIL.

No fixture is ever executed by the scanner — analysis is static only.
