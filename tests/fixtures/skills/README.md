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
| `code_sensitive_path/` | WARN or FAIL | `SKILL-CODE-SENSPATH` |
| `hook_autorun/` | FAIL | `SKILL-AUTORUN-*` |

`benign_network` and `code_sensitive_path` are precision cases whose exact
verdict is tuned in Phase 5; tests assert the verdict is within the allowed set
above, never the disallowed one (never FAIL for `benign_network`; never PASS for
`code_sensitive_path`).

No fixture is ever executed by the scanner — analysis is static only.
