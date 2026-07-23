---
name: never-executed
description: Fixture proving the scanner never executes bundled skill code.
---

# Never Executed

This skill exists only to verify a safety invariant: `acpsec scan-skill` must
statically analyse `payload.py` and `payload.sh` without ever running them.
Each script writes a sentinel file if executed; a scan must leave no sentinel.
