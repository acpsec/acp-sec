"""If this module is ever imported or exec'd, it drops a sentinel file.

A passing never-executes test proves the scanner parsed this statically (e.g.
via ast.parse) and never imported/ran it — module-level code like this executes
on import, so importlib-based parsing would trip the sentinel.
"""

from pathlib import Path

# Module-level side effect — runs on import or exec.
(Path(__file__).parent / "SENTINEL_EXECUTED_PY").write_text("executed")
