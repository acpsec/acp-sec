"""Score state store — FastAPI port of the Flask persistence model.

Mirrors ``dashboard/serve.py`` exactly: a single in-memory cache backed by a
JSON file on disk. Reads prefer the in-memory value and fall back to disk;
writes are write-through (memory + disk); clear drops both.

Persistence semantics (matched to Flask):
  * get()   -> in-memory value if set, else load from disk, else None
  * set()   -> update memory AND write to disk (best-effort, silent on OSError)
  * clear() -> memory None AND unlink the file (missing_ok)

Thread-safety: Flask used a module-level dict with NO locking, so concurrent
requests could interleave read/modify/write. This class replicates that
behaviour (no locks) rather than papering over it — the gap is inherited, not
introduced. Revisit if/when the API moves to a real concurrent workload.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Default path: <repo>/acpsec_api/store.py → <repo>/data/score_store.json
_DEFAULT_STORE_FILE = Path(__file__).resolve().parent.parent / "data" / "score_store.json"


class ScoreStore:
    """In-memory cache + JSON-file persistence for the current score."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else _DEFAULT_STORE_FILE
        self._current: dict[str, Any] | None = None

    def get(self) -> dict[str, Any] | None:
        """Return the current score: memory → disk → None."""
        return self._current or self._load_from_disk()

    def set(self, data: dict[str, Any]) -> None:
        """Cache and persist a score (write-through)."""
        self._current = data
        self._save_to_disk(data)

    def clear(self) -> None:
        """Drop the in-memory cache and remove the persisted file."""
        self._current = None
        if self.path.exists():
            self.path.unlink(missing_ok=True)

    # -- disk helpers (match Flask's best-effort, silent-on-failure behaviour) --

    def _load_from_disk(self) -> dict[str, Any] | None:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError):
                return None
        return None

    def _save_to_disk(self, data: dict[str, Any]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, indent=2, default=str))
        except OSError:
            pass
