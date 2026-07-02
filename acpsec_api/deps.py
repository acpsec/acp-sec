"""Dependency-injection wiring for acpsec_api.

Exposes providers consumed by routers via FastAPI's ``Depends``. Tests override
these (``app.dependency_overrides``) to inject isolated, temp-backed instances.

Group 2 continues filling this in (config, acpsec scorer access). For 2.3a it
provides the singleton ScoreStore backing the score read endpoints.
"""

from __future__ import annotations

from functools import lru_cache

from acpsec_api.store import ScoreStore


@lru_cache
def get_score_store() -> ScoreStore:
    """Process-wide ScoreStore singleton (default disk-backed path).

    ``lru_cache`` gives one shared instance so the in-memory cache persists
    across requests — matching Flask's module-level ``_current_score``.
    """
    return ScoreStore()
