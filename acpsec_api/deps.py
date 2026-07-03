"""Dependency-injection wiring for acpsec_api.

Exposes providers consumed by routers via FastAPI's ``Depends``. Tests override
these (``app.dependency_overrides``) to inject isolated, temp-backed instances.

Group 2 continues filling this in (config, acpsec scorer access). For 2.3a it
provides the singleton ScoreStore backing the score read endpoints.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from typing import Callable, Optional

from acpsec_api.leaderboard_store import LeaderboardStore
from acpsec_api.scanner_lookup import SCRAPER_AVAILABLE, scrape_x_profile
from acpsec_api.sessions import LbSessions
from acpsec_api.store import ScoreStore

# Default reports directory = the SAME path Flask uses (dashboard/reports),
# so /api/report reads the pre-existing seeded report files.
DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent.parent / "dashboard" / "reports"


@lru_cache
def get_score_store() -> ScoreStore:
    """Process-wide ScoreStore singleton (default disk-backed path).

    ``lru_cache`` gives one shared instance so the in-memory cache persists
    across requests — matching Flask's module-level ``_current_score``.
    """
    return ScoreStore()


@lru_cache
def get_leaderboard_store() -> LeaderboardStore:
    """Process-wide LeaderboardStore singleton (default disk-backed path)."""
    return LeaderboardStore()


@lru_cache
def get_lb_sessions() -> LbSessions:
    """Process-wide leaderboard session store (in-memory, matches Flask)."""
    return LbSessions()


def get_reports_dir() -> Path:
    """Directory holding full-scan report files. Overridden in tests."""
    return DEFAULT_REPORTS_DIR


def get_profile_scraper() -> Optional[Callable[[str], dict]]:
    """The X/Twitter profile scraper, or None if its deps are unavailable.

    Mirrors Flask's ``_get_scanner()``: None → the endpoint returns 503.
    Tests override this to inject a mock scraper (no live network).
    """
    return scrape_x_profile if SCRAPER_AVAILABLE else None
