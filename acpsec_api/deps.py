"""Dependency-injection wiring for acpsec_api.

Exposes providers consumed by routers via FastAPI's ``Depends``. Tests override
these (``app.dependency_overrides``) to inject isolated, temp-backed instances.

Process-wide singletons (``lru_cache``): the per-visitor score store, the
leaderboard store and the leaderboard session store.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from typing import Any, Callable, Optional

from acpsec_api.leaderboard_store import LeaderboardStore
from acpsec_api.scanner_lookup import SCRAPER_AVAILABLE, scrape_x_profile
from acpsec_api.sessions import LbSessions
from acpsec_api.store import SessionScoreStore

# Default reports directory (data/reports), holding the seeded report files
# read by /api/report.
DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent.parent / "data" / "reports"


@lru_cache
def get_score_store() -> SessionScoreStore:
    """Process-wide per-visitor score store (one slot per score_session cookie)."""
    return SessionScoreStore()


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


def get_scanner_engine() -> Optional[Any]:
    """The heuristic scan engine (``acpsec_api/scanner.py``), or None if unavailable.

    The engine is ~2,400 lines with external network fetches; it lives in
    ``acpsec_api`` (Group 9.6 relocation) as the single source of truth. Mirrors
    the Flask ``_get_scanner()`` contract (None → the endpoint returns 503).
    Pinned by ``tests/test_scanner_engine.py``; mocked in the router tests.
    """
    try:
        from acpsec_api import scanner

        return scanner
    except ImportError:
        return None


def get_onchain_checker() -> Optional[Callable[..., dict]]:
    """The on-chain ACP registration checker, or None if acpsec.onchain is absent.

    Mirrors Flask's inline ``from acpsec.onchain import check_acp_registration``
    guarded by ImportError → the endpoint returns 503. Tests override this to
    inject a mock checker so NO live Base RPC call is ever made by the suite.

    The returned callable has the signature
    ``check_acp_registration(wallet, *, rpc_url=None) -> dict`` and never raises.
    """
    try:
        from acpsec.onchain import check_acp_registration
    except ImportError:
        return None
    return check_acp_registration
