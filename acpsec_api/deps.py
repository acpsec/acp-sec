"""Dependency-injection wiring for acpsec_api.

Exposes providers consumed by routers via FastAPI's ``Depends``. Tests override
these (``app.dependency_overrides``) to inject isolated, temp-backed instances.

Group 2 continues filling this in (config, acpsec scorer access). For 2.3a it
provides the singleton ScoreStore backing the score read endpoints.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from typing import Any, Callable, Optional

from acpsec_api.leaderboard_store import LeaderboardStore
from acpsec_api.scanner_lookup import SCRAPER_AVAILABLE, scrape_x_profile
from acpsec_api.sessions import LbSessions
from acpsec_api.store import ScoreStore

# Default reports directory = the SAME path Flask uses (dashboard/reports),
# so /api/report reads the pre-existing seeded report files.
DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent.parent / "dashboard" / "reports"

# Default last-scan store file — same path Flask uses (dashboard/scan_store.json).
# Write-only (nothing reads it); replicated for side-effect parity.
DEFAULT_SCAN_STORE = Path(__file__).resolve().parent.parent / "dashboard" / "scan_store.json"


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


def get_scanner_engine() -> Optional[Any]:
    """The heuristic scan engine (dashboard/scanner.py), or None if unavailable.

    APPROVED EXCEPTION to the no-dashboard-import rule (Task 2.5b-i): the engine
    is 2,380 lines with external network fetches — importing it keeps a single
    source of truth rather than duplicating it. Mirrors Flask's ``_get_scanner()``
    (None → the endpoint returns 503). Mocked in all tests, so this import path
    is never exercised by the suite.
    """
    try:
        from dashboard import scanner

        return scanner
    except ImportError:
        return None


def get_scan_store_path() -> Path:
    """Path for the best-effort last-scan write. Overridden in tests."""
    return DEFAULT_SCAN_STORE


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


def get_anthropic_client() -> Optional[Any]:
    """The Anthropic API client, or None if AI chat is unavailable.

    Returns None when ANTHROPIC_API_KEY is unset OR the ``anthropic`` package is
    not installed — mirroring Flask's two inline guards. The chat router checks
    the env var FIRST, so a None with the key present unambiguously means the
    import failed (which maps to Flask's distinct 503 messages).

    Constructing the client does no network I/O. Tests override this to inject a
    fake client, so NO live Claude API call is ever made by the suite.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None
    return anthropic.Anthropic(api_key=api_key)
