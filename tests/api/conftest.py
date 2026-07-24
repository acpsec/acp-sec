"""Shared fixtures for FastAPI endpoint tests.

Every endpoint is validated by direct contract assertions against the FastAPI
app. The legacy Flask byte-for-byte parity oracle (``dashboard/serve.py`` +
``assert_parity``) was retired with the Flask service; the contracts it pinned
are now frozen as golden-value assertions in the endpoint tests themselves.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from acpsec_api.deps import (
    get_lb_sessions,
    get_leaderboard_store,
    get_profile_scraper,
    get_reports_dir,
    get_scan_store_path,
    get_scanner_engine,
    get_score_store,
)
from acpsec_api.leaderboard_store import LeaderboardStore
from acpsec_api.main import app as fastapi_app
from acpsec_api.sessions import LbSessions
from acpsec_api.store import ScoreStore


@pytest.fixture
def fastapi_client() -> TestClient:
    """TestClient bound to the FastAPI app under migration."""
    return TestClient(fastapi_app)


@pytest.fixture
def temp_store(tmp_path: Path) -> ScoreStore:
    """A ScoreStore backed by a throwaway temp file (never the real store)."""
    return ScoreStore(path=tmp_path / "score_store.json")


@pytest.fixture
def isolated_client(temp_store: ScoreStore):
    """FastAPI TestClient whose ScoreStore dependency is overridden with a
    temp-backed store, so score-read tests never touch dashboard/score_store.json.

    Yields ``(client, temp_store)`` so tests can seed the store directly.
    """
    fastapi_app.dependency_overrides[get_score_store] = lambda: temp_store
    try:
        yield TestClient(fastapi_app), temp_store
    finally:
        fastapi_app.dependency_overrides.pop(get_score_store, None)


@pytest.fixture
def leaderboard_client(tmp_path: Path):
    """FastAPI TestClient with leaderboard store, reports dir, and sessions all
    overridden with temp-backed, isolated instances.

    Yields ``(client, lb_store, reports_dir, sessions)`` for direct seeding.
    """
    lb_store = LeaderboardStore(path=tmp_path / "leaderboard.json")
    reports_dir = tmp_path / "reports"
    sessions = LbSessions()

    fastapi_app.dependency_overrides[get_leaderboard_store] = lambda: lb_store
    fastapi_app.dependency_overrides[get_reports_dir] = lambda: reports_dir
    fastapi_app.dependency_overrides[get_lb_sessions] = lambda: sessions
    try:
        yield TestClient(fastapi_app), lb_store, reports_dir, sessions
    finally:
        for dep in (get_leaderboard_store, get_reports_dir, get_lb_sessions):
            fastapi_app.dependency_overrides.pop(dep, None)


@pytest.fixture
def scanner_client():
    """Factory yielding a TestClient with the profile scraper overridden.

    Usage: ``client = scanner_client(mock_fn)`` where ``mock_fn`` is a callable
    ``(username) -> dict`` (or ``None`` to exercise the 503 path). Keeps ALL
    external Nitter fetches out of the test suite — no live network.
    """
    _sentinel = object()

    def _make(scraper=_sentinel):
        if scraper is not _sentinel:
            fastapi_app.dependency_overrides[get_profile_scraper] = lambda: scraper
        return TestClient(fastapi_app)

    try:
        yield _make
    finally:
        fastapi_app.dependency_overrides.pop(get_profile_scraper, None)


@pytest.fixture
def scan_client(tmp_path: Path):
    """Factory for /api/scanner/scan tests with ALL write targets + engine isolated.

    ``make(engine=...)`` overrides the scanner engine (a stub — no live heuristic
    run / network), plus the leaderboard store, reports dir, and scan-store path
    with temp-backed instances so nothing touches the real dashboard files.

    Yields ``(make, lb_store, reports_dir, scan_store_path)``.
    """
    lb_store = LeaderboardStore(path=tmp_path / "leaderboard.json")
    reports_dir = tmp_path / "reports"
    scan_store_path = tmp_path / "scan_store.json"
    _sentinel = object()

    def _make(engine=_sentinel):
        fastapi_app.dependency_overrides[get_leaderboard_store] = lambda: lb_store
        fastapi_app.dependency_overrides[get_reports_dir] = lambda: reports_dir
        fastapi_app.dependency_overrides[get_scan_store_path] = lambda: scan_store_path
        if engine is not _sentinel:
            fastapi_app.dependency_overrides[get_scanner_engine] = lambda: engine
        return TestClient(fastapi_app)

    try:
        yield _make, lb_store, reports_dir, scan_store_path
    finally:
        for dep in (
            get_leaderboard_store,
            get_reports_dir,
            get_scan_store_path,
            get_scanner_engine,
        ):
            fastapi_app.dependency_overrides.pop(dep, None)

