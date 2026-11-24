"""Every user-influenced fetch in the scan engine goes through net_guard.

Spies replace ``guarded_get`` where a response is needed; the blocked-target
tests need no spy at all because the guard refuses them before any network
I/O (URL-level checks) — so this module never touches the network.
"""

from __future__ import annotations

import inspect
import socket
from pathlib import Path

import pytest
import requests

from acpsec_api import net_guard, scanner, scanner_lookup
from acpsec_api.deps import get_leaderboard_store, get_reports_dir
from acpsec_api.leaderboard_store import LeaderboardStore


class _Resp:
    def __init__(self, url="https://example.com/", text="<html><title>t</title></html>", status=200):
        self.url = url
        self.text = text
        self.status_code = status
        self.headers = {}


@pytest.fixture
def no_sockets(monkeypatch):
    """Record (and refuse) any socket creation: blocked targets must be refused
    before the network is touched, not merely fail to connect."""
    attempts: list = []

    def _socket(*a, **k):
        attempts.append(a)
        raise OSError("test: sockets are not allowed here")

    monkeypatch.setattr(socket, "socket", _socket)
    return attempts


@pytest.fixture
def spy(monkeypatch):
    calls: list[dict] = []
    script: list = []  # queued outcomes: a response, or an exception to raise

    def _guarded_get(url, **kw):
        calls.append({"url": url, **kw})
        outcome = script.pop(0) if script else _Resp(url)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(scanner, "guarded_get", _guarded_get)
    return calls, script


def test_engine_modules_have_no_unguarded_fetches() -> None:
    # Regression guard: a new requests.get / Session / urlopen in the engine
    # would silently bypass the SSRF checks.
    for mod in (scanner, scanner_lookup):
        src = inspect.getsource(mod)
        for needle in ("requests.get(", "requests.post(", "requests.request(",
                       "requests.Session(", "urlopen("):
            assert needle not in src, f"{mod.__name__} calls {needle} directly"
    assert scanner.guarded_get is net_guard.guarded_get
    assert scanner_lookup.guarded_get is net_guard.guarded_get


def test_fetch_website_routes_through_guard(spy) -> None:
    calls, _ = spy
    resp, soup, warn = scanner._fetch_website("example.com")
    assert resp is not None and soup is not None and warn is None
    assert [c["url"] for c in calls] == ["https://example.com"]
    assert calls[0]["verify"] is True
    assert calls[0]["total_timeout"] == scanner.FETCH_TOTAL_TIMEOUT


def test_fetch_website_ssl_fallback_uses_guard_with_verify_false(spy) -> None:
    calls, script = spy
    script.extend([requests.exceptions.SSLError("bad cert"), _Resp("https://example.com/")])
    resp, _soup, warn = scanner._fetch_website("https://example.com/")
    assert resp is not None
    assert "SSL certificate verification failed" in warn
    assert [(c["url"], c["verify"]) for c in calls] == [
        ("https://example.com/", True),
        ("https://example.com/", False),
    ]


def test_fetch_website_blocked_target_is_a_clean_fetch_failure(no_sockets) -> None:
    resp, soup, warn = scanner._fetch_website("http://169.254.169.254/latest/meta-data/")
    assert resp is None and soup is None
    assert warn.startswith("Blocked by outbound fetch policy:")
    assert no_sockets == []


def test_quick_get_routes_through_guard(spy) -> None:
    calls, _ = spy
    scanner._quick_get("https://example.com/security", timeout=4)
    assert calls == [{
        "url": "https://example.com/security",
        "headers": scanner.BROWSER_HEADERS,
        "timeout": 4,
        "total_timeout": 8,
        "verify": True,
    }]


@pytest.mark.parametrize("url", ["http://10.0.0.1/security", "http://localhost/robots.txt"])
def test_quick_get_blocked_target_returns_none(url, no_sockets) -> None:
    assert scanner._quick_get(url, timeout=4) is None
    assert no_sockets == []


def test_legacy_scanner_scrape_x_profile_uses_guard(spy) -> None:
    calls, _ = spy
    scanner.scrape_x_profile("agentx")
    assert calls and all(c["url"].endswith("/agentx") for c in calls)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:6379/",
        "http://api-prod.railway.internal/",
        "http://[::1]/",
        "https://10.0.0.1/",
    ],
)
def test_analyze_agent_internal_target_is_unrated(url, no_sockets) -> None:
    res = scanner.analyze_agent(url, "Probe", scan_mode="exact")
    assert res["ok"] is True
    assert res["data"]["rated"] is False
    assert res["data"]["fetch_warning"].startswith("Blocked by outbound fetch policy:")
    assert no_sockets == []


def test_scan_endpoint_internal_target_is_not_persisted(fastapi_app_client) -> None:
    # (no `no_sockets` here: TestClient's event loop needs a local socketpair;
    # the engine-level tests above already prove no outbound socket is made.)
    client, lb_store = fastapi_app_client
    resp = client.post(
        "/api/scanner/scan",
        json={"url": "http://169.254.169.254/latest/meta-data/", "agent_name": "probe"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["rated"] is False
    assert body["data"]["fetch_warning"].startswith("Blocked by outbound fetch policy:")
    assert lb_store.load()["agents"] == []


@pytest.fixture
def fastapi_app_client(tmp_path: Path, monkeypatch):
    """Real engine, isolated stores, open gate (no token, not production)."""
    from fastapi.testclient import TestClient

    from acpsec_api.main import app

    from acpsec_api.rate_limit import reset_rate_limits

    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    reset_rate_limits()
    lb_store = LeaderboardStore(path=tmp_path / "leaderboard.json")
    app.dependency_overrides[get_leaderboard_store] = lambda: lb_store
    app.dependency_overrides[get_reports_dir] = lambda: tmp_path / "reports"
    try:
        yield TestClient(app), lb_store
    finally:
        for dep in (get_leaderboard_store, get_reports_dir):
            app.dependency_overrides.pop(dep, None)
