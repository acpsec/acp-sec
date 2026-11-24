"""Per-client rate limiting for /api/scanner/* and /api/onchain/check.

Scrapers, engine and on-chain checker are stubbed — no network. The limiter
clock is a fake (``rate_limit._now``), so no test sleeps.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from acpsec_api import rate_limit
from acpsec_api.deps import (
    get_leaderboard_store,
    get_onchain_checker,
    get_profile_scraper,
    get_reports_dir,
    get_scan_store_path,
    get_scanner_engine,
)
from acpsec_api.leaderboard_store import LeaderboardStore
from acpsec_api.main import app
from acpsec_api.rate_limit import LIMITS, RATE_LIMITED_ERROR, SlidingWindowLimiter, client_key


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class _Engine:
    def analyze_agent(self, url, agent_name="", scan_mode="root"):
        return {"ok": True, "data": {"agent_name": agent_name, "rated": False}}

    def extract_token_info(self, html="", x_bio=""):
        return {}


@pytest.fixture
def clock(monkeypatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(rate_limit, "_now", c)
    return c


@pytest.fixture
def client(tmp_path, clock, monkeypatch):
    """Open gate (dev mode), every downstream dependency stubbed and isolated."""
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)  # /bulk throttle
    overrides = {
        get_profile_scraper: lambda: (lambda username: {"username": username}),
        get_scanner_engine: lambda: _Engine(),
        get_onchain_checker: lambda: (lambda wallet, *, rpc_url=None: {"wallet": wallet}),
        get_leaderboard_store: lambda: LeaderboardStore(path=tmp_path / "lb.json"),
        get_reports_dir: lambda: tmp_path / "reports",
        get_scan_store_path: lambda: tmp_path / "scan.json",
    }
    app.dependency_overrides.update(overrides)
    try:
        yield TestClient(app)
    finally:
        for dep in overrides:
            app.dependency_overrides.pop(dep, None)


ENDPOINTS = {
    "scanner_lookup": ("/api/scanner/lookup", {"username": "agentx"}),
    "scanner_scan": ("/api/scanner/scan", {"url": "https://agent.example"}),
    "scanner_bulk": ("/api/scanner/bulk", {"usernames": ["a"]}),
    "onchain_check": ("/api/onchain/check", {"wallet": "0x" + "1" * 40}),
}


@pytest.mark.parametrize("bucket", list(ENDPOINTS))
def test_each_endpoint_is_limited_per_client(client, bucket) -> None:
    path, body = ENDPOINTS[bucket]
    allowance = LIMITS[bucket].per_client
    for _ in range(allowance):
        assert client.post(path, json=body).status_code == 200
    resp = client.post(path, json=body)
    assert resp.status_code == 429
    assert resp.json() == {"ok": False, "error": RATE_LIMITED_ERROR}
    assert int(resp.headers["Retry-After"]) >= 1


def test_window_slides(client, clock) -> None:
    path, body = ENDPOINTS["scanner_scan"]
    limit = LIMITS["scanner_scan"]
    for _ in range(limit.per_client):
        client.post(path, json=body)
    assert client.post(path, json=body).status_code == 429
    clock.t += limit.window + 0.01
    assert client.post(path, json=body).status_code == 200


def test_retry_after_counts_down_to_the_oldest_hit(client, clock) -> None:
    path, body = ENDPOINTS["scanner_scan"]
    limit = LIMITS["scanner_scan"]
    for _ in range(limit.per_client):
        client.post(path, json=body)
    clock.t += 20
    resp = client.post(path, json=body)
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) == int(limit.window - 20)


def test_buckets_are_independent(client) -> None:
    path, body = ENDPOINTS["scanner_scan"]
    for _ in range(LIMITS["scanner_scan"].per_client):
        client.post(path, json=body)
    assert client.post(path, json=body).status_code == 429
    lookup_path, lookup_body = ENDPOINTS["scanner_lookup"]
    assert client.post(lookup_path, json=lookup_body).status_code == 200


def _exhaust(client, headers) -> None:
    path, body = ENDPOINTS["scanner_scan"]
    for _ in range(LIMITS["scanner_scan"].per_client):
        assert client.post(path, json=body, headers=headers).status_code == 200


def _scan(client, headers):
    path, body = ENDPOINTS["scanner_scan"]
    return client.post(path, json=body, headers=headers)


def test_railway_clients_keyed_by_x_real_ip(client, monkeypatch) -> None:
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")  # production: the gate needs it
    auth = {"X-Scanner-Token": "sekret"}
    _exhaust(client, {**auth, "X-Real-IP": "203.0.113.7"})
    assert _scan(client, {**auth, "X-Real-IP": "203.0.113.7"}).status_code == 429
    assert _scan(client, {**auth, "X-Real-IP": "198.51.100.9"}).status_code == 200


def test_forwarded_for_is_never_trusted(client, monkeypatch) -> None:
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    base = {"X-Scanner-Token": "sekret", "X-Real-IP": "203.0.113.7"}
    _exhaust(client, {**base, "X-Forwarded-For": "1.1.1.1"})
    for spoof in ("8.8.8.8", "9.9.9.9, 203.0.113.7", "203.0.113.8"):
        assert _scan(client, {**base, "X-Forwarded-For": spoof}).status_code == 429


def test_proxy_headers_ignored_off_railway(client) -> None:
    # Local/dev: no proxy in front, so neither header is believed.
    _exhaust(client, {"X-Real-IP": "203.0.113.1", "X-Forwarded-For": "203.0.113.1"})
    for spoof in ("203.0.113.2", "203.0.113.3"):
        assert _scan(client, {"X-Real-IP": spoof, "X-Forwarded-For": spoof}).status_code == 429


def test_unparseable_x_real_ip_falls_back_to_the_peer(client, monkeypatch) -> None:
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    auth = {"X-Scanner-Token": "sekret"}
    _exhaust(client, {**auth, "X-Real-IP": "not-an-ip"})
    # Same (shared) peer bucket — rotating junk values does not help.
    assert _scan(client, {**auth, "X-Real-IP": "also-junk"}).status_code == 429
    assert _scan(client, auth).status_code == 429


def test_gate_runs_before_the_limiter(client, monkeypatch) -> None:
    # Rejected (401) callers must not burn the allowance of the real client.
    monkeypatch.setenv("SCANNER_TOKEN", "sekret")
    for _ in range(3 * LIMITS["scanner_scan"].per_client):
        assert _scan(client, {}).status_code == 401
    assert _scan(client, {"X-Scanner-Token": "sekret"}).status_code == 200


# --- Unit level ----------------------------------------------------------------


class _Req:
    def __init__(self, peer, headers=None):
        self.client = type("C", (), {"host": peer})() if peer is not None else None
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}


def test_client_key_off_railway_is_the_peer(monkeypatch) -> None:
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    assert client_key(_Req("203.0.113.5", {"X-Real-IP": "8.8.8.8"})) == "203.0.113.5"
    assert client_key(_Req("testclient")) == "testclient"
    assert client_key(_Req(None)) == "unknown"


def test_client_key_on_railway_groups_ipv6_by_64(monkeypatch) -> None:
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    a = client_key(_Req("10.0.0.2", {"X-Real-IP": "2001:db8:1:2::1"}))
    b = client_key(_Req("10.0.0.2", {"X-Real-IP": "2001:db8:1:2:ffff::9"}))
    c = client_key(_Req("10.0.0.2", {"X-Real-IP": "2001:db8:1:3::1"}))
    assert a == b == "2001:db8:1:2::/64"
    assert c != a
    assert client_key(_Req("10.0.0.2", {"X-Real-IP": "::ffff:203.0.113.4"})) == "203.0.113.4"


def test_global_ceiling_caps_all_clients() -> None:
    clock = _Clock()
    lim = SlidingWindowLimiter(per_client=2, global_limit=3, window=60, clock=clock)
    assert lim.hit("a") is None
    assert lim.hit("a") is None
    assert lim.hit("a") is not None  # per-client
    assert lim.hit("b") is None      # third request overall
    assert lim.hit("c") is not None  # global ceiling, though "c" is fresh
    clock.t += 61
    assert lim.hit("c") is None


def test_denied_hits_do_not_extend_the_lockout() -> None:
    clock = _Clock()
    lim = SlidingWindowLimiter(per_client=1, global_limit=100, window=10, clock=clock)
    assert lim.hit("a") is None
    for _ in range(50):
        clock.t += 0.1
        assert lim.hit("a") is not None
    clock.t = 1000.0 + 10.01
    assert lim.hit("a") is None


def test_client_table_is_bounded() -> None:
    lim = SlidingWindowLimiter(per_client=5, global_limit=10_000, window=60, max_clients=3, clock=_Clock())
    for key in "abcde":
        lim.hit(key)
    assert lim.tracked_clients() == 3
