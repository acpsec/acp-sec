"""Blocking outbound work never runs on the event loop, and is capped.

``with TestClient(app)`` runs every request on ONE event loop (like a single
uvicorn worker), so a handler that blocked the loop would stall /api/health.
Stubs block on an Event until released — no network, no sleeps on the happy
path.
"""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from acpsec_api import leaderboard_store as lbs
from acpsec_api.concurrency import SERVER_BUSY_ERROR, SLOT_LIMITS
from acpsec_api.deps import (
    get_leaderboard_store,
    get_onchain_checker,
    get_profile_scraper,
    get_reports_dir,
    get_scanner_engine,
)
from acpsec_api.leaderboard_store import LeaderboardStore
from acpsec_api.main import app
from acpsec_api.routers import b20 as b20_router


class _Gate:
    """Counts blocked calls in, holds them until ``release``."""

    def __init__(self) -> None:
        self.entered = threading.Semaphore(0)
        self.release = threading.Event()

    def hold(self):
        self.entered.release()
        self.release.wait(10)

    def wait_entered(self, n: int) -> bool:
        return all(self.entered.acquire(timeout=5) for _ in range(n))


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    monkeypatch.setattr("time.sleep", lambda *a, **k: None)  # /bulk throttle
    g = _Gate()

    class _Engine:
        def analyze_agent(self, url, agent_name="", scan_mode="root"):
            g.hold()
            return {"ok": True, "data": {"agent_name": agent_name, "rated": False, "token": {}}}

        def extract_token_info(self, html="", x_bio=""):
            return {}

    def _scraper(username):
        g.hold()
        return {"username": username}

    def _checker(wallet, *, rpc_url=None):
        g.hold()
        return {"wallet": wallet}

    def _read(address, chain_id, rpc=None):
        g.hold()
        raise b20_router.B20Unavailable("stub")

    overrides = {
        get_scanner_engine: lambda: _Engine(),
        get_profile_scraper: lambda: _scraper,
        get_onchain_checker: lambda: _checker,
        get_leaderboard_store: lambda: LeaderboardStore(path=tmp_path / "lb.json"),
        get_reports_dir: lambda: tmp_path / "reports",
        b20_router.get_read_fn: lambda: _read,
        b20_router.get_rpc_factory: lambda: (lambda chain_id: object()),
    }
    app.dependency_overrides.update(overrides)
    try:
        yield g
    finally:
        g.release.set()
        for dep in overrides:
            app.dependency_overrides.pop(dep, None)


def _health_latency(client) -> float:
    t0 = time.monotonic()
    resp = client.get("/api/health")
    assert resp.status_code == 200
    return time.monotonic() - t0


def _in_threads(client, n, path, body):
    threads = [threading.Thread(target=client.post, args=(path,), kwargs={"json": body(i)}, daemon=True)
               for i in range(n)]
    for t in threads:
        t.start()
    return threads


def test_health_answers_under_a_second_while_three_slow_scans_run(gate) -> None:
    with TestClient(app) as client:
        threads = _in_threads(client, 3, "/api/scanner/scan", lambda i: {"url": f"https://s{i}.example"})
        try:
            assert gate.wait_entered(3), "three scans must run concurrently, off the event loop"
            assert _health_latency(client) < 1.0
        finally:
            gate.release.set()
            for t in threads:
                t.join(10)


def test_scans_beyond_the_cap_get_a_busy_503(gate) -> None:
    cap = SLOT_LIMITS["scan"]
    with TestClient(app) as client:
        threads = _in_threads(client, cap, "/api/scanner/scan", lambda i: {"url": f"https://s{i}.example"})
        try:
            assert gate.wait_entered(cap)
            busy = client.post("/api/scanner/scan", json={"url": "https://one-too-many.example"})
            assert busy.status_code == 503
            assert busy.json() == {"ok": False, "error": SERVER_BUSY_ERROR}
            assert int(busy.headers["Retry-After"]) >= 1
            # /bulk shares the scan cap.
            assert client.post("/api/scanner/bulk", json={"usernames": ["x"]}).status_code == 503
        finally:
            gate.release.set()
            for t in threads:
                t.join(10)
        # Slots are returned once the scans finish.
        gate.release.set()
        assert client.post("/api/scanner/scan", json={"url": "https://after.example"}).status_code == 200


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/scanner/lookup", {"username": "agentx"}),
        ("/api/scanner/bulk", {"usernames": ["agentx"]}),
        ("/api/onchain/check", {"wallet": "0x" + "1" * 40}),
        ("/api/b20/scan", {"address": "0x" + "2" * 40, "chain_id": 84532}),
    ],
    ids=["lookup", "bulk", "onchain", "b20"],
)
def test_other_blocking_handlers_leave_the_loop_free(gate, path, body) -> None:
    with TestClient(app) as client:
        (thread,) = _in_threads(client, 1, path, lambda i: body)
        try:
            assert gate.wait_entered(1)
            assert _health_latency(client) < 1.0
        finally:
            gate.release.set()
            thread.join(10)


@pytest.mark.parametrize(
    ("kind", "path", "body"),
    [
        ("lookup", "/api/scanner/lookup", {"username": "agentx"}),
        ("onchain", "/api/onchain/check", {"wallet": "0x" + "1" * 40}),
        ("b20", "/api/b20/scan", {"address": "0x" + "2" * 40, "chain_id": 84532}),
    ],
)
def test_each_blocking_kind_has_its_own_cap(gate, kind, path, body) -> None:
    cap = SLOT_LIMITS[kind]
    with TestClient(app) as client:
        threads = _in_threads(client, cap, path, lambda i: body)
        try:
            assert gate.wait_entered(cap)
            assert client.post(path, json=body).status_code == 503
        finally:
            gate.release.set()
            for t in threads:
                t.join(10)


def test_caps_leave_most_of_the_threadpool_free() -> None:
    # anyio's default threadpool has 40 workers; cheap sync endpoints need some.
    assert sum(SLOT_LIMITS.values()) <= 20


def test_concurrent_upserts_lose_nothing(tmp_path, monkeypatch) -> None:
    # Widen the read-modify-write window so an unserialised upsert would lose
    # entries; with the store lock every scan lands.
    real_write = lbs.atomic_write_text

    def _slow_write(path, text):
        time.sleep(0.005)
        real_write(path, text)

    monkeypatch.setattr(lbs, "atomic_write_text", _slow_write)
    store = LeaderboardStore(path=tmp_path / "lb.json")
    hosts = [f"https://site{i}.example/" for i in range(20)]
    threads = [threading.Thread(target=store.upsert, args=({"scan_url": h, "score_pct": 50, "controls": []},))
               for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(store.load()["agents"]) == 20
