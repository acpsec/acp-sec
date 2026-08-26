"""Unit tests for acpsec_api.scanner_lookup.scrape_x_profile().

TDD RED phase: all tests below fail before the fetch_status / instance_errors /
nitter_instance / cache changes are added to scanner_lookup.py.

No live network — requests.get is always monkeypatched.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from acpsec_api import scanner_lookup
from acpsec_api.scanner_lookup import NITTER_INSTANCES, scrape_x_profile

# ---------------------------------------------------------------------------
# HTML fixtures
# ---------------------------------------------------------------------------

_EMPTY_HTML = "<html><body></body></html>"

_PROFILE_HTML = """
<html><body>
  <div class="profile-card-fullname">Agent X</div>
  <div class="profile-bio">Test bio for Agent X</div>
</body></html>
"""


def _fake_resp(status: int = 200, text: str = _EMPTY_HTML) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


# ---------------------------------------------------------------------------
# Autouse fixture: reset the module-level cache between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_cache():
    scanner_lookup._last_good_instance = None
    yield
    scanner_lookup._last_good_instance = None


# ---------------------------------------------------------------------------
# RED tests (all fail before implementation)
# ---------------------------------------------------------------------------


def test_all_failed_fetch_status(monkeypatch):
    """All instances raise ConnectionError → fetch_status='all_failed'."""

    def _raise(*_a, **_kw):
        raise ConnectionError("timed out")

    monkeypatch.setattr(scanner_lookup.requests, "get", _raise)

    result = scrape_x_profile("agentx")

    assert result["fetch_status"] == "all_failed"
    assert result["nitter_instance"] is None
    assert len(result["instance_errors"]) == len(NITTER_INSTANCES)
    for entry in result["instance_errors"]:
        assert "instance" in entry
        assert "error" in entry
        assert "timed out" in entry["error"]
    assert result["source"] == "failed"


def test_blocked_fetch_status(monkeypatch):
    """All instances return HTTP 200 but no profile elements → fetch_status='blocked'."""
    monkeypatch.setattr(
        scanner_lookup.requests, "get",
        lambda *_a, **_kw: _fake_resp(200, _EMPTY_HTML),
    )

    result = scrape_x_profile("agentx")

    assert result["fetch_status"] == "blocked"
    assert result["source"] == "failed"
    assert result["nitter_instance"] is None


def test_ok_fetch_status(monkeypatch):
    """First instance returns valid profile HTML → fetch_status='ok'."""
    monkeypatch.setattr(
        scanner_lookup.requests, "get",
        lambda *_a, **_kw: _fake_resp(200, _PROFILE_HTML),
    )

    result = scrape_x_profile("agentx")

    assert result["fetch_status"] == "ok"
    assert result["nitter_instance"] == NITTER_INSTANCES[0]
    assert result["instance_errors"] == []
    assert result["source"] == "nitter"
    assert result["display_name"] == "Agent X"


def test_cache_last_good_instance(monkeypatch):
    """When _last_good_instance is set, that instance is tried first."""
    scanner_lookup._last_good_instance = NITTER_INSTANCES[2]
    called_urls: list[str] = []

    def _record(url, **_kw):
        called_urls.append(url)
        return _fake_resp(200, _PROFILE_HTML)

    monkeypatch.setattr(scanner_lookup.requests, "get", _record)

    scrape_x_profile("agentx")

    assert called_urls[0].startswith(NITTER_INSTANCES[2])


def test_cache_updated_on_success(monkeypatch):
    """After a successful scrape, _last_good_instance is updated to that instance."""

    def _selective(url, **_kw):
        if NITTER_INSTANCES[1] in url:
            return _fake_resp(200, _PROFILE_HTML)
        return _fake_resp(200, _EMPTY_HTML)

    monkeypatch.setattr(scanner_lookup.requests, "get", _selective)

    scrape_x_profile("agentx")

    assert scanner_lookup._last_good_instance == NITTER_INSTANCES[1]


def test_no_fabrication_on_failure(monkeypatch):
    """On total failure all profile fields are empty — no fabricated data."""

    def _raise(*_a, **_kw):
        raise ConnectionError("refused")

    monkeypatch.setattr(scanner_lookup.requests, "get", _raise)

    result = scrape_x_profile("agentx")

    assert result["display_name"] == ""
    assert result["bio"] == ""
    assert result["website"] == ""
    assert result["avatar_url"] == ""


def test_mixed_failures_classified_blocked(monkeypatch):
    """First two instances raise, third returns 200 with empty HTML → 'blocked'."""
    call_count = [0]

    def _mixed(*_a, **_kw):
        call_count[0] += 1
        if call_count[0] <= 2:
            raise ConnectionError("refused")
        return _fake_resp(200, _EMPTY_HTML)

    monkeypatch.setattr(scanner_lookup.requests, "get", _mixed)

    result = scrape_x_profile("agentx")

    assert result["fetch_status"] == "blocked"
