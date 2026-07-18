"""Characterization tests for the heuristic scan engine (Group 9.6).

Pins the CURRENT behaviour of the two public entry points that ``acpsec_api``
calls on the engine, so the 9.6 relocation
(``dashboard/scanner.py`` -> ``acpsec_api/scanner.py``) is provably
behaviour-preserving: the assertions below stay byte-for-byte identical across
the move; only the import line changes. Any drift = the move altered behaviour.

Entry points (traced from ``acpsec_api/deps.py:78`` through
``acpsec_api/routers/scanner.py``):
  - ``analyze_agent(url, agent_name, scan_mode)``   routers/scanner.py:131,231
  - ``extract_token_info(html, x_bio, ...)``        routers/scanner.py:146

Network is fully stubbed (fixtures only) — no live fetches.
"""

from __future__ import annotations

import pytest
from bs4 import BeautifulSoup

# NOTE (Group 9.6): moved from `dashboard` -> `acpsec_api` in Phase 2. The
# assertions are unchanged from the pre-move baseline — that identity is the
# proof the move preserved behaviour.
from acpsec_api import scanner

_SCAN_URL = "https://secureagent.example/"

_RICH_HTML = """
<html><head><title>SecureAgent</title>
<meta name="description" content="An AI agent with strong security posture."></head>
<body>
<h1>SecureAgent</h1>
<p>We take security seriously. Read our <a href="/security">security policy</a>,
our <a href="/privacy">privacy policy</a>, and <a href="/terms">terms</a>.</p>
<p>We run a bug bounty program and support responsible disclosure. Contact
security@secureagent.com. We use rate limiting, authentication, and input
validation. All data is encrypted. We follow the OWASP guidelines and have a
security.txt file. Human oversight and audit logging are in place.</p>
</body></html>
"""

_SEC_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=63072000",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "content-type": "text/html",
}


class _FakeResp:
    """Minimal stand-in for a ``requests.Response`` (no network)."""

    def __init__(self, url, html, headers=None, status=200):
        self.url = url
        self.text = html
        self.content = html.encode()
        self.status_code = status
        self.headers = headers or {}


@pytest.fixture
def stub_network(monkeypatch):
    """Replace every network seam in the engine with canned, offline responses.

    These module-level functions are resolved from the engine's own globals at
    call time, so patching the module attributes fully severs network access
    while leaving the heuristic pipeline intact.
    """
    monkeypatch.setattr(
        scanner,
        "_fetch_website",
        lambda url: (
            _FakeResp(_SCAN_URL, _RICH_HTML, _SEC_HEADERS),
            BeautifulSoup(_RICH_HTML, "html.parser"),
            "",
        ),
    )
    monkeypatch.setattr(scanner, "_parallel_get", lambda urls, *a, **k: {u: None for u in urls})
    monkeypatch.setattr(scanner, "_quick_get", lambda url, timeout=6: None)
    monkeypatch.setattr(scanner, "_resolve_parent", lambda url: None)
    monkeypatch.setattr(scanner, "_resolve_self_probe", lambda url: None)


def _scan():
    return scanner.analyze_agent(_SCAN_URL, "SecureAgent", scan_mode="exact")


def test_analyze_agent_output_contract(stub_network):
    res = _scan()
    assert res["ok"] is True
    assert set(res.keys()) == {"ok", "data"}
    expected_keys = {
        "acpsec_available", "agent_name", "agent_version", "band", "controls",
        "corpus", "critical_fails", "fetch_warning", "final_score",
        "is_self_probe", "metadata", "methodology", "original_url",
        "parent_domain", "parent_score_contribution", "parent_signals",
        "scan_duration_ms", "scan_mode", "scan_url", "score_pct",
        "sec_header_count", "security_headers", "source", "timestamp",
        "token", "verdict",
    }
    assert expected_keys <= set(res["data"].keys())


def test_analyze_agent_heuristic_values(stub_network):
    d = _scan()["data"]
    assert d["agent_name"] == "SecureAgent"
    assert d["scan_mode"] == "exact"
    assert d["scan_url"] == _SCAN_URL
    assert d["source"] == "scanner"
    assert d["methodology"] == "heuristic+corpus+parent"
    assert d["acpsec_available"] is True
    assert d["sec_header_count"] == 4
    assert d["final_score"] == 30.1
    assert d["score_pct"] == 25.9
    assert d["band"] == "CRITICAL"
    assert d["verdict"].startswith("Multiple high-severity issues")
    assert d["critical_fails"] == 3


def test_analyze_agent_controls(stub_network):
    ctrls = _scan()["data"]["controls"]
    assert len(ctrls) == 38
    assert all(c["inferred"] is True for c in ctrls)
    assert sorted({c["dimension"] for c in ctrls}) == [
        "AUTH", "CTX", "GOV", "INJ", "OUT", "PRIV", "PUB",
    ]
    by_id = {c["ctrl"]: c for c in ctrls}
    assert by_id["AUTH-01"]["status"] == "warn"
    assert by_id["AUTH-01"]["score"] == 1.5
    assert by_id["AUTH-01"]["max"] == 3
    assert by_id["PRIV-01"]["status"] == "fail"
    assert by_id["PRIV-01"]["score"] == 0.0
    assert by_id["GOV-01"]["status"] == "warn"
    assert by_id["GOV-01"]["score"] == 1.2
    assert by_id["PUB-01"]["status"] == "fail"
    assert by_id["PUB-01"]["score"] == 0.0


def test_analyze_agent_social_media_shortcircuit():
    """x.com input short-circuits to a limited scan before any fetch (no stub)."""
    d = scanner.analyze_agent("https://x.com/someagent", "SomeAgent", scan_mode="exact")["data"]
    assert d["limited_scan"] is True
    assert d["no_website"] is True
    assert d["limited_reason"] == "social-media-input"
    assert d["band"] == "COMPROMISED"
    assert d["score_pct"] == 1.7


def test_extract_token_info_detects_token_and_ca():
    ti = scanner.extract_token_info(
        html="Buy $SECURE now! CA: 0x1234567890abcdef1234567890abcdef12345678",
    )
    assert ti["has_token"] is True
    assert ti["ticker"] == "$SECURE"
    assert ti["contract_address"] == "0x1234567890abcdef1234567890abcdef12345678"
    assert ti["all_tickers_found"] == ["$SECURE"]
    assert ti["all_contracts_found"] == ["0x1234567890abcdef1234567890abcdef12345678"]
    assert ti["signals"] is True
    assert ti["detected_from"] == "website"


def test_extract_token_info_no_token():
    ti = scanner.extract_token_info(html="<p>no tokens here</p>")
    assert ti["has_token"] is False
    assert ti["ticker"] is None
    assert ti["contract_address"] is None
    assert ti["all_tickers_found"] == []
    assert ti["detected_from"] is None
