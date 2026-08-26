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
    assert d["final_score"] == 25.9   # was 30.1 raw pts; now unified with score_pct
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


# ---------------------------------------------------------------------------
# No-website partial scan (RED tests — all fail before implementation)
# ---------------------------------------------------------------------------


def test_analyze_agent_empty_url_returns_ok():
    """analyze_agent('') returns ok:True (partial result, not a failure)."""
    result = scanner.analyze_agent("", "SomeAgent", scan_mode="exact")
    assert result["ok"] is True, f"expected ok:True, got: {result}"


def test_analyze_agent_empty_url_rated_false():
    """Partial scan carries rated:false so it can't be mistaken for a full scan."""
    data = scanner.analyze_agent("", "SomeAgent", scan_mode="exact")["data"]
    assert data["rated"] is False


def test_analyze_agent_empty_url_metadata():
    """Partial scan carries no_website=True and limited_reason='no-website-provided'."""
    data = scanner.analyze_agent("", "SomeAgent", scan_mode="exact")["data"]
    assert data["no_website"] is True
    assert data["limited_reason"] == "no-website-provided"
    assert data["methodology"] == "no-website-partial"


def test_analyze_agent_empty_url_controls_unrated():
    """All controls except AUTH-01 carry status='unrated' — not 'skip' or scored."""
    ctrls = scanner.analyze_agent("", "SomeAgent", scan_mode="exact")["data"]["controls"]
    assert len(ctrls) == 38
    by_id = {c["ctrl"]: c for c in ctrls}
    non_auth01 = [c for c in ctrls if c["ctrl"] != "AUTH-01"]
    assert all(c["status"] == "unrated" for c in non_auth01), (
        "expected all non-AUTH-01 checks to be 'unrated'"
    )
    # AUTH-01 gets partial credit (agent name declared)
    assert by_id["AUTH-01"]["status"] == "warn"
    assert by_id["AUTH-01"]["score"] == 2.0


def test_analyze_agent_empty_url_evidence_diagnostic():
    """Unrated checks carry the 'no website provided' diagnostic in their evidence."""
    ctrls = scanner.analyze_agent("", "SomeAgent", scan_mode="exact")["data"]["controls"]
    non_auth01 = [c for c in ctrls if c["ctrl"] != "AUTH-01"]
    for c in non_auth01:
        evidence_text = " ".join(c.get("evidence") or [])
        assert "no website" in evidence_text.lower(), (
            f"{c['ctrl']} evidence does not mention 'no website': {c.get('evidence')}"
        )


def test_analyze_agent_empty_url_no_fabrication():
    """Unrated checks all score 0 — no points awarded from non-existent web content."""
    ctrls = scanner.analyze_agent("", "SomeAgent", scan_mode="exact")["data"]["controls"]
    non_auth01 = [c for c in ctrls if c["ctrl"] != "AUTH-01"]
    assert all(c["score"] == 0.0 for c in non_auth01), (
        "non-AUTH-01 checks must not receive fabricated scores"
    )


# ---------------------------------------------------------------------------
# Coverage summary (RED — all fail before implementation)
# ---------------------------------------------------------------------------


def test_coverage_summary_keys_exist(stub_network):
    """analyze_agent result carries evidence_coverage, evidence_found_count, low_evidence."""
    d = _scan()["data"]
    assert "evidence_coverage" in d, "missing evidence_coverage"
    assert "evidence_found_count" in d, "missing evidence_found_count"
    assert "low_evidence" in d, "missing low_evidence"


def test_coverage_summary_types(stub_network):
    """Coverage fields have correct types and ranges."""
    d = _scan()["data"]
    assert isinstance(d["evidence_coverage"], float)
    assert 0.0 <= d["evidence_coverage"] <= 1.0
    assert isinstance(d["evidence_found_count"], int)
    assert d["evidence_found_count"] >= 0
    assert isinstance(d["low_evidence"], bool)


def test_coverage_does_not_change_score(stub_network):
    """Coverage metadata must not alter score_pct, band (final_score now == score_pct)."""
    d = _scan()["data"]
    assert d["score_pct"] == 25.9
    assert d["final_score"] == 25.9  # unified with score_pct (Bug 2 fix)
    assert d["band"] == "CRITICAL"


def test_compute_coverage_all_fail():
    """_compute_coverage: all-fail controls → found=0, coverage=0.0, low_evidence=True."""
    controls = [{"status": "fail", "score": 0.0, "max": 3} for _ in range(38)]
    coverage, found, low = scanner._compute_coverage(controls)
    assert found == 0
    assert coverage == 0.0
    assert low is True


def test_compute_coverage_all_pass():
    """_compute_coverage: all-pass controls → found=38, coverage=1.0, low_evidence=False."""
    controls = [{"status": "pass", "score": 3.0, "max": 3} for _ in range(38)]
    coverage, found, low = scanner._compute_coverage(controls)
    assert found == 38
    assert coverage == 1.0
    assert low is False


def test_compute_coverage_threshold_boundary():
    """score/max exactly 0.5 counts as evidence found; below 0.5 does not."""
    at_threshold = {"status": "warn", "score": 1.5, "max": 3}   # 0.5 → counts
    below = {"status": "warn", "score": 1.2, "max": 3}           # 0.4 → doesn't
    cov_at, found_at, _ = scanner._compute_coverage([at_threshold])
    cov_below, found_below, _ = scanner._compute_coverage([below])
    assert found_at == 1
    assert found_below == 0


def test_coverage_excludes_skip_and_unrated():
    """skip/unrated controls are excluded from the coverage denominator."""
    # Social-media short-circuit produces skip controls — evidence_coverage
    # must still be a valid float (no div-by-zero) and low_evidence must be bool.
    d = scanner.analyze_agent("https://x.com/someagent", "SomeAgent")["data"]
    assert isinstance(d.get("evidence_coverage"), float)
    assert isinstance(d.get("low_evidence"), bool)


# ---------------------------------------------------------------------------
# Bug 1 — fetch failure must produce UNRATED controls, not a CRITICAL verdict
# (all tests below are RED before implementation)
# ---------------------------------------------------------------------------

class _Resp:
    """Minimal stand-in for requests.Response."""
    def __init__(self, status, text, url=_SCAN_URL, headers=None):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = headers or {}
        self.url = url


@pytest.fixture
def stub_fetch_fail(monkeypatch):
    """Simulate total fetch failure (connection refused / timeout)."""
    monkeypatch.setattr(
        scanner, "_fetch_website",
        lambda url: (None, None, "Connection refused: timed out"),
    )


@pytest.fixture
def stub_server_error(monkeypatch):
    """Simulate a 503 Cloudflare response (server error code)."""
    _html = "<html><body>Service Unavailable</body></html>"
    monkeypatch.setattr(
        scanner, "_fetch_website",
        lambda url: (
            _Resp(503, _html),
            BeautifulSoup(_html, "html.parser"),
            None,
        ),
    )


@pytest.fixture
def stub_empty_body(monkeypatch):
    """Simulate a 200 response with a near-empty body (JS-only SPA shell)."""
    _html = "<html><head></head><body><div id='root'></div></body></html>"
    monkeypatch.setattr(
        scanner, "_fetch_website",
        lambda url: (
            _Resp(200, _html),
            BeautifulSoup(_html, "html.parser"),
            None,
        ),
    )


def test_fetch_fail_ok_true(stub_fetch_fail):
    """Network error → ok:True partial result, not ok:False."""
    result = scanner.analyze_agent("https://example.com", "MyAgent")
    assert result["ok"] is True, f"expected ok:True, got: {result}"


def test_fetch_fail_rated_false(stub_fetch_fail):
    """Fetch failure → rated:False so the result can't be shown as authoritative."""
    data = scanner.analyze_agent("https://example.com", "MyAgent")["data"]
    assert data["rated"] is False


def test_fetch_fail_limited_reason(stub_fetch_fail):
    """Fetch failure → limited_reason='fetch-failed'."""
    data = scanner.analyze_agent("https://example.com", "MyAgent")["data"]
    assert data["limited_reason"] == "fetch-failed"


def test_fetch_fail_controls_unrated(stub_fetch_fail):
    """All non-AUTH-01 controls are unrated with score=0 (no fabrication)."""
    ctrls = scanner.analyze_agent("https://example.com", "MyAgent")["data"]["controls"]
    assert len(ctrls) == 38
    non_auth01 = [c for c in ctrls if c["ctrl"] != "AUTH-01"]
    assert all(c["status"] == "unrated" for c in non_auth01), (
        "non-AUTH-01 controls must be unrated on fetch failure"
    )
    assert all(c["score"] == 0.0 for c in non_auth01), (
        "non-AUTH-01 controls must score 0 (no fabrication)"
    )


def test_fetch_fail_auth01_partial_credit(stub_fetch_fail):
    """AUTH-01 still gets 2/3 pts when agent_name is provided."""
    by_id = {
        c["ctrl"]: c
        for c in scanner.analyze_agent("https://example.com", "MyAgent")["data"]["controls"]
    }
    assert by_id["AUTH-01"]["status"] == "warn"
    assert by_id["AUTH-01"]["score"] == 2.0


def test_fetch_fail_evidence_has_diagnostic(stub_fetch_fail):
    """Each unrated control's evidence mentions the fetch failure."""
    ctrls = scanner.analyze_agent("https://example.com", "MyAgent")["data"]["controls"]
    non_auth01 = [c for c in ctrls if c["ctrl"] != "AUTH-01"]
    for c in non_auth01:
        ev = " ".join(c.get("evidence") or []).lower()
        assert "fetch" in ev or "website" in ev, (
            f"{c['ctrl']} evidence missing fetch diagnostic: {c.get('evidence')}"
        )


def test_fetch_fail_not_critical_band(stub_fetch_fail):
    """Fetch failure must never produce a CRITICAL or COMPROMISED band signal.
    rated:False is the authoritative signal; score is too low to map to CRITICAL."""
    data = scanner.analyze_agent("https://example.com", "MyAgent")["data"]
    assert data["band"] != "CRITICAL", (
        "fetch failure must not produce a CRITICAL verdict — absence is not a finding"
    )


def test_server_error_controls_unrated(stub_server_error):
    """503 response → controls unrated, not a full CRITICAL scan of the error page."""
    ctrls = scanner.analyze_agent("https://example.com", "MyAgent")["data"]["controls"]
    non_auth01 = [c for c in ctrls if c["ctrl"] != "AUTH-01"]
    assert all(c["status"] == "unrated" for c in non_auth01), (
        "503 response must produce unrated controls, not a CRITICAL from server-error HTML"
    )


def test_empty_body_controls_unrated(stub_empty_body):
    """Near-empty body (JS-only SPA shell) → controls unrated, not CRITICAL from no content."""
    ctrls = scanner.analyze_agent("https://example.com", "MyAgent")["data"]["controls"]
    non_auth01 = [c for c in ctrls if c["ctrl"] != "AUTH-01"]
    assert all(c["status"] == "unrated" for c in non_auth01), (
        "near-empty body must produce unrated controls, not CRITICAL"
    )


def test_successful_fetch_unchanged(stub_network):
    """A successful fetch continues to produce the same full scan result (regression guard)."""
    d = _scan()["data"]
    assert d["score_pct"] == 25.9
    assert d["band"] == "CRITICAL"
    assert len(d["controls"]) == 38
    assert all(c["status"] != "unrated" for c in d["controls"]), (
        "successful fetch must not mark controls as unrated"
    )


# ---------------------------------------------------------------------------
# Bug 2 — score_pct and final_score must be the same number (0–100 %)
# (all tests below are RED before implementation)
# ---------------------------------------------------------------------------


def test_final_score_equals_score_pct_full_scan(stub_network):
    """Full scan: final_score == score_pct (both 0–100 %, not raw points)."""
    d = _scan()["data"]
    assert d["final_score"] == d["score_pct"], (
        f"full scan: final_score ({d['final_score']}) != score_pct ({d['score_pct']})"
    )


def test_final_score_equals_score_pct_no_website():
    """No-website scan: final_score == score_pct."""
    d = scanner.analyze_agent("", "SomeAgent")["data"]
    assert d["final_score"] == d["score_pct"], (
        f"no-website: final_score ({d['final_score']}) != score_pct ({d['score_pct']})"
    )


def test_final_score_equals_score_pct_limited():
    """Limited (social-media) scan: final_score == score_pct."""
    d = scanner.analyze_agent("https://x.com/agent", "SomeAgent")["data"]
    assert d["final_score"] == d["score_pct"], (
        f"limited: final_score ({d['final_score']}) != score_pct ({d['score_pct']})"
    )


def test_final_score_equals_score_pct_fetch_fail(stub_fetch_fail):
    """Fetch-failed scan: final_score == score_pct."""
    d = scanner.analyze_agent("https://example.com", "MyAgent")["data"]
    assert d["final_score"] == d["score_pct"], (
        f"fetch-fail: final_score ({d['final_score']}) != score_pct ({d['score_pct']})"
    )


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
