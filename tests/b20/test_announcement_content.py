"""#68 — announcement content-blindness.

Announcements are issuer self-attestation the scanner can't verify, so they're NEVER
a bonus — at most a SUBSTANTIVE one lifts the "no disclosure" penalty. Substantive
⟺ len(description.strip()) >= 8 AND not an exact duplicate of an earlier-seen
stripped description on the same token. Junk (empty/whitespace/under-floor/dup) is
neutral (not counted, not extra-penalized). URIs: format-validate only, NEVER fetch.
Content is surfaced in evidence so consumers can read what the issuer claimed.
Floor = 8 (data: shortest real announcement "Stock Split" = 11).
"""

import urllib.request

from tests.b20.test_reader_integration import _good_asset, ASSET

from acpsec_api.b20 import reader as R
from acpsec_api.b20.dimensions import run_origin_transparency
from acpsec_api.b20.models import ScanInputs


# --------------------------------------------------------------------------
# classify_announcement(desc, uri, seen_stripped) -> (substantive, reason)
# --------------------------------------------------------------------------
def test_classify_empty():
    assert R.classify_announcement("", "", set()) == (False, "empty")


def test_classify_whitespace_is_empty():
    assert R.classify_announcement("    ", "", set()) == (False, "empty")


def test_classify_under_floor():
    assert R.classify_announcement("short", "", set()) == (False, "under 8 chars")  # 5


def test_classify_floor_boundary():
    assert R.classify_announcement("1234567", "", set())[0] is False   # 7 < 8
    assert R.classify_announcement("12345678", "", set())[0] is True   # 8 >= 8


def test_classify_substantive_real_examples():
    assert R.classify_announcement("Stock Split", "", set()) == (True, "substantive")   # 11
    assert R.classify_announcement("Cash Dividend", "", set()) == (True, "substantive")  # 13


def test_classify_exact_duplicate():
    assert R.classify_announcement("Cash Dividend", "", {"Cash Dividend"}) == (False, "duplicate")


def test_classify_distinct_dates_not_duplicate():
    seen = {"0 ETH + 0 CONSOL · 2026-08-07"}
    ok, reason = R.classify_announcement("0 ETH + 0 CONSOL · 2026-08-08", "", seen)
    assert ok is True and reason == "substantive"


def test_classify_never_fetches_uri(monkeypatch):
    called = {"n": 0}
    def boom(*a, **k):
        called["n"] += 1
        raise AssertionError("network fetch attempted!")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    R.classify_announcement("Cash Dividend paid to holders", "https://evil.example/x", set())
    assert called["n"] == 0


# --------------------------------------------------------------------------
# origin_transparency scoring
# --------------------------------------------------------------------------
def _origin(sub, tot, status=None):
    return ScanInputs(token="0xB200", chain_id=8453, issuer_has_history=True,
                      announcements_total=tot, announcements_substantive=sub,
                      official_ticker_status=status)


def test_one_substantive_lifts_absence_penalty():
    r = run_origin_transparency(_origin(sub=1, tot=1))
    assert r.rated is True
    assert r.score == 100.0
    assert not any("announcement" in f.detail.lower() for f in r.findings)


def test_five_substantive_same_as_one_no_bonus():
    assert run_origin_transparency(_origin(1, 1)).score == run_origin_transparency(_origin(5, 5)).score


def test_zero_substantive_junk_unverified_is_low():
    r = run_origin_transparency(_origin(sub=0, tot=5))
    assert r.score == 90.0
    assert any("none substantive" in f.detail.lower() for f in r.findings)


def test_silent_unverified_is_low():
    r = run_origin_transparency(_origin(sub=0, tot=0))
    assert r.score == 90.0
    assert any("no on-chain announcements" in f.detail.lower() for f in r.findings)


def test_verified_zero_is_info_not_low():
    r = run_origin_transparency(_origin(sub=0, tot=0, status="verified"))
    assert r.score == 100.0
    assert any(f.severity == "Info" and "off-chain" in f.detail.lower() for f in r.findings)


def test_unrated_when_substantive_unknown():
    # read failed -> substantive None -> unrated (no-infer discipline)
    assert run_origin_transparency(_origin(sub=None, tot=None)).rated is False


# --------------------------------------------------------------------------
# reader: evidence enrichment + counts (dedup on the same token)
# --------------------------------------------------------------------------
def test_reader_enriches_announcement_evidence_and_counts():
    f = _good_asset().set_announcements_desc(["Cash Dividend paid", "Cash Dividend paid", "   "])
    inp = R.read_token(ASSET, 84532, rpc=f)
    ev = inp.announcement_evidence
    assert len(ev) == 3
    assert ev[0].description == "Cash Dividend paid" and ev[0].substantive is True and ev[0].reason == "substantive"
    assert ev[1].substantive is False and ev[1].reason == "duplicate"
    assert ev[2].substantive is False and ev[2].reason == "empty"
    assert inp.announcements_total == 3
    assert inp.announcements_substantive == 1
