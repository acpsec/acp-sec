"""Origin & Transparency dimension (task 2.8)."""

from acpsec_api.b20.dimensions import run_origin_transparency
from acpsec_api.b20.models import ScanInputs


def _inp(**kw) -> ScanInputs:
    return ScanInputs(token="0xB200", chain_id=8453, **kw)


def test_strong_origin_scores_full():
    r = run_origin_transparency(_inp(
        issuer_wallet_age_days=400, issuer_has_history=True,
        verified_entity=True, public_docs=True, announcement_events=True,
    ))
    assert r.name == "origin_transparency"
    assert r.weight == 0.10
    assert r.score == 100


def test_fresh_wallet_penalized():
    base = run_origin_transparency(_inp(issuer_wallet_age_days=400)).score
    r = run_origin_transparency(_inp(issuer_wallet_age_days=5))
    assert r.score < base
    assert any("wallet" in f.detail.lower() for f in r.findings)


def test_no_public_docs_penalized():
    base = run_origin_transparency(_inp(public_docs=True)).score
    r = run_origin_transparency(_inp(public_docs=False))
    assert r.score < base


def test_unknown_origin_is_unrated():
    assert run_origin_transparency(_inp()).rated is False
