"""Variant & Config dimension (task 2.7)."""

from acpsec_api.b20.dimensions import run_variant_config
from acpsec_api.b20.models import ScanInputs


def _inp(**kw) -> ScanInputs:
    return ScanInputs(token="0xB200", chain_id=8453, **kw)


def test_asset_with_valid_decimals_scores_full():
    r = run_variant_config(_inp(variant="ASSET", decimals=18, factory_is_official=True))
    assert r.name == "variant_config"
    assert r.weight == 0.15
    assert r.rated is True
    assert r.score == 100


def test_asset_decimals_out_of_range_penalized():
    r = run_variant_config(_inp(variant="ASSET", decimals=2, factory_is_official=True))
    assert r.score < 100
    assert any("decimals" in f.detail.lower() for f in r.findings)


def test_stablecoin_valid_config_scores_full():
    r = run_variant_config(_inp(
        variant="STABLECOIN", decimals=6, currency_code="USD", factory_is_official=True,
    ))
    assert r.score == 100


def test_stablecoin_bad_currency_code_penalized():
    r = run_variant_config(_inp(
        variant="STABLECOIN", decimals=6, currency_code="usd1", factory_is_official=True,
    ))
    assert r.score < 100
    assert any("currency" in f.detail.lower() for f in r.findings)


def test_stablecoin_wrong_decimals_penalized():
    r = run_variant_config(_inp(
        variant="STABLECOIN", decimals=18, currency_code="USD", factory_is_official=True,
    ))
    assert r.score < 100


def test_unknown_config_is_unrated():
    assert run_variant_config(_inp()).rated is False
