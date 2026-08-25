"""Canonical output models + serialization (spec: b20-trust-scoring)."""

from acpsec_api.b20.models import (
    DimensionResult,
    Finding,
    IssuerPowers,
    ScanInputs,
    ScanResult,
)


def _sample_result() -> ScanResult:
    powers = IssuerPowers(
        can_freeze=True,
        can_seize=True,
        can_burn_blocked=False,
        can_pause=True,
        can_mint_unbounded=False,
        supply_cap="1000000000000000000000000",
        admin_addresses=["0xaaa", "0xbbb"],
        admin_is_multisig=True,
        mint_role_holders=["0xccc"],
        pause_role_holders=["0xddd"],
    )
    dim = DimensionResult(
        name="supply_integrity",
        score=90.0,
        weight=0.25,
        rated=True,
        findings=[Finding(severity="Medium", detail="x")],
    )
    return ScanResult(
        token="0xB200",
        chain_id=8453,
        variant="ASSET",
        name="Foo",
        symbol="FOO",
        decimals=18,
        currency_code=None,
        trust_score=76,
        raw_score=76,
        grade="B",
        is_critical=False,
        critical_reasons=[],
        rated=True,
        multiplier=1.0,
        unrated_dimensions=[],
        read_diagnostics={},
        dimensions={dim.name: dim},
        issuer_powers=powers,
        deployed_via_factory="0xB20f000000000000000000000000000000000000",
        scanner_version="0.6.0",
        scanned_at="2026-06-22T00:00:00Z",
    )


def test_top_level_keys_match_canonical_schema():
    d = _sample_result().to_dict()
    assert set(d.keys()) == {
        "token", "chain_id", "variant", "name", "symbol", "decimals",
        "currency_code", "trust_score", "raw_score", "grade", "rated",
        "multiplier", "unrated_dimensions", "read_diagnostics", "is_critical",
        "critical_reasons", "dimensions", "issuer_powers", "deployed_via_factory",
        "scanner_version", "scanned_at", "evidence",
    }


def test_dimensions_serialized_as_score_weight_rated_findings():
    d = _sample_result().to_dict()
    sup = d["dimensions"]["supply_integrity"]
    assert set(sup.keys()) == {"score", "rated", "weight", "findings"}
    assert sup["score"] == 90.0
    assert sup["rated"] is True
    assert sup["weight"] == 0.25
    assert sup["findings"] == [{"severity": "Medium", "detail": "x", "evidence": None}]


def test_issuer_powers_block_keys():
    d = _sample_result().to_dict()
    assert set(d["issuer_powers"].keys()) == {
        "can_freeze", "can_seize", "can_burn_blocked", "can_pause",
        "can_mint_unbounded", "supply_cap", "admin_addresses",
        "admin_is_multisig", "mint_role_holders", "pause_role_holders",
    }
    assert d["issuer_powers"]["can_freeze"] is True
    assert d["issuer_powers"]["supply_cap"] == "1000000000000000000000000"


# ---------------------------------------------------------------------------
# Gap 1: DimensionResult.to_dict() — score:null + rated:bool
# ---------------------------------------------------------------------------

def test_rated_dimension_serializes_score_as_number_and_rated_true():
    dim = DimensionResult(name="supply_integrity", score=85.0, weight=0.25, rated=True)
    d = dim.to_dict()
    assert d["score"] == 85.0
    assert d["rated"] is True


def test_unrated_dimension_serializes_score_as_null_and_rated_false():
    dim = DimensionResult(name="issuer_authority", score=100.0, weight=0.30, rated=False)
    d = dim.to_dict()
    assert d["score"] is None
    assert d["rated"] is False


def test_unrated_dimension_score_null_not_100():
    # The false-safe: absence must not look like a perfect score.
    dim = DimensionResult(name="issuer_authority", score=100.0, weight=0.30, rated=False)
    d = dim.to_dict()
    assert d["score"] != 100.0


def test_dimension_dict_includes_rated_key():
    dim = DimensionResult(name="supply_integrity", score=85.0, weight=0.25, rated=True)
    assert "rated" in dim.to_dict()


def test_scan_inputs_constructs_with_unknown_defaults():
    # All on-chain fields default to None (unknown) so a reader can fill in only
    # what it could read; the engine treats None as unrated.
    inp = ScanInputs(token="0xB200", chain_id=8453)
    assert inp.supply_cap is None
    assert inp.admin_holders is None
    assert inp.variant is None
    assert inp.read_diagnostics == {}   # additive read provenance, empty by default
