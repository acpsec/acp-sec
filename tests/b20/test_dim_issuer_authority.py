"""Issuer Authority dimension (task 2.4)."""

from acpsec_api.b20.dimensions import run_issuer_authority
from acpsec_api.b20.models import ScanInputs


def _inp(**kw) -> ScanInputs:
    return ScanInputs(token="0xB200", chain_id=8453, **kw)


def test_roles_revoked_is_best():
    r = run_issuer_authority(_inp(admin_roles_revoked=True))
    assert r.name == "issuer_authority"
    assert r.weight == 0.30
    assert r.rated is True
    assert r.score == 100


def test_multisig_admin_is_good_but_penalized_slightly():
    r = run_issuer_authority(_inp(admin_holders=["0xa"], admin_is_multisig=True))
    assert r.rated is True
    assert 80 <= r.score < 100


def test_single_eoa_admin_is_severely_penalized():
    r = run_issuer_authority(_inp(admin_holders=["0xa"], admin_is_multisig=False))
    assert r.score <= 50
    assert any(f.severity == "High" for f in r.findings)


def test_ordering_revoked_better_than_multisig_better_than_eoa():
    revoked = run_issuer_authority(_inp(admin_roles_revoked=True)).score
    multisig = run_issuer_authority(_inp(admin_is_multisig=True)).score
    eoa = run_issuer_authority(_inp(admin_is_multisig=False)).score
    assert revoked > multisig > eoa


def test_pause_held_by_non_multisig_eoa_is_high_penalty():
    base = run_issuer_authority(_inp(admin_is_multisig=True)).score
    with_pause = run_issuer_authority(_inp(
        admin_is_multisig=True,
        pause_role_holders=["0xp"], pause_holder_is_multisig=False,
    ))
    assert with_pause.score < base
    assert any("pause" in f.detail.lower() and f.severity == "High" for f in with_pause.findings)


def test_unknown_admin_data_is_unrated():
    r = run_issuer_authority(_inp())
    assert r.rated is False
