"""Transfer Policy Risk dimension (task 2.6)."""

from acpsec_api.b20.dimensions import run_transfer_policy
from acpsec_api.b20.models import ScanInputs


def _inp(**kw) -> ScanInputs:
    return ScanInputs(token="0xB200", chain_id=8453, **kw)


def test_benign_policy_scores_high():
    r = run_transfer_policy(_inp(
        can_freeze=False, can_seize=False, can_pause=False, is_paused=False,
        policy_registry_active=False, memo_required=False, asymmetric_policy=False,
    ))
    assert r.name == "transfer_policy"
    assert r.weight == 0.20
    assert r.score == 100


def test_freeze_seize_without_transparency_is_high_penalty():
    no_transparency = run_transfer_policy(_inp(
        can_freeze=True, can_seize=True, public_docs=False,
    ))
    with_transparency = run_transfer_policy(_inp(
        can_freeze=True, can_seize=True, public_docs=True,
    ))
    assert no_transparency.score < with_transparency.score
    assert any(f.severity == "High" for f in no_transparency.findings)


def test_currently_paused_is_penalized_high():
    r = run_transfer_policy(_inp(is_paused=True))
    assert any("paus" in f.detail.lower() and f.severity == "High" for f in r.findings)
    assert r.score < 100


def test_unknown_policy_is_unrated():
    assert run_transfer_policy(_inp()).rated is False
