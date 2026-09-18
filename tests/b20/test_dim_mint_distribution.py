"""#69 — mint-role distribution scored in issuer_authority.

Gap: ``mint_role_holders`` was read (reader) and surfaced (issuer_powers) but
scored in NO dimension, so a second/unaccountable MINT_ROLE holder was
invisible to the score. Mint is an authority question — a MINT_ROLE holder can
dilute holders up to the cap — so it composes here with the admin governance
ladder.

Signal is EOA-ness + admin∩mint overlap, NOT count (all 10 legit tokenized
stocks have exactly 1 mint holder that is a separated CONTRACT, so count does
not discriminate). Classification is honest: ``mint_holders_eoa`` comes from
eth_getCode (empty = EOA); the wording says "non-multisig EOA" / "not a bare
EOA", NEVER "safe" (a contract can be a single-key proxy — same caveat as
admin_is_multisig).

Rated: mint contributes only when mint holders are readable. A silent
zero-event token (mint empty from silence) emits NO mint finding and does not
newly unrate the dimension (#70 doctrine: silent != unread).
"""

from acpsec_api.b20.dimensions import run_issuer_authority
from acpsec_api.b20.engine import assess
from acpsec_api.b20.models import ScanInputs

ADMIN = "0x" + "ad" * 20
EOA_A = "0x" + "e0" * 20
EOA_B = "0x" + "e1" * 20
CONTRACT = "0x" + "c0" * 20


def _inp(**kw) -> ScanInputs:
    return ScanInputs(token="0xB200", chain_id=8453, **kw)


def _has(findings, severity, needle) -> bool:
    return any(f.severity == severity and needle in f.detail.lower() for f in findings)


# --------------------------------------------------------------------------
# HIGH — a bare (non-multisig EOA) mint key can dilute supply to the cap.
# --------------------------------------------------------------------------
def test_eoa_mint_key_separated_from_admin_is_high():
    # unverified, admin is a multisig, one mint key that is a bare EOA, separated
    base = run_issuer_authority(_inp(admin_holders=[ADMIN], admin_is_multisig=True)).score
    r = run_issuer_authority(_inp(
        admin_holders=[ADMIN], admin_is_multisig=True,
        mint_role_holders=[EOA_A], mint_holders_eoa=[EOA_A],
    ))
    assert _has(r.findings, "High", "mint")
    assert r.score < base                     # a bare mint key drops the score
    assert r.rated is True                    # admin governance is known -> rated


def test_verified_does_not_excuse_a_bare_eoa_mint_key():
    # #55 verified gate excuses a separated CONTRACT mint — NOT a bare EOA key.
    r = run_issuer_authority(_inp(
        official_ticker_status="verified",
        admin_holders=[ADMIN], admin_is_multisig=True,
        mint_role_holders=[EOA_A], mint_holders_eoa=[EOA_A],
    ))
    assert _has(r.findings, "High", "mint")
    assert not _has(r.findings, "Info", "mint")     # no free pass


# --------------------------------------------------------------------------
# EXTRA / compounds — a mint holder that ALSO holds admin (no separation).
# --------------------------------------------------------------------------
def test_admin_equals_mint_same_eoa_is_high_plus_overlap():
    # unverified, admin == mint == one bare EOA: worst separation-of-duties case
    sep = run_issuer_authority(_inp(
        admin_holders=[ADMIN], admin_is_multisig=False,
        mint_role_holders=[EOA_A], mint_holders_eoa=[EOA_A],   # separated
    )).score
    overlap = run_issuer_authority(_inp(
        admin_holders=[EOA_A], admin_is_multisig=False,
        mint_role_holders=[EOA_A], mint_holders_eoa=[EOA_A],   # SAME address
    ))
    assert _has(overlap.findings, "High", "mint")             # bare EOA mint High
    assert any("admin" in f.detail.lower() and "mint" in f.detail.lower()
               for f in overlap.findings)                     # the overlap finding
    assert overlap.score < sep                                # overlap compounds


def test_overlap_with_contract_admin_still_flagged_but_milder_than_eoa_overlap():
    # overlap where the shared address is a CONTRACT (admin multisig): still a
    # separation-of-duties finding, but milder than a single-EOA overlap.
    contract_overlap = run_issuer_authority(_inp(
        admin_holders=[CONTRACT], admin_is_multisig=True,
        mint_role_holders=[CONTRACT], mint_holders_eoa=[],     # shared, a contract
    ))
    eoa_overlap = run_issuer_authority(_inp(
        admin_holders=[EOA_A], admin_is_multisig=False,
        mint_role_holders=[EOA_A], mint_holders_eoa=[EOA_A],   # shared, a bare EOA
    ))
    assert any("admin" in f.detail.lower() and "mint" in f.detail.lower()
               for f in contract_overlap.findings)
    # bare-EOA overlap is the worse of the two
    assert eoa_overlap.score < contract_overlap.score


# --------------------------------------------------------------------------
# MEDIUM — multiple bare-EOA mint keys are a larger key surface.
# --------------------------------------------------------------------------
def test_multiple_eoa_mint_keys_adds_medium():
    r = run_issuer_authority(_inp(
        admin_holders=[ADMIN], admin_is_multisig=True,
        mint_role_holders=[EOA_A, EOA_B], mint_holders_eoa=[EOA_A, EOA_B],
    ))
    assert _has(r.findings, "High", "mint")            # bare mint key(s) present
    assert _has(r.findings, "Medium", "multiple")      # + the multi-key medium


# --------------------------------------------------------------------------
# #55 verified gate — a separated CONTRACT mint on a verified stock is expected.
# --------------------------------------------------------------------------
def test_verified_separated_contract_mint_is_info_no_penalty():
    base = run_issuer_authority(_inp(
        official_ticker_status="verified",
        admin_holders=[ADMIN], admin_is_multisig=True,
    )).score
    r = run_issuer_authority(_inp(
        official_ticker_status="verified",
        admin_holders=[ADMIN], admin_is_multisig=True,
        mint_role_holders=[CONTRACT], mint_holders_eoa=[],   # separated contract
    ))
    assert _has(r.findings, "Info", "mint")            # expected-for-verified Info
    assert not _has(r.findings, "High", "mint")
    assert not _has(r.findings, "Medium", "mint")
    assert r.score == base                             # no penalty


def test_verified_info_wording_is_honest_never_says_safe():
    r = run_issuer_authority(_inp(
        official_ticker_status="verified",
        admin_holders=[ADMIN], admin_is_multisig=True,
        mint_role_holders=[CONTRACT], mint_holders_eoa=[],
    ))
    info = next(f for f in r.findings if f.severity == "Info" and "mint" in f.detail.lower())
    assert "not a bare eoa" in info.detail.lower()
    assert "safe" not in info.detail.lower()
    assert "verified multisig" not in info.detail.lower()


# --------------------------------------------------------------------------
# Silent token — mint empty from zero events must NOT invent a finding or unrate.
# --------------------------------------------------------------------------
def test_silent_token_no_mint_finding_dimension_unchanged():
    base = run_issuer_authority(_inp(admin_holders=[ADMIN], admin_is_multisig=True))
    silent = run_issuer_authority(_inp(
        admin_holders=[ADMIN], admin_is_multisig=True,
        mint_role_holders=None, mint_holders_eoa=None,       # unread / silent
    ))
    assert not any("mint" in f.detail.lower() for f in silent.findings)
    assert silent.score == base.score
    assert silent.rated == base.rated


def test_empty_mint_holders_no_finding():
    # readable-but-empty (no mint role granted) — nothing to talk about
    r = run_issuer_authority(_inp(
        admin_holders=[ADMIN], admin_is_multisig=True,
        mint_role_holders=[], mint_holders_eoa=None,
    ))
    assert not any("mint" in f.detail.lower() for f in r.findings)


def test_unreadable_mint_classification_emits_no_eoa_finding():
    # mint holders present but eth_getCode unreadable for all -> no EOA assertion
    r = run_issuer_authority(_inp(
        admin_holders=[ADMIN], admin_is_multisig=True,
        mint_role_holders=[EOA_A], mint_holders_eoa=None,    # classification failed
    ))
    assert not _has(r.findings, "High", "mint")
    assert not _has(r.findings, "Medium", "mint")


# --------------------------------------------------------------------------
# Engine-level: a verified stock whose ADMIN is a single EOA stays F/39 from the
# single_eoa_admin critical — the separated-contract mint adds no penalty.
# --------------------------------------------------------------------------
def test_verified_single_eoa_admin_stays_f39_mint_adds_nothing():
    inp = _inp(
        official_ticker_status="verified",
        admin_holders=[ADMIN], admin_is_multisig=False,          # single EOA admin
        mint_role_holders=[CONTRACT], mint_holders_eoa=[],       # separated contract
        supply_cap=1, can_freeze=False, can_seize=False, is_paused=False,
        factory_is_official=True, symbol="NVDAc",
        issuer_has_history=True, announcements_substantive=0, announcements_total=0,
    )
    res = assess(inp)
    assert res.is_critical is True
    assert any("single_eoa_admin" in reason for reason in res.critical_reasons)
    assert res.trust_score <= 39 and res.grade == "F"
    ia = res.dimensions["issuer_authority"]
    assert _has(ia.findings, "Info", "mint")                     # the verified Info
    assert not _has(ia.findings, "High", "mint")                 # mint no penalty
