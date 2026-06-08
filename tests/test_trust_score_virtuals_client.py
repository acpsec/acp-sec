"""Tests for acpsec/trust_score/data/virtuals_client.py — TDD.

VirtualsClient is the injectable data source for Virtuals-specific signals.
The Agent Card spend limit is genuinely private (self-audit-only): in an
external scan it is not reachable and must resolve to None (Unrated), never a
penalty. In self-audit mode an operator-supplied fetcher provides the card.
"""

from acpsec.trust_score.models import ScanMode

_UNSET = object()


def _client(scan_mode="external", fetcher=_UNSET):
    from acpsec.trust_score.data.virtuals_client import VirtualsClient
    kwargs = {}
    if fetcher is not _UNSET:
        kwargs["_fetcher"] = fetcher
    return VirtualsClient(scan_mode=scan_mode, **kwargs)


# ---------------------------------------------------------------------------
# Sentinel + scan mode
# ---------------------------------------------------------------------------

class TestSentinel:
    def test_sentinel_importable(self):
        from acpsec.trust_score.data.virtuals_client import NOT_REACHABLE_EXTERNAL
        assert NOT_REACHABLE_EXTERNAL is not None


class TestScanMode:
    def test_defaults_to_external(self):
        assert _client().scan_mode == ScanMode.EXTERNAL

    def test_accepts_self_audit(self):
        assert _client(scan_mode="self_audit").scan_mode == ScanMode.SELF_AUDIT


# ---------------------------------------------------------------------------
# Raw spend-limit getter — external returns sentinel
# ---------------------------------------------------------------------------

class TestGetSpendLimitRaw:
    def test_external_returns_sentinel(self):
        from acpsec.trust_score.data.virtuals_client import NOT_REACHABLE_EXTERNAL
        c = _client("external", fetcher=lambda a: {"spend_limit": 100})
        assert c.get_spend_limit("0x") is NOT_REACHABLE_EXTERNAL

    def test_self_audit_returns_value(self):
        c = _client("self_audit", fetcher=lambda a: {"spend_limit": 100})
        assert c.get_spend_limit("0x") == 100

    def test_self_audit_no_fetcher_is_none(self):
        assert _client("self_audit").get_spend_limit("0x") is None

    def test_self_audit_card_unreachable_is_none(self):
        assert _client("self_audit", fetcher=lambda a: None).get_spend_limit("0x") is None


# ---------------------------------------------------------------------------
# Tri-state derivation consumed by Dimension 2
# ---------------------------------------------------------------------------

class TestNoSpendLimitTriState:
    def test_external_is_unrated(self):
        c = _client("external", fetcher=lambda a: {"spend_limit": 100})
        assert c.get_agent_card_no_spend_limit("0x") is None

    def test_self_audit_positive_limit_is_false(self):
        c = _client("self_audit", fetcher=lambda a: {"spend_limit": 100})
        assert c.get_agent_card_no_spend_limit("0x") is False

    def test_self_audit_zero_limit_is_true(self):
        c = _client("self_audit", fetcher=lambda a: {"spend_limit": 0})
        assert c.get_agent_card_no_spend_limit("0x") is True

    def test_self_audit_null_limit_is_true(self):
        c = _client("self_audit", fetcher=lambda a: {"spend_limit": None})
        assert c.get_agent_card_no_spend_limit("0x") is True

    def test_self_audit_absent_field_is_true(self):
        c = _client("self_audit", fetcher=lambda a: {"name": "x"})
        assert c.get_agent_card_no_spend_limit("0x") is True

    def test_self_audit_card_unreachable_is_unrated(self):
        c = _client("self_audit", fetcher=lambda a: None)
        assert c.get_agent_card_no_spend_limit("0x") is None

    def test_self_audit_no_fetcher_is_unrated(self):
        assert _client("self_audit").get_agent_card_no_spend_limit("0x") is None

    def test_self_audit_fetcher_raises_is_unrated(self):
        def boom(a):
            raise RuntimeError("network")
        assert _client("self_audit", fetcher=boom).get_agent_card_no_spend_limit("0x") is None

    def test_self_audit_non_numeric_limit_is_unrated(self):
        c = _client("self_audit", fetcher=lambda a: {"spend_limit": "lots"})
        assert c.get_agent_card_no_spend_limit("0x") is None
