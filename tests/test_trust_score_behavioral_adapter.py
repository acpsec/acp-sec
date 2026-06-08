"""Tests for acpsec/trust_score/data/behavioral_adapter.py — TDD RED."""

import pytest

from acpsec.trust_score.dimensions.behavioral import BehavioralInput


# ---------------------------------------------------------------------------
# Helpers — injectable RPC stubs
# ---------------------------------------------------------------------------

_ZERO_ADDR = "0x" + "0" * 64          # padded zero address
_SOME_ADDR  = "0x" + "a" * 64          # padded non-zero address
_ADDR_B     = "0x" + "b" * 64
_ADDR_C     = "0x" + "c" * 64


def _make_log(topics: list[str], data: str = "0x0") -> dict:
    return {"topics": topics, "data": data}


def _rpc_with_logs(logs: list[dict], latest_block: int = 20_000):
    """Injectable RPC that returns `logs` for eth_getLogs and `latest_block` for eth_blockNumber."""
    def rpc(method: str, params: list):
        if method == "eth_blockNumber":
            return hex(latest_block)
        if method == "eth_getLogs":
            from_block = int(params[0]["fromBlock"], 16)
            to_block   = int(params[0]["toBlock"], 16)
            # Return all logs — tests don't need block-range filtering
            return logs
        return "0x0"
    return rpc


def _rpc_failing():
    def rpc(method: str, params: list):
        raise RuntimeError("RPC unavailable")
    return rpc


def _adapter(rpc=None, block_window: int = 10_000):
    from acpsec.trust_score.data.behavioral_adapter import BehavioralAdapter
    return BehavioralAdapter(block_window=block_window, _rpc=rpc or _rpc_with_logs([]))


# ---------------------------------------------------------------------------
# fetch() — return type and defaults
# ---------------------------------------------------------------------------

class TestDefaults:
    def test_returns_behavioral_input(self):
        result = _adapter().fetch("0xABCD")
        assert isinstance(result, BehavioralInput)

    def test_no_logs_no_fund_loss(self):
        assert _adapter().fetch("0xABCD").fund_loss_incident is False

    def test_no_logs_empty_counterparty_jobs(self):
        assert _adapter().fetch("0xABCD").counterparty_jobs == []

    def test_no_logs_no_volume_spike(self):
        assert _adapter().fetch("0xABCD").volume_spike is False

    def test_dispute_rate_always_zero(self):
        # No on-chain source for dispute rates without subgraph
        assert _adapter().fetch("0xABCD").dispute_rate == 0.0

    def test_failed_delivery_rate_always_zero(self):
        assert _adapter().fetch("0xABCD").failed_delivery_rate == 0.0

    def test_rpc_failure_returns_defaults_not_raises(self):
        result = _adapter(_rpc_failing()).fetch("0xABCD")
        assert isinstance(result, BehavioralInput)

    def test_rpc_failure_no_fund_loss(self):
        assert _adapter(_rpc_failing()).fetch("0xABCD").fund_loss_incident is False


# ---------------------------------------------------------------------------
# Counterparty diversity — unique topic[1] addresses → counterparty_jobs list
# ---------------------------------------------------------------------------

class TestCounterpartyDiversity:
    def test_single_caller_one_entry(self):
        logs = [_make_log([_ZERO_ADDR, _SOME_ADDR])]
        result = _adapter(_rpc_with_logs(logs)).fetch("0xABCD")
        assert len(result.counterparty_jobs) == 1

    def test_two_distinct_callers_two_entries(self):
        logs = [
            _make_log([_ZERO_ADDR, _SOME_ADDR]),
            _make_log([_ZERO_ADDR, _ADDR_B]),
        ]
        result = _adapter(_rpc_with_logs(logs)).fetch("0xABCD")
        assert len(result.counterparty_jobs) == 2

    def test_same_caller_twice_one_entry_count_two(self):
        logs = [
            _make_log([_ZERO_ADDR, _SOME_ADDR]),
            _make_log([_ZERO_ADDR, _SOME_ADDR]),
        ]
        result = _adapter(_rpc_with_logs(logs)).fetch("0xABCD")
        assert len(result.counterparty_jobs) == 1
        assert result.counterparty_jobs[0] == 2

    def test_mixed_callers_counts_correct(self):
        # _SOME_ADDR: 3 times, _ADDR_B: 2 times, _ADDR_C: 1 time
        logs = (
            [_make_log([_ZERO_ADDR, _SOME_ADDR])] * 3
            + [_make_log([_ZERO_ADDR, _ADDR_B])] * 2
            + [_make_log([_ZERO_ADDR, _ADDR_C])] * 1
        )
        result = _adapter(_rpc_with_logs(logs)).fetch("0xABCD")
        assert sorted(result.counterparty_jobs, reverse=True) == [3, 2, 1]

    def test_logs_without_topic1_skipped(self):
        # Log with only one topic (no from-address topic)
        logs = [{"topics": ["0xsometopic"], "data": "0x0"}]
        result = _adapter(_rpc_with_logs(logs)).fetch("0xABCD")
        assert result.counterparty_jobs == []


# ---------------------------------------------------------------------------
# Volume spike detection
# ---------------------------------------------------------------------------

class TestVolumeSpike:
    def _rpc_two_windows(self, full_count: int, recent_count: int, latest: int = 20_000):
        """Returns different log counts depending on which block window is queried."""
        def rpc(method: str, params: list):
            if method == "eth_blockNumber":
                return hex(latest)
            if method == "eth_getLogs":
                from_block = int(params[0]["fromBlock"], 16)
                span = latest - from_block
                # recent window is 1/10 of full window
                if span <= (latest // 10) + 1:
                    return [_make_log([_ZERO_ADDR, _SOME_ADDR])] * recent_count
                return [_make_log([_ZERO_ADDR, _SOME_ADDR])] * full_count
            return "0x0"
        return rpc

    def test_uniform_log_distribution_no_spike(self):
        # full window: 100 logs / 10 000 blocks = 0.01/block
        # recent window: 10 logs / 1 000 blocks = 0.01/block — same rate, no spike
        rpc = self._rpc_two_windows(full_count=100, recent_count=10, latest=20_000)
        result = _adapter(rpc, block_window=10_000).fetch("0xABCD")
        assert result.volume_spike is False

    def test_spike_detected_when_recent_rate_double_historical(self):
        # full: 100 / 10 000 = 0.01/block; recent: 40 / 1 000 = 0.04/block → 4× spike
        rpc = self._rpc_two_windows(full_count=100, recent_count=40, latest=20_000)
        result = _adapter(rpc, block_window=10_000).fetch("0xABCD")
        assert result.volume_spike is True

    def test_no_logs_no_spike(self):
        result = _adapter(_rpc_with_logs([])).fetch("0xABCD")
        assert result.volume_spike is False


# ---------------------------------------------------------------------------
# Fund-loss incident detection
# ---------------------------------------------------------------------------

class TestFundLossDetection:
    def test_no_logs_no_fund_loss(self):
        result = _adapter(_rpc_with_logs([])).fetch("0xABCD")
        assert result.fund_loss_incident is False

    def test_transfer_to_zero_address_flags_fund_loss(self):
        # Transfer to 0x000...000 (burn / potential loss)
        zero_padded = "0x" + "0" * 64
        logs = [_make_log([_ZERO_ADDR, _SOME_ADDR, zero_padded])]
        result = _adapter(_rpc_with_logs(logs)).fetch("0xABCD")
        assert result.fund_loss_incident is True

    def test_normal_transfer_no_fund_loss(self):
        logs = [_make_log([_ZERO_ADDR, _SOME_ADDR, _ADDR_B])]
        result = _adapter(_rpc_with_logs(logs)).fetch("0xABCD")
        assert result.fund_loss_incident is False
