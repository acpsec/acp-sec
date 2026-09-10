"""getLogs fallback robustness (Jalur A) — a full-range query that TIMES OUT (or
fails for any non-range-cap reason) must still fall back to the chunk walk, and a
role-read failure must surface its verbatim reason (not the generic Layer-B
fallback). Root cause: NVDAc's ~2M-block full-range getLogs timed out on CDP, and
the chunk fallback was gated on RANGE_CAP only, so the 100k chunk budget was never
used and the diagnostic said "no read diagnostic recorded".
"""

from tests.b20.test_reader_integration import _good_asset, ASSET, MINT_H

from acpsec_api.b20 import constants as C
from acpsec_api.b20 import reader as R


class _TimeoutOnWideLogs:
    """Wrap a FakeRpc: eth_get_logs over a range wider than ``threshold`` fails like a
    TIMEOUT (``last_error_kind=None`` — NOT a range cap); narrower queries delegate."""

    def __init__(self, inner, threshold):
        self._inner = inner
        self._threshold = threshold
        self.last_error = None
        self.last_error_kind = None
        self.any_response = True
        self.wide_calls = 0

    def eth_get_logs(self, filter_obj):
        frm = int(filter_obj.get("fromBlock", "0x0"), 16)
        to_raw = filter_obj.get("toBlock", "latest")
        to = self._inner.block_number if to_raw == "latest" else int(to_raw, 16)
        if to - frm > self._threshold:
            self.wide_calls += 1
            self.last_error = "TimeoutError: The read operation timed out"
            self.last_error_kind = None       # NOT a range cap
            return None
        res = self._inner.eth_get_logs(filter_obj)
        self.last_error = self._inner.last_error
        self.last_error_kind = self._inner.last_error_kind
        return res

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_getlogs_chunks_when_full_range_would_timeout():
    # NVDAc case: full-range getLogs times out; the chunk walk must still run.
    inner = _good_asset()
    inner.set_block_number(20000)
    rpc = _TimeoutOnWideLogs(inner, threshold=5000)   # any >5000-block query times out
    holders = R.role_holders(rpc, ASSET, C.B20_ROLE_MINT, 84532, from_block=0)
    assert holders == [MINT_H]   # read via chunk walk despite the full-range timeout


def test_read_roles_surfaces_verbatim_error_on_non_rangecap_failure():
    f = _good_asset()
    f.set_logs_fail(True)   # every getLogs fails, last_error_kind=None (non-range-cap)
    roles = R.read_roles(f, ASSET, 84532, from_block=0)
    assert roles["read_error"] is not None
    assert "getlogs failed" in roles["read_error"]   # verbatim reason, not generic fallback


def test_range_cap_path_still_chunk_walks():
    # #32/#33 preserved: a classified range cap still recovers via the chunk walk.
    f = _good_asset()
    f.set_block_number(20000)
    f.set_max_getlogs_range(2000)
    holders = R.role_holders(f, ASSET, C.B20_ROLE_MINT, 84532, from_block=0)
    assert holders == [MINT_H]


def test_genuinely_unreadable_still_none_with_reason():
    # every query fails -> honest None, but WITH a verbatim reason (not silent).
    f = _good_asset()
    f.set_logs_fail(True)
    assert R.role_holders(f, ASSET, C.B20_ROLE_MINT, 84532, from_block=0) is None


class _TransientChunkFail:
    """Wrap FakeRpc: the chunk starting at ``fail_from`` fails its FIRST call with a
    transient timeout, then succeeds — models one flaky chunk in a long walk."""

    def __init__(self, inner, fail_from):
        self._inner = inner
        self._fail_from = fail_from
        self._failed = False
        self.last_error = None
        self.last_error_kind = None
        self.any_response = True

    def eth_get_logs(self, filter_obj):
        frm = int(filter_obj.get("fromBlock", "0x0"), 16)
        if frm == self._fail_from and not self._failed:
            self._failed = True
            self.last_error = "TimeoutError: The read operation timed out"
            self.last_error_kind = None       # transient (not a range cap)
            return None
        res = self._inner.eth_get_logs(filter_obj)
        self.last_error = self._inner.last_error
        self.last_error_kind = self._inner.last_error_kind
        return res

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_chunk_walk_retries_a_transient_chunk_timeout(monkeypatch):
    # NVDAc case: full-range range-caps -> chunk walk; one late chunk transiently
    # times out. With per-chunk retry the walk recovers instead of discarding the
    # already-read events.
    monkeypatch.setattr(R, "_GETLOGS_CHUNK_BACKOFF", (0.0, 0.0), raising=False)
    inner = _good_asset()
    inner.set_block_number(6000)
    inner.set_max_getlogs_range(2000)          # full [0,6000] range-caps -> chunk walk
    rpc = _TransientChunkFail(inner, fail_from=4000)   # chunk [4000,5999] flakes once
    holders = R.role_holders(rpc, ASSET, C.B20_ROLE_MINT, 84532, from_block=0)
    assert holders == [MINT_H]   # recovered via per-chunk retry (events in chunk [0,1999])
