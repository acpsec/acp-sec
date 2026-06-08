"""Tests for acpsec/trust_score/data/smart_account_reader.py — TDD.

SmartAccountPermissionReader performs a best-effort on-chain read of an
Alchemy Modular Account V2 session-key contract allowlist to classify the
agent's signer mode as Restricted / Unrestricted, falling back to None
(Unrated) whenever the data is not reachable.
"""

ACP_CORE = "0x238E541BfefD82238730D00a2208E5497F1832E0"
FUND_HOOK = "0x90717828D78731313CB350D6a58b0f91668Ea702"
OTHER = "0x1111111111111111111111111111111111111111"

_UNSET = object()


def _rpc_code(has_code: bool = True):
    def rpc(method: str, params: list):
        if method == "eth_getCode":
            return "0x6060604052" if has_code else "0x"
        return "0x0"
    return rpc


def _rpc_fail():
    def rpc(method: str, params: list):
        raise RuntimeError("rpc down")
    return rpc


def _reader(allowed=None, rpc=None, allowlist_reader=_UNSET):
    from acpsec.trust_score.data.smart_account_reader import SmartAccountPermissionReader
    kwargs = {}
    if allowlist_reader is not _UNSET:
        kwargs["_allowlist_reader"] = allowlist_reader
    return SmartAccountPermissionReader(
        allowed_targets=allowed,
        _rpc=rpc or _rpc_code(True),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Account-type gating — only smart accounts are classifiable
# ---------------------------------------------------------------------------

class TestAccountType:
    def test_eoa_is_unrated(self):
        r = _reader(rpc=_rpc_code(has_code=False), allowlist_reader=lambda a: [])
        assert r.read_signer_mode("0xabc") is None

    def test_rpc_failure_is_unrated(self):
        r = _reader(rpc=_rpc_fail(), allowlist_reader=lambda a: [])
        assert r.read_signer_mode("0xabc") is None


# ---------------------------------------------------------------------------
# Allowlist reader not wired (default) — always Unrated
# ---------------------------------------------------------------------------

class TestAllowlistReaderNotWired:
    def test_default_reader_is_unrated(self):
        # Smart account, but no MA v2 ABI wired → cannot read scope → Unrated.
        r = _reader(allowed=[ACP_CORE], rpc=_rpc_code(True))
        assert r.read_signer_mode("0xabc") is None


# ---------------------------------------------------------------------------
# Signer-mode resolution from a readable allowlist
# ---------------------------------------------------------------------------

class TestSignerModeResolution:
    def test_empty_allowlist_is_unrestricted(self):
        r = _reader(allowed=[ACP_CORE], rpc=_rpc_code(True), allowlist_reader=lambda a: [])
        assert r.read_signer_mode("0xabc") == "Unrestricted"

    def test_subset_of_allowed_is_restricted(self):
        r = _reader(allowed=[ACP_CORE, FUND_HOOK], rpc=_rpc_code(True),
                    allowlist_reader=lambda a: [ACP_CORE])
        assert r.read_signer_mode("0xabc") == "Restricted"

    def test_equal_to_allowed_is_restricted(self):
        r = _reader(allowed=[ACP_CORE, FUND_HOOK], rpc=_rpc_code(True),
                    allowlist_reader=lambda a: [ACP_CORE, FUND_HOOK])
        assert r.read_signer_mode("0xabc") == "Restricted"

    def test_beyond_allowed_is_unrestricted(self):
        r = _reader(allowed=[ACP_CORE], rpc=_rpc_code(True),
                    allowlist_reader=lambda a: [ACP_CORE, OTHER])
        assert r.read_signer_mode("0xabc") == "Unrestricted"

    def test_match_is_case_insensitive(self):
        r = _reader(allowed=[ACP_CORE.lower()], rpc=_rpc_code(True),
                    allowlist_reader=lambda a: [ACP_CORE.upper()])
        assert r.read_signer_mode("0xabc") == "Restricted"

    def test_nonempty_allowlist_without_reference_is_unrated(self):
        r = _reader(allowed=None, rpc=_rpc_code(True),
                    allowlist_reader=lambda a: [ACP_CORE])
        assert r.read_signer_mode("0xabc") is None

    def test_allowlist_reader_returns_none_is_unrated(self):
        r = _reader(allowed=[ACP_CORE], rpc=_rpc_code(True),
                    allowlist_reader=lambda a: None)
        assert r.read_signer_mode("0xabc") is None

    def test_allowlist_reader_raises_is_unrated(self):
        def boom(a):
            raise RuntimeError("decode error")
        r = _reader(allowed=[ACP_CORE], rpc=_rpc_code(True), allowlist_reader=boom)
        assert r.read_signer_mode("0xabc") is None
