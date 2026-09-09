"""#66 + #55 — tokenized-stock impersonation defense.

symbol()-only, case-insensitive (uppercase-normalized) match against a hardcoded,
chain-scoped allowlist of official Coinbase tokenized stocks (base.org/stocks).
Three states (same doctrine as #70): "verified" | "impersonation" | None.
The allowlist is CODE — the scan path never fetches base.org.
"""

from tests.b20.conftest import FakeRpc, abi_string
from tests.b20 import test_reader_integration as TRI

from acpsec_api.b20 import constants as C
from acpsec_api.b20 import reader as R
from acpsec_api.b20.engine import assess, detect_critical, CRITICAL_IMPERSONATION
from acpsec_api.b20.dimensions import run_variant_config
from acpsec_api.b20.models import ScanInputs

NVDAC_8453 = "0xb20000000000000000000078ee7ce2fE4908108C"      # pinned official
IMP_8453 = "0xb200000000000000000000111111111111111111"       # non-pinned, ASSET byte[10]=00


# --------------------------------------------------------------------------
# classify_official_ticker() — pure helper (symbol, chain_id, token) -> status
# --------------------------------------------------------------------------
def test_impersonation_when_official_symbol_at_wrong_address_8453():
    assert R.classify_official_ticker("NVDAc", 8453, IMP_8453) == "impersonation"


def test_verified_when_official_symbol_at_pinned_address_8453():
    assert R.classify_official_ticker("NVDAc", 8453, NVDAC_8453) == "verified"


def test_verified_is_address_case_insensitive():
    assert R.classify_official_ticker("NVDAc", 8453, NVDAC_8453.lower()) == "verified"


def test_impersonation_case_insensitive_symbol():
    assert R.classify_official_ticker("nvdac", 8453, IMP_8453) == "impersonation"
    assert R.classify_official_ticker("NVDAC", 8453, IMP_8453) == "impersonation"


def test_none_when_symbol_not_official_ticker():
    assert R.classify_official_ticker("BRIAN", 8453, IMP_8453) is None


def test_none_when_symbol_missing():
    assert R.classify_official_ticker(None, 8453, IMP_8453) is None


def test_impersonation_when_official_symbol_on_sepolia():
    # T4 case: official ticker claimed on a chain with NO official issuance.
    assert R.classify_official_ticker("NVDAc", 84532, IMP_8453) == "impersonation"


# --------------------------------------------------------------------------
# Reader: populates name/symbol (#66 baseline gap) + sets the tri-state.
# --------------------------------------------------------------------------
def _asset_with_symbol(chain: int, addr: str, symbol: str, name: str = "Some Name") -> FakeRpc:
    f = TRI._good_asset()                       # fully-readable ASSET fixture
    f.chain_id = chain
    f.set_is_b20(addr, True)
    f.set_is_b20_initialized(addr, True)
    f.set_creation_code(addr, 1, "0xef")
    f.set_selector(C.B20_SELECTOR_NAME, abi_string(name))
    f.set_selector(C.B20_SELECTOR_SYMBOL, abi_string(symbol))
    return f


def test_reader_populates_name_and_symbol():
    inp = R.read_token(IMP_8453, 8453, rpc=_asset_with_symbol(8453, IMP_8453, "SOMEC", "Some Token"))
    assert inp.symbol == "SOMEC"
    assert inp.name == "Some Token"


def test_reader_sets_impersonation_status():
    inp = R.read_token(IMP_8453, 8453, rpc=_asset_with_symbol(8453, IMP_8453, "NVDAc", "NVIDIA"))
    assert inp.official_ticker_status == "impersonation"


def test_reader_sets_verified_status():
    inp = R.read_token(NVDAC_8453, 8453, rpc=_asset_with_symbol(8453, NVDAC_8453, "NVDAc", "NVIDIA"))
    assert inp.official_ticker_status == "verified"


# --------------------------------------------------------------------------
# Engine: impersonation is CRITICAL -> caps composite at F.
# --------------------------------------------------------------------------
def _inp(status):
    return ScanInputs(token=IMP_8453, chain_id=8453, variant="ASSET", symbol="NVDAc",
                      decimals=18, official_ticker_status=status,
                      factory_is_official=True, supply_cap=10**24)


def test_impersonation_is_critical_and_caps_at_F():
    res = assess(_inp("impersonation"))
    assert res.is_critical is True
    assert CRITICAL_IMPERSONATION in res.critical_reasons
    assert res.grade == "F"
    assert res.trust_score <= C.CRITICAL_CAP


def test_verified_is_not_critical():
    assert CRITICAL_IMPERSONATION not in detect_critical(_inp("verified"))
    assert CRITICAL_IMPERSONATION not in detect_critical(_inp(None))


# --------------------------------------------------------------------------
# Dimension: variant_config emits the itemized finding / positive signal.
# --------------------------------------------------------------------------
def test_variant_config_emits_impersonation_finding_with_evidence():
    dim = run_variant_config(_inp("impersonation"))
    texts = " ".join(f.detail for f in dim.findings)
    assert any(f.severity == "High" for f in dim.findings)
    assert "NVDAC" in texts.upper() and "impersonat" in texts.lower()
    assert NVDAC_8453.lower() in texts.lower()   # expected official address as evidence


def test_variant_config_verified_emits_positive_no_penalty():
    dim = run_variant_config(_inp("verified"))
    assert dim.score == 100.0
    assert any("official" in f.detail.lower() for f in dim.findings)


# --------------------------------------------------------------------------
# Metadata-read retry (name/symbol) — the impersonation check is a SECURITY
# feature and must be deterministic on any RPC. symbol() is retried; a genuine
# total failure stays None + records a diagnostic (never guesses).
# --------------------------------------------------------------------------
class _FlakySymbol:
    """Wrap a FakeRpc: return None for the first ``fail_n`` symbol() eth_calls, then delegate."""

    def __init__(self, inner, fail_n):
        self._inner = inner
        self._fail_n = fail_n
        self.symbol_calls = 0

    def eth_call(self, to, data, block="latest"):
        if str(data).startswith(C.B20_SELECTOR_SYMBOL):
            self.symbol_calls += 1
            if self.symbol_calls <= self._fail_n:
                return None
        return self._inner.eth_call(to, data, block)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_symbol_retry_recovers_then_verifies(monkeypatch):
    monkeypatch.setattr(R, "_METADATA_BACKOFF", (0.0, 0.0), raising=False)
    rpc = _FlakySymbol(_asset_with_symbol(8453, NVDAC_8453, "NVDAc", "NVIDIA"), fail_n=2)
    inp = R.read_token(NVDAC_8453, 8453, rpc=rpc)
    assert inp.symbol == "NVDAc"
    assert inp.official_ticker_status == "verified"


def test_symbol_retry_stops_at_3_attempts(monkeypatch):
    monkeypatch.setattr(R, "_METADATA_BACKOFF", (0.0, 0.0), raising=False)
    rpc = _FlakySymbol(_asset_with_symbol(8453, NVDAC_8453, "NVDAc", "NVIDIA"), fail_n=99)
    R.read_token(NVDAC_8453, 8453, rpc=rpc)
    assert rpc.symbol_calls == 3


def test_symbol_read_exhausted_stays_none_with_diagnostic(monkeypatch):
    monkeypatch.setattr(R, "_METADATA_BACKOFF", (0.0, 0.0), raising=False)
    rpc = _FlakySymbol(_asset_with_symbol(8453, NVDAC_8453, "NVDAc", "NVIDIA"), fail_n=99)
    inp = R.read_token(NVDAC_8453, 8453, rpc=rpc)
    assert inp.symbol is None                       # never guessed
    assert inp.official_ticker_status is None        # not verified, not impersonation
    assert "symbol" in inp.read_diagnostics
    assert "could not run" in inp.read_diagnostics["symbol"].lower()
    # surfaced in the assessed output (must SAY it couldn't check)
    out = assess(inp).to_dict()
    assert "variant_config" in out["read_diagnostics"]  # normal unrated path


# --------------------------------------------------------------------------
# Unrate: symbol() unreadable -> the impersonation check can't run -> the whole
# variant_config dimension is UNRATED (same doctrine as #70 can_seize), so the
# uncertainty hits the score (0.5 multiplier), and the diagnostic flows through
# the NORMAL unrated-dimension path (keyed by "variant_config").
# --------------------------------------------------------------------------
def test_variant_config_unrated_when_symbol_unreadable(monkeypatch):
    monkeypatch.setattr(R, "_METADATA_BACKOFF", (0.0, 0.0), raising=False)
    rpc = _FlakySymbol(_asset_with_symbol(8453, NVDAC_8453, "NVDAc", "NVIDIA"), fail_n=99)
    inp = R.read_token(NVDAC_8453, 8453, rpc=rpc)
    res = assess(inp)
    d = res.to_dict()
    assert inp.symbol is None
    assert res.dimensions["variant_config"].rated is False          # UNRATED
    assert "variant_config" in d["unrated_dimensions"]
    assert d["multiplier"] == 0.5                                    # floor drops
    assert "variant_config" in d["read_diagnostics"]                # normal path
    assert "could not run" in d["read_diagnostics"]["variant_config"].lower()


def test_variant_config_rated_when_symbol_readable():
    # readable symbol (verified / impersonation / non-ticker) -> still rated
    for addr, sym in [(NVDAC_8453, "NVDAc"), (IMP_8453, "NVDAc"), (IMP_8453, "GOOD")]:
        inp = R.read_token(addr, 8453, rpc=_asset_with_symbol(8453, addr, sym))
        assert assess(inp).dimensions["variant_config"].rated is True
