"""B20 router (Task 7.1b) — POST /api/b20/scan.

Ported from acp-sec-b20's test_api.py, adapted to acpsec_api's shared app + the
POST body. Mocked reader/rpc via dependency_overrides — no live network.
"""

import pytest
from fastapi.testclient import TestClient

from acpsec_api.b20.engine import assess
from acpsec_api.b20.models import ScanInputs
from acpsec_api.main import app as fastapi_app
from acpsec_api.routers import b20

ADDR = "0x" + "b2" * 20
_FACTORY = "0xB20f000000000000000000000000000000000000"
_FIXED_TS = "2026-01-01T00:00:00Z"


# --- fixtures (verbatim inputs from the source suite) ---------------------
def good_inputs(token: str = ADDR) -> ScanInputs:
    return ScanInputs(
        token=token, chain_id=8453, variant="ASSET", decimals=18,
        admin_holders=[token], admin_is_multisig=True, pause_role_holders=[],
        supply_cap=10**24, multiplier_active=False, burn_enabled=False,
        policy_registry_active=False, can_freeze=True, can_seize=True,
        can_pause=False, is_paused=False, memo_required=False, asymmetric_policy=False,
        deployed_via_factory=_FACTORY, factory_is_official=True,
        issuer_has_history=True, public_docs=True, verified_entity=True,
        announcement_events=True,
    )


def none_inputs(token: str = ADDR) -> ScanInputs:
    return ScanInputs(token=token, chain_id=8453)


class FakeConn:
    def __init__(self, attempts, any_response):
        self.attempts = attempts
        self.any_response = any_response


def fake_read(inputs):
    def _read(address, chain_id, *, rpc=None):
        return inputs
    return _read


class SpyRead:
    def __init__(self, inputs):
        self.inputs = inputs
        self.calls = []

    def __call__(self, address, chain_id, *, rpc=None):
        self.calls.append((address, chain_id))
        return self.inputs


@pytest.fixture(autouse=True)
def _clear_b20_overrides():
    yield
    for dep in (b20.get_read_fn, b20.get_scorer, b20.get_rpc_factory):
        fastapi_app.dependency_overrides.pop(dep, None)


def make_client(*, read_fn=None, rpc_factory=None, scorer=None) -> TestClient:
    if read_fn is not None:
        fastapi_app.dependency_overrides[b20.get_read_fn] = lambda: read_fn
    if scorer is not None:
        fastapi_app.dependency_overrides[b20.get_scorer] = lambda: scorer
    if rpc_factory is not None:
        fastapi_app.dependency_overrides[b20.get_rpc_factory] = lambda: rpc_factory
    return TestClient(fastapi_app)


def _post(c, address=ADDR, chain_id=8453):
    return c.post("/api/b20/scan", json={"address": address, "chain_id": chain_id})


# --- success + shape ------------------------------------------------------
def test_scan_success_returns_200_and_canonical_shape():
    c = make_client(read_fn=fake_read(good_inputs()))
    r = _post(c)
    assert r.status_code == 200
    body = r.json()
    assert body["token"] == ADDR
    assert set(body["dimensions"].keys())
    assert isinstance(body["trust_score"], int)
    assert body["grade"] in {"A", "B", "C", "D", "F"}


def test_scan_all_unrated_is_200():
    c = make_client(
        read_fn=fake_read(none_inputs()),
        rpc_factory=lambda cid: FakeConn(attempts=10, any_response=True),
    )
    r = _post(c)
    assert r.status_code == 200
    assert r.json()["rated"] is False


# --- validation + error responses -----------------------------------------
def test_invalid_address_returns_400_without_reading():
    spy = SpyRead(good_inputs())
    c = make_client(read_fn=spy)
    r = _post(c, address="0xnothex")
    assert r.status_code == 400
    body = r.json()
    assert set(body.keys()) == {"error", "detail"}
    assert body["error"] == "invalid_address"
    assert spy.calls == []


def test_unsupported_chain_returns_400_without_reading():
    spy = SpyRead(good_inputs())
    c = make_client(read_fn=spy)
    r = _post(c, chain_id=1)
    assert r.status_code == 400
    body = r.json()
    assert set(body.keys()) == {"error", "detail"}
    assert body["error"] == "unsupported_chain"
    assert spy.calls == []


def test_rpc_entirely_unreachable_returns_503():
    c = make_client(
        read_fn=fake_read(none_inputs()),
        rpc_factory=lambda cid: FakeConn(attempts=3, any_response=False),
    )
    r = _post(c)
    assert r.status_code == 503
    assert r.json()["error"] == "rpc_unreachable"


def test_rpc_factory_construction_failure_returns_503():
    def boom(_cid):
        raise RuntimeError("dns fail")
    c = make_client(read_fn=fake_read(good_inputs()), rpc_factory=boom)
    r = _post(c)
    assert r.status_code == 503
    assert r.json()["error"] == "rpc_unreachable"


def test_b20_unavailable_returns_400_not_b20():
    from acpsec_api.b20.reader import B20Unavailable

    def boom(address, chain_id, *, rpc=None):
        raise B20Unavailable("not a B20 token (factory.isB20 == false)")
    c = make_client(read_fn=boom)
    r = _post(c)
    assert r.status_code == 400
    body = r.json()
    assert set(body.keys()) == {"error", "detail"}
    assert body["error"] == "not_b20"
    assert "not a B20 token" in body["detail"]


def test_isb20_false_refusal_returns_400_not_b20_with_enriched_detail():
    # End-to-end via the REAL read_token against a FakeRpc where the official
    # factory reports isB20 == false. Contract stays 400 / not_b20; the detail now
    # explains the cause (B20 security reads do not apply), not a bare flag.
    from tests.b20.conftest import FakeRpc

    fake = FakeRpc(8453).set_is_b20(ADDR, False)
    c = make_client(rpc_factory=lambda cid: fake)  # default read_fn = real read_token
    r = _post(c)
    assert r.status_code == 400                      # status unchanged
    body = r.json()
    assert set(body.keys()) == {"error", "detail"}
    assert body["error"] == "not_b20"               # error code unchanged
    detail = body["detail"].lower()
    assert "not a b20" in detail                     # cause named
    assert "do not apply" in detail or "security" in detail  # the enrichment


# --- single-payload multi-layer contract ----------------------------------
def test_one_response_serves_all_three_layers():
    c = make_client(read_fn=fake_read(good_inputs()))
    body = _post(c).json()

    canonical = set(assess(good_inputs()).to_dict().keys())
    assert set(body.keys()) == canonical
    for k in ("trust_score", "grade", "is_critical", "issuer_powers"):
        assert k in body
    assert {"can_freeze", "can_seize", "can_pause", "can_mint_unbounded"} <= set(
        body["issuer_powers"].keys())
    assert body["dimensions"]
    for dim in body["dimensions"].values():
        assert set(dim.keys()) == {"score", "rated", "weight", "findings"}
    for k in ("raw_score", "multiplier", "unrated_dimensions",
              "critical_reasons", "scanner_version", "scanned_at"):
        assert k in body


# --- byte-parity: endpoint body == vendored engine output -----------------
def test_scan_body_byte_parity_with_engine():
    """With a fixed scanned_at (via the scorer seam), the POST response body is
    byte-identical to the vendored engine's ScanResult.to_dict()."""
    c = make_client(
        read_fn=fake_read(good_inputs()),
        scorer=lambda inp: assess(inp, scanned_at=_FIXED_TS),
    )
    body = _post(c).json()
    expected = assess(good_inputs(), scanned_at=_FIXED_TS).to_dict()
    assert body == expected


def test_openapi_exposes_b20_scan():
    c = TestClient(fastapi_app)
    schema = c.get("/openapi.json").json()
    assert "/api/b20/scan" in schema["paths"]
    assert "post" in schema["paths"]["/api/b20/scan"]
