"""POST /api/b20/preflight endpoint — RED CHECKPOINT (task 01).

The route + its injection seam (`b20.get_preflight_fn`) do NOT exist yet, so:
- openapi/validation tests fail on the 404 (route absent);
- the verdict-body test fails when it references the absent `get_preflight_fn` seam.

Mirrors tests/api/test_b20.py (dependency_overrides, no network). Defines the
endpoint contract; see docs/b20-preflight-design-v1.md.
"""

import pytest
from fastapi.testclient import TestClient

from acpsec_api.main import app as fastapi_app
from acpsec_api.routers import b20

TOKEN = "0x" + "b2" * 20
FROM = "0x" + "f1" * 20
TO = "0x" + "70" * 20


def _body(token=TOKEN, chain_id=8453, amount="100"):
    return {"token": token, "chain_id": chain_id, "from": FROM, "to": TO, "amount": amount}


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    for name in ("get_preflight_fn", "get_rpc_factory"):
        dep = getattr(b20, name, None)
        if dep is not None:
            fastapi_app.dependency_overrides.pop(dep, None)


def _post(c, **kw):
    return c.post("/api/b20/preflight", json=_body(**kw))


def test_openapi_exposes_preflight():
    schema = TestClient(fastapi_app).get("/openapi.json").json()
    assert "/api/b20/preflight" in schema["paths"]
    assert "post" in schema["paths"]["/api/b20/preflight"]


def test_preflight_invalid_address_returns_400():
    r = _post(TestClient(fastapi_app), token="0xnothex")
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_address"


def test_preflight_unsupported_chain_returns_400():
    r = _post(TestClient(fastapi_app), chain_id=1)
    assert r.status_code == 400
    assert r.json()["error"] == "unsupported_chain"


def test_preflight_returns_verdict_body():
    # Inject a canned verdict via the seam so the endpoint contract is testable
    # without network. RED now: b20.get_preflight_fn does not exist.
    canned = {
        "verdict": "deny",
        "reasons": [{"code": "policy_forbids", "detail": "blocked",
                     "scope": "TRANSFER_SENDER_POLICY", "policy_id": 2}],
        "as_of_block": 123,
        "evidence_tier": "verified",
    }

    class _V:
        def to_dict(self):
            return canned

    def fake_preflight(token, chain_id, from_addr, to_addr, amount, *, rpc=None):
        return _V()

    fastapi_app.dependency_overrides[b20.get_preflight_fn] = lambda: fake_preflight
    r = _post(TestClient(fastapi_app))
    assert r.status_code == 200
    assert r.json() == canned
