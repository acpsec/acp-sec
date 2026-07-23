"""Parity + contract tests for score WRITE endpoints (Task 2.3b).

Contracts (from dashboard/serve.py):
    POST /api/score          acpsec ('dimensions') or ASF ('controls') format
                             -> 200 {"ok": True, "data": <wire>}
                             -> 400 {"error": <ValueError msg>} on unrecognised format
                             -> 415 {"error": "Content-Type must be application/json"}
    POST /api/score/manual   requires non-empty 'controls'
                             -> 200 {"ok": True, "data": {...source:"manual", acpsec_scoring}}
                             -> 422 {"error": "'controls' list is required and must be non-empty"}
                             -> 415 (not JSON)

Parity note: unlike seeded reads, POST creates state symmetrically in both apps,
so full parity works. It DOES pollute the real Flask/FastAPI store file, so the
parity test cleans up with DELETE on both apps afterwards (see try/finally).
"""

from __future__ import annotations

from acpsec_api.scoring import auto_normalise

_ACPSEC_PAYLOAD = {
    "agent_name": "Acpsec Agent",
    "agent_version": "1.0",
    "band": "SECURE",
    "verdict": "Production-ready with active monitoring",
    "final_score": 92,
    "timestamp": "2026-07-02T00:00:00Z",
    "dimensions": [
        {
            "dimension_id": "AUTH",
            "name": "Authentication & Identity",
            "checks": [
                {
                    "check_id": "AUTH-01",
                    "name": "Agent identity declared",
                    "score": 3,
                    "max_score": 3,
                    "severity": "HIGH",
                    "status": "pass",
                    "evidence": ["Identity block present"],
                    "recommendations": [],
                }
            ],
        }
    ],
}

_ASF_PAYLOAD = {
    "agent_name": "ASF Agent",
    "agent_version": "2.0",
    "band": "HARDENED",
    "verdict": "Minor gaps present, low overall risk",
    "final_score": 85,
    "timestamp": "2026-07-02T00:00:00Z",
    "controls": [
        {"ctrl": "ASF-01", "name": "Source Authentication", "score": 20, "max": 20, "severity": "CRITICAL", "status": "pass"},
    ],
}

_MANUAL_PAYLOAD = {
    "agent_name": "Manual Agent",
    "controls": [
        {"ctrl": "AUTH-01", "name": "Agent identity declared", "score": 3, "max": 3, "severity": "HIGH", "status": "pass"},
        {"ctrl": "CTX-01", "name": "System prompt not extractable", "score": 5, "max": 5, "severity": "CRITICAL", "status": "pass"},
    ],
}


# --- POST /api/score ------------------------------------------------------

def test_post_acpsec_format(isolated_client) -> None:
    client, _store = isolated_client
    resp = client.post("/api/score", json=_ACPSEC_PAYLOAD)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["data"] == auto_normalise(_ACPSEC_PAYLOAD)
    assert body["data"]["source"] == "acpsec"


def test_post_asf_format(isolated_client) -> None:
    client, _store = isolated_client
    resp = client.post("/api/score", json=_ASF_PAYLOAD)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["data"] == auto_normalise(_ASF_PAYLOAD)
    assert body["data"]["source"] == "asf"


def test_post_then_get_roundtrip(isolated_client) -> None:
    client, _store = isolated_client
    client.post("/api/score", json=_ASF_PAYLOAD)
    resp = client.get("/api/score")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "data": auto_normalise(_ASF_PAYLOAD)}


def test_post_invalid_payload(isolated_client) -> None:
    client, _store = isolated_client
    resp = client.post("/api/score", json={"foo": "bar"})
    assert resp.status_code == 400
    assert resp.json() == {
        "error": (
            "Unrecognised JSON format. "
            "Expected 'dimensions' (acpsec output) or 'controls' (dashboard native) key."
        )
    }


def test_post_not_json(isolated_client) -> None:
    client, _store = isolated_client
    resp = client.post("/api/score", content="not json", headers={"Content-Type": "text/plain"})
    assert resp.status_code == 415
    assert resp.json() == {"error": "Content-Type must be application/json"}


# --- POST /api/score/manual ----------------------------------------------

def test_post_manual(isolated_client) -> None:
    client, _store = isolated_client
    resp = client.post("/api/score/manual", json=_MANUAL_PAYLOAD)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    data = body["data"]
    assert data["source"] == "manual"
    assert data["agent_name"] == "Manual Agent"
    assert data["controls"] == _MANUAL_PAYLOAD["controls"]
    # Golden band/verdict frozen from the acpsec ScoringEngine while the Flask
    # parity test (test_post_parity_with_flask) still passed — see PR A1.
    # _MANUAL_PAYLOAD is a perfect score (AUTH-01 3/3 + CTX-01 5/5) → EXEMPLARY.
    assert data["acpsec_scoring"] is True
    assert data["band"] == "EXEMPLARY"
    assert data["verdict"] == "Best-in-class — sets the bar for the industry"


def test_post_manual_invalid(isolated_client) -> None:
    client, _store = isolated_client
    resp = client.post("/api/score/manual", json={"agent_name": "x"})
    assert resp.status_code == 422
    assert resp.json() == {"error": "'controls' list is required and must be non-empty"}


# --- Full parity vs Flask (creates + cleans up real state) ----------------

def test_post_parity_with_flask(fastapi_client, flask_client) -> None:
    try:
        fa_post = fastapi_client.post("/api/score", json=_ACPSEC_PAYLOAD)
        fl_post = flask_client.post("/api/score", json=_ACPSEC_PAYLOAD)
        assert fa_post.status_code == fl_post.status_code
        assert fa_post.json() == fl_post.get_json()

        fa_get = fastapi_client.get("/api/score")
        fl_get = flask_client.get("/api/score")
        assert fa_get.status_code == fl_get.status_code
        assert fa_get.json() == fl_get.get_json()

        # Manual endpoint parity
        fa_m = fastapi_client.post("/api/score/manual", json=_MANUAL_PAYLOAD)
        fl_m = flask_client.post("/api/score/manual", json=_MANUAL_PAYLOAD)
        assert fa_m.status_code == fl_m.status_code
        assert fa_m.json() == fl_m.get_json()
    finally:
        # Clean up the polluted real store on BOTH apps.
        fastapi_client.delete("/api/score")
        flask_client.delete("/api/score")
