"""ACP-SEC Dashboard — Flask server.

Routes
------
GET  /                       → serve acp-sec-dashboard.html
GET  /scanner                → serve scanner.html (Agent Scanner MVP)
GET  /api/score              → return current score (memory → disk → null)
POST /api/score              → accept acpsec / ASF JSON, normalise, persist
POST /api/score/manual       → accept hand-entered control scores, compute band
DELETE /api/score            → clear in-memory + disk store
GET  /api/controls           → return check metadata for the scoring editor
POST /api/scanner/lookup     → scrape X/Twitter profile via Nitter
POST /api/scanner/scan       → heuristic website security analysis

Usage
-----
    python serve.py              # default port 5001
    PORT=5002 python serve.py    # custom port
"""

from __future__ import annotations

import json
import os
import re
import secrets
import warnings
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, redirect, request, send_file

app = Flask(__name__, static_folder="static", static_url_path="/static")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

PORT = int(os.environ.get("PORT", 8080))

DASHBOARD_HTML       = Path(__file__).parent / "acp-sec-dashboard.html"
SCANNER_HTML         = Path(__file__).parent / "scanner.html"
MONITOR_HTML         = Path(__file__).parent / "monitor_dashboard.html"
LEADERBOARD_HTML     = Path(__file__).parent / "leaderboard.html"
SENTRYAGENT_HTML            = Path(__file__).parent / "agents" / "sentryagent.html"
SENTRYAGENT_PLAYGROUND_HTML = Path(__file__).parent / "agents" / "sentryagent" / "playground.html"
PRIVACY_HTML                = Path(__file__).parent / "privacy.html"
TERMS_HTML                  = Path(__file__).parent / "terms.html"
SECURITY_PAGE_HTML          = Path(__file__).parent / "security.html"
SECURITY_TXT                = Path(__file__).parent / ".well-known" / "security.txt"
ROBOTS_TXT                  = Path(__file__).parent / "robots.txt"
SITEMAP_XML                 = Path(__file__).parent / "sitemap.xml"
STORE_FILE       = Path(__file__).parent / "score_store.json"
SCAN_STORE       = Path(__file__).parent / "scan_store.json"
LEADERBOARD_FILE = Path(__file__).parent / "leaderboard.json"
REPORTS_DIR      = Path(__file__).parent / "reports"

# ---------------------------------------------------------------------------
# Leaderboard auth session store
# ---------------------------------------------------------------------------
_lb_sessions: dict[str, datetime] = {}  # token → expiry
LB_SESSION_COOKIE = "lb_session"
LB_SESSION_DAYS = 7

# In-memory cache; populated from disk on startup
_current_score: dict[str, Any] | None = None

# ---------------------------------------------------------------------------
# Optional acpsec package integration
# ---------------------------------------------------------------------------
# We import everything we need from the package at module load time so that
# any ImportError surfaces immediately (rather than at request time), and so
# that callers get a clear one-time warning when the package is absent.

try:
    from acpsec.scorer import CRITICAL_PENALTY, SCORE_BANDS, ScoringEngine  # type: ignore[import]
    from acpsec.models import CheckStatus, Severity  # type: ignore[import]
    from acpsec.catalogue import get_check_catalogue  # type: ignore[import]
    ACPSEC_AVAILABLE = True
except ImportError:
    ACPSEC_AVAILABLE = False
    warnings.warn(
        "acpsec package not found. "
        "Install it with: pip install -e /path/to/acp-sec  "
        "Falling back to built-in scoring tables.",
        stacklevel=1,
    )

# ---------------------------------------------------------------------------
# Score band tables — only used when acpsec is unavailable
# ---------------------------------------------------------------------------

_FALLBACK_BANDS = [
    (90, "SECURE",      "Production-ready with active monitoring"),
    (70, "HARDENED",    "Minor gaps present, low overall risk"),
    (50, "VULNERABLE",  "Known exploitable weaknesses — remediate before production"),
    (30, "CRITICAL",    "Multiple high-severity issues — do not deploy"),
    (0,  "COMPROMISED", "Fundamental security failures — immediate halt required"),
]


def _calc_band(score_pct: float) -> tuple[str, str]:
    """Return (band, verdict) for a given 0-100 score percentage."""
    if ACPSEC_AVAILABLE:
        return ScoringEngine().band(score_pct)
    for threshold, band, verdict in _FALLBACK_BANDS:
        if score_pct >= threshold:
            return band, verdict
    return _FALLBACK_BANDS[-1][1], _FALLBACK_BANDS[-1][2]


def _apply_critical_penalties(score: float, controls: list[dict]) -> float:
    """Deduct CRITICAL_PENALTY for each unmitigated CRITICAL-severity failure.

    Works with or without the acpsec package installed.
    """
    if ACPSEC_AVAILABLE:
        # Build lightweight CheckResult-compatible objects from the control dicts
        from acpsec.models import CheckResult, CheckStatus, Severity  # noqa: PLC0415
        check_results: list[CheckResult] = []
        for c in controls:
            try:
                sev = Severity(c.get("severity", "MEDIUM").upper())
                status_raw = c.get("status", "fail").lower()
                status = CheckStatus(status_raw) if status_raw in CheckStatus._value2member_map_ else CheckStatus.FAIL
                check_results.append(
                    CheckResult(
                        check_id=c.get("ctrl", "UNKNOWN"),
                        name=c.get("name", ""),
                        dimension=c.get("dimension", ""),
                        status=status,
                        score=float(c.get("score", 0)),
                        max_score=float(c.get("max", 0)),
                        severity=sev,
                    )
                )
            except Exception:
                continue
        return ScoringEngine().apply_penalties(score, check_results)
    else:
        # Fallback: manual penalty calculation
        penalty_per = 5  # mirrors acpsec.scorer.CRITICAL_PENALTY
        critical_failures = [
            c for c in controls
            if c.get("severity", "").upper() == "CRITICAL"
            and c.get("status", "fail").lower() == "fail"
        ]
        return max(0.0, score - len(critical_failures) * penalty_per)

# ---------------------------------------------------------------------------
# Default ASF controls (shown in dashboard before any acpsec data is loaded)
# ---------------------------------------------------------------------------

_ASF_CONTROLS_DEFAULT = [
    {"id": "ASF-01", "name": "Source Authentication",    "dimension": "CAT-01", "max_score": 20, "severity": "CRITICAL"},
    {"id": "ASF-02", "name": "Intent Classification",    "dimension": "CAT-01", "max_score": 20, "severity": "CRITICAL"},
    {"id": "ASF-03", "name": "Amount Threshold Controls","dimension": "CAT-03", "max_score": 15, "severity": "CRITICAL"},
    {"id": "ASF-04", "name": "Recipient Verification",   "dimension": "CAT-02", "max_score": 10, "severity": "HIGH"},
    {"id": "ASF-05", "name": "Execution Delay Window",   "dimension": "CAT-01", "max_score": 10, "severity": "HIGH"},
    {"id": "ASF-06", "name": "Audit Logging",            "dimension": "ALL",    "max_score": 10, "severity": "HIGH"},
    {"id": "ASF-07", "name": "Anomaly Detection",        "dimension": "CAT-01", "max_score": 10, "severity": "MEDIUM"},
    {"id": "ASF-08", "name": "Recovery Procedures",      "dimension": "ALL",    "max_score":  5, "severity": "MEDIUM"},
]

# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def _load_from_disk() -> dict | None:
    """Return persisted score data, or None if unavailable."""
    if STORE_FILE.exists():
        try:
            return json.loads(STORE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _save_to_disk(data: dict) -> None:
    """Write score data to JSON file (best-effort, silent on failure)."""
    try:
        STORE_FILE.write_text(json.dumps(data, indent=2, default=str))
    except OSError:
        pass

# ---------------------------------------------------------------------------
# Data normalisation
# ---------------------------------------------------------------------------

def _normalise_acpsec(data: dict) -> dict:
    """Convert an acpsec AssessmentResult JSON into the dashboard wire format."""
    controls: list[dict] = []
    for dim in data.get("dimensions", []):
        for check in dim.get("checks", []):
            evidence = check.get("evidence", [])
            controls.append({
                "ctrl":            check["check_id"],
                "name":            check.get("name", check["check_id"]),
                "score":           check.get("score", 0),
                "max":             check.get("max_score", 0),
                "finding":         evidence[0] if evidence else "No evidence recorded.",
                "severity":        check.get("severity", "MEDIUM"),
                "dimension":       dim.get("dimension_id", ""),
                "dimension_name":  dim.get("name", ""),
                "recommendations": check.get("recommendations", []),
                "status":          check.get("status", "fail"),
            })

    return {
        "agent_name":    data.get("agent_name", "Unknown Agent"),
        "agent_version": data.get("agent_version", ""),
        "band":          data.get("band", ""),
        "verdict":       data.get("verdict", ""),
        "final_score":   data.get("final_score", 0),
        "timestamp":     data.get("timestamp", ""),
        "controls":      controls,
        "source":        "acpsec",
    }


def _normalise_asf(data: dict) -> dict:
    """Pass-through for the dashboard's native ASF format."""
    return {
        "agent_name":    data.get("agent_name", "Agent"),
        "agent_version": data.get("agent_version", ""),
        "band":          data.get("band", ""),
        "verdict":       data.get("verdict", ""),
        "final_score":   data.get("final_score", 0),
        "timestamp":     data.get("timestamp", ""),
        "controls":      data.get("controls", []),
        "source":        "asf",
    }


def _auto_normalise(data: dict) -> dict:
    """Detect format and normalise to the dashboard wire format."""
    if "dimensions" in data:
        return _normalise_acpsec(data)
    if "controls" in data:
        return _normalise_asf(data)
    raise ValueError(
        "Unrecognised JSON format. "
        "Expected 'dimensions' (acpsec output) or 'controls' (dashboard native) key."
    )

# ---------------------------------------------------------------------------
# Scanner module (lazy import — only needed for /scanner routes)
# ---------------------------------------------------------------------------

def _get_scanner():
    """Import scanner module on first use (avoids startup cost)."""
    try:
        import scanner as _scanner  # local module in same directory  # noqa: PLC0415
        return _scanner
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Leaderboard storage
# ---------------------------------------------------------------------------
# leaderboard.json is committed to git with seed data.  On Railway's
# ephemeral disk, runtime upserts persist only for the dyno's lifetime and
# reset to the committed seed on redeploy — same trade-off as the monitor
# SQLite store.  That's acceptable for a public demo leaderboard.

# Six-band thresholds — mirrors acpsec.scorer.SCORE_BANDS (v0.3.1).  Local
# copy so the leaderboard tier never depends on the older 5-band fallback
# table above.
_LEADERBOARD_BANDS = [
    (90, "EXEMPLARY"),
    (70, "SECURE"),
    (50, "HARDENED"),
    (30, "VULNERABLE"),
    (10, "CRITICAL"),
    (0,  "COMPROMISED"),
]


def _tier_for_score(score: float) -> str:
    """Return the band name for a 0-100 score (six-band scheme)."""
    for threshold, band in _LEADERBOARD_BANDS:
        if score >= threshold:
            return band
    return "COMPROMISED"


def _lb_session_valid(req) -> bool:
    """Return True if the request carries a valid leaderboard session cookie."""
    token = req.cookies.get(LB_SESSION_COOKIE, "")
    expiry = _lb_sessions.get(token)
    return bool(expiry and datetime.now(timezone.utc) < expiry)


def _limited_tiebreaker_bonus(token, acp_registered: bool, base_mcp: bool) -> float:
    """Extra points for limited-scan agents based on observable public signals."""
    bonus = 0.0
    if token:
        bonus += 1.0
    if acp_registered:
        bonus += 1.0
    if base_mcp:
        bonus += 0.5
    return bonus


def _leaderboard_key(name: str) -> str:
    """Stable id for an agent: lowercase, strip @, keep [a-z0-9_]."""
    key = (name or "").strip().lstrip("@").lower()
    return re.sub(r"[^a-z0-9_]", "", key.replace(" ", "_")) or "unknown"


def _load_leaderboard() -> dict:
    """Load leaderboard.json (seed + runtime upserts).  Never raises."""
    try:
        return json.loads(LEADERBOARD_FILE.read_text())
    except (OSError, ValueError):
        return {"updated": "", "checks_per_scan": 38, "agents": []}


def _save_leaderboard(board: dict) -> None:
    """Persist leaderboard.json (best-effort; ignores read-only FS)."""
    try:
        LEADERBOARD_FILE.write_text(json.dumps(board, indent=2))
    except OSError:
        pass


def _report_path(agent_id: str) -> Path:
    """Canonical path for a full-scan report file."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR / f"{agent_id}.json"


def _save_report(scan: dict) -> None:
    """Persist the full scan result as dashboard/reports/{agent_id}.json.

    Called automatically after every successful /api/scanner/scan so the
    leaderboard click handler can load the full 38-control breakdown.
    Best-effort; never raises.
    """
    name = (scan.get("agent_name") or scan.get("x_username") or "").strip()
    if not name:
        return
    key = _leaderboard_key(scan.get("x_username") or name)
    if not key:
        return
    try:
        _report_path(key).write_text(json.dumps(scan, indent=2, default=str))
    except OSError:
        pass


def _upsert_leaderboard_entry(scan: dict) -> None:
    """Add or update an agent in the leaderboard from a completed scan.

    `scan` is the dashboard-wire-format data object returned by
    scanner.analyze_agent().  Movement is derived by stashing the prior
    score as previous_score before overwriting.
    """
    name = (scan.get("agent_name") or "").strip()
    if not name:
        return
    key = _leaderboard_key(scan.get("x_username") or name)

    score = scan.get("score_pct")
    if score is None:
        score = scan.get("final_score") or 0
    score = round(float(score))

    controls = scan.get("controls") or []
    critical_fails = scan.get("critical_fails")
    if critical_fails is None:
        critical_fails = sum(
            1 for c in controls
            if str(c.get("severity", "")).upper() == "CRITICAL"
            and str(c.get("status", "")).lower() == "fail"
        )

    board = _load_leaderboard()
    agents = board.setdefault("agents", [])
    existing = next((a for a in agents if a.get("id") == key), None)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # v0.4.1 — extract ticker from scan token block, if present
    token_block = scan.get("token") or {}
    detected_ticker = token_block.get("ticker") if token_block.get("has_token") else None

    is_limited = bool(scan.get("limited_scan", False))

    if existing:
        effective_token = detected_ticker or existing.get("token")
        if is_limited:
            score += _limited_tiebreaker_bonus(
                token=effective_token,
                acp_registered=bool(scan.get("acp_registered", existing.get("acp_registered", False))),
                base_mcp=bool(existing.get("base_mcp", False)),
            )
        existing["previous_score"] = existing.get("score", score)
        existing["score"]          = score
        existing["tier"]           = _tier_for_score(score)
        existing["critical_fails"] = int(critical_fails)
        existing["limited_scan"]   = is_limited
        existing["last_scan_date"] = today
        if scan.get("x_username"):
            existing["x_handle"] = scan["x_username"]
        # Overwrite token only when scan found one and existing is blank.
        if detected_ticker and not existing.get("token"):
            existing["token"] = detected_ticker
    else:
        if is_limited:
            score += _limited_tiebreaker_bonus(
                token=detected_ticker,
                acp_registered=bool(scan.get("acp_registered", False)),
                base_mcp=False,
            )
        agents.append({
            "id":             key,
            "name":           name,
            "x_handle":       scan.get("x_username") or key,
            "score":          score,
            "tier":           _tier_for_score(score),
            "critical_fails": int(critical_fails),
            "category":       "general",
            "token":          detected_ticker,   # v0.4.1 — from scan token block
            "base_mcp":       False,
            "limited_scan":   is_limited,
            # v0.4.0 fields
            "wallet_address": scan.get("wallet_address"),
            "acp_registered": bool(scan.get("acp_registered", False)),
            "custodial":      scan.get("custodial", "unknown"),
            "fund_transfer":  bool(scan.get("fund_transfer", False)),
            "evaluator":      bool(scan.get("evaluator", False)),
            "job_types":      list(scan.get("job_types", []) or []),
            "last_scan_date": today,
            "previous_score": score,   # first sighting → no movement
        })

    board["updated"] = today
    _save_leaderboard(board)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return send_file(DASHBOARD_HTML)


@app.get("/scanner")
def scanner_page():
    return send_file(SCANNER_HTML)


@app.get("/monitor")
def monitor_page():
    """Serve the continuous-monitoring dashboard (watchlist + score history + alerts)."""
    return send_file(MONITOR_HTML)


@app.get("/agents/sentryagent")
def sentryagent_page():
    """Serve the SentryAgent public security disclosure page."""
    return send_file(SENTRYAGENT_HTML)


@app.get("/agents/sentryagent/playground")
def sentryagent_playground_page():
    """Serve the SentryAgent interactive contract playground."""
    return send_file(SENTRYAGENT_PLAYGROUND_HTML)


@app.get("/privacy")
def privacy_page():
    return send_file(PRIVACY_HTML)


@app.get("/terms")
def terms_page():
    return send_file(TERMS_HTML)


@app.get("/security")
def security_page():
    return send_file(SECURITY_PAGE_HTML)


@app.get("/.well-known/security.txt")
def security_txt():
    return send_file(SECURITY_TXT, mimetype="text/plain")


@app.get("/robots.txt")
def robots_txt():
    return send_file(ROBOTS_TXT, mimetype="text/plain")


@app.get("/sitemap.xml")
def sitemap_xml():
    return send_file(SITEMAP_XML, mimetype="application/xml")


@app.get("/leaderboard")
def leaderboard_page():
    """Serve the agent-security leaderboard (password-protected when LEADERBOARD_PASSWORD is set)."""
    password = os.environ.get("LEADERBOARD_PASSWORD", "")
    if password and not _lb_session_valid(request):
        return redirect("/leaderboard/login")
    return send_file(LEADERBOARD_HTML)


@app.get("/leaderboard/login")
def leaderboard_login():
    """Serve the leaderboard login page."""
    return send_file(Path(__file__).parent / "leaderboard_login.html")


@app.post("/api/leaderboard/auth")
def leaderboard_auth():
    """Validate the leaderboard password and issue a session cookie."""
    password = os.environ.get("LEADERBOARD_PASSWORD", "")
    if not password:
        # No password set — leaderboard is open
        return jsonify({"ok": True, "token": "open"}), 200
    body = request.get_json(silent=True) or {}
    if body.get("password") != password:
        return jsonify({"ok": False, "error": "Incorrect password"}), 401
    token = "lb_" + secrets.token_urlsafe(24)
    expiry = datetime.now(timezone.utc) + timedelta(days=LB_SESSION_DAYS)
    _lb_sessions[token] = expiry
    resp = jsonify({"ok": True})
    resp.set_cookie(LB_SESSION_COOKIE, token, max_age=LB_SESSION_DAYS * 86400,
                    httponly=True, samesite="Lax", secure=False)
    return resp, 200


@app.post("/api/onchain/check")
def onchain_check():
    """v0.4.0 — best-effort on-chain ACP registration check.

    Request body: { "wallet": "0x…" }
    Returns: { ok, data: { contract, wallet, registered, log_count, ... } }

    Same gating as /api/scanner/* — needs the same-origin browser flow
    or a valid X-Scanner-Token header, since this hits public RPC and
    could be abused.
    """
    gate = _require_scanner_token()
    if gate is not None:
        return jsonify(gate[0]), gate[1]
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    payload = request.get_json(force=True)
    wallet  = (payload.get("wallet") or "").strip()
    if not wallet:
        return jsonify({"ok": False, "error": "'wallet' is required"}), 422

    try:
        from acpsec.onchain import check_acp_registration  # noqa: PLC0415
    except ImportError:
        return jsonify({"ok": False, "error": "acpsec.onchain not available"}), 503

    rpc_url = os.environ.get("BASE_RPC_URL", "").strip() or None
    result = check_acp_registration(wallet, rpc_url=rpc_url)
    return jsonify({"ok": True, "data": result}), 200


@app.get("/api/leaderboard")
def get_leaderboard():
    """Return the leaderboard sorted by score descending.

    Each agent carries a derived `movement` field: 'up' | 'down' | 'same'
    based on score vs previous_score.
    """
    board = _load_leaderboard()
    agents = list(board.get("agents", []))

    for a in agents:
        prev = a.get("previous_score", a.get("score", 0))
        cur  = a.get("score", 0)
        if cur > prev:
            a["movement"] = "up"
        elif cur < prev:
            a["movement"] = "down"
        else:
            a["movement"] = "same"
        a["movement_delta"] = round(cur - prev)

    agents.sort(key=lambda a: a.get("score", 0), reverse=True)
    for i, a in enumerate(agents, 1):
        a["rank"] = i

    return jsonify({
        "ok": True,
        "updated": board.get("updated", ""),
        "checks_per_scan": board.get("checks_per_scan", 38),
        "count": len(agents),
        "agents": agents,
    }), 200


@app.get("/api/report/<agent_id>")
def get_report(agent_id: str):
    """Return the full scan breakdown (38 controls) for a leaderboard agent.

    Reports are stored in dashboard/reports/{agent_id}.json — written on
    every successful scan via /api/scanner/scan, or seeded at deploy time
    by running the scanner against each seeded agent.

    Returns 404 with a friendly message when no report exists so the
    leaderboard UI can offer a "Scan now" fallback.
    """
    # Normalise: strip @ and lowercase, same as _leaderboard_key()
    safe_id = re.sub(r"[^a-z0-9_]", "", (agent_id or "").lower().replace("-", "_"))
    if not safe_id:
        return jsonify({"ok": False, "error": "invalid agent id"}), 400

    path = _report_path(safe_id)
    if not path.exists():
        return jsonify({
            "ok": False,
            "error": "report_not_found",
            "message": (
                "Full report not available for this agent. "
                "Re-scan it from the Scanner page for a detailed breakdown."
            ),
            "scan_url": f"/scanner",
        }), 404

    try:
        data = json.loads(path.read_text())
        return jsonify({"ok": True, "data": data}), 200
    except (OSError, ValueError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.get("/api/health")
def health():
    """Lightweight liveness probe — used by Railway healthchecks and uptime monitors."""
    return jsonify({
        "ok": True,
        "service": "acp-sec-dashboard",
        "acpsec_available": bool(ACPSEC_AVAILABLE),
        "scanner_protected": bool(os.environ.get("SCANNER_TOKEN")),
    }), 200


def _is_same_origin_request() -> bool:
    """True iff the request was issued by this server's own browser frontend.

    Browsers ALWAYS attach an Origin header to POSTs (it's part of CORS and
    cannot be spoofed by attacker JS running on a different site — only the
    user's own browser at our domain emits our Origin).  Scripted callers
    (curl, requests, Python) can set Origin to anything, so this is not a
    universal auth check — it is specifically the "is this a browser fetch
    from my own dashboard" check.  Token gate still applies to everyone else.
    """
    origin = request.headers.get("Origin", "")
    if not origin or origin == "null":
        return False
    # Compare HOSTS, not full URLs — Railway terminates TLS upstream so the
    # Flask process sees `request.host_url` as http://… even though the
    # browser sent Origin: https://…  Matching on host alone avoids the
    # scheme-mismatch trap without weakening the check meaningfully.
    from urllib.parse import urlparse
    try:
        origin_host = urlparse(origin).netloc.lower()
    except Exception:
        return False
    return bool(origin_host) and origin_host == request.host.lower()


def _require_scanner_token() -> tuple[dict, int] | None:
    """Gate the scanner endpoints when SCANNER_TOKEN is set.

    On a public Railway URL the heuristic scanner becomes a free SSRF
    relay if left open — every request kicks off ~10 parallel HTTP fetches
    against an attacker-chosen target.  Two paths are allowed through:

      1. Same-origin browser request — the dashboard's own JS calling its
         own backend.  Detected via the Origin header (always present on
         POSTs, set by the browser, not spoofable from a foreign site).
         This is what lets the in-browser /scanner UI work without us
         embedding the token in public HTML.
      2. Explicit X-Scanner-Token header matching SCANNER_TOKEN.  This is
         the path for scripted / programmatic callers (CI, curl, agents).

    Anything else gets 401.  Returns None to allow, or (body, status) to
    short-circuit.
    """
    required = os.environ.get("SCANNER_TOKEN", "").strip()
    if not required:
        # No token configured → endpoints behave exactly as in dev (open).
        return None

    if _is_same_origin_request():
        return None

    sent = request.headers.get("X-Scanner-Token", "").strip()
    if not sent or sent != required:
        return (
            {
                "ok": False,
                "error": (
                    "scanner endpoint requires same-origin browser request "
                    "OR X-Scanner-Token header"
                ),
            },
            401,
        )
    return None


@app.post("/api/scanner/lookup")
def scanner_lookup():
    """Scrape basic X/Twitter profile info via Nitter.

    Request body: { "username": "@agentname" }
    Returns: { ok, data: { username, display_name, bio, website, avatar_url, source, error } }
    """
    gate = _require_scanner_token()
    if gate is not None:
        return jsonify(gate[0]), gate[1]
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    payload  = request.get_json(force=True)
    username = (payload.get("username") or "").strip()
    if not username:
        return jsonify({"error": "'username' is required"}), 422

    sc = _get_scanner()
    if sc is None:
        return jsonify({"error": "scanner module not available"}), 503

    result = sc.scrape_x_profile(username)
    return jsonify({"ok": True, "data": result}), 200


@app.post("/api/scanner/scan")
def scanner_scan():
    """Heuristic website security analysis mapped to acpsec checks.

    Request body: { "url": "https://...", "agent_name": "...", "username": "@..." }
    Returns: { ok, data: <dashboard wire format> } or { ok: false, error }
    """
    gate = _require_scanner_token()
    if gate is not None:
        return jsonify(gate[0]), gate[1]
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    payload    = request.get_json(force=True)
    url        = (payload.get("url") or "").strip()
    agent_name = (payload.get("agent_name") or "").strip()
    username   = (payload.get("username")   or "").strip()
    scan_mode  = (payload.get("scan_mode")  or "root").strip().lower()
    # `scraped` is True only when the X profile was successfully fetched
    # via Nitter — used by the UI to decide whether to render the @handle.
    scraped    = bool(payload.get("scraped", False))

    if scan_mode not in ("root", "exact"):
        scan_mode = "root"

    if not url:
        return jsonify({"error": "'url' is required"}), 422

    sc = _get_scanner()
    if sc is None:
        return jsonify({"error": "scanner module not available"}), 503

    result = sc.analyze_agent(url, agent_name or url, scan_mode=scan_mode)
    if not result["ok"]:
        return jsonify(result), 422

    # Attach the X username only when it came from a verified scrape — this
    # prevents stale @handles from being shown after the user pivots to a
    # different agent following a scrape failure (ISSUE 1).
    result["data"]["x_username"]      = username if scraped else ""
    result["data"]["x_handle_verified"] = scraped
    result["data"]["agent_name"]      = agent_name or result["data"]["agent_name"]

    # v0.4.1 — re-run token extraction with the X bio when we have it from
    # a successful Nitter scrape.  The scanner only has the website body;
    # the bio often carries the ticker / CA that the site omits.
    x_bio = (payload.get("x_bio") or "").strip()
    if scraped and x_bio:
        try:
            token_merged = sc.extract_token_info(
                html=result["data"].get("_body_text_for_token", ""),
                x_bio=x_bio,
            )
            existing = result["data"].get("token") or {}
            # Bio signal wins for ticker/CA if website didn't find any.
            if not existing.get("has_token") and token_merged.get("has_token"):
                result["data"]["token"] = token_merged
            elif token_merged.get("has_token"):
                # Merge: prefer website CA but take bio ticker if we don't have one.
                if not existing.get("ticker") and token_merged.get("ticker"):
                    existing["ticker"] = token_merged["ticker"]
                if not existing.get("contract_address") and token_merged.get("contract_address"):
                    existing["contract_address"] = token_merged["contract_address"]
                existing["has_token"] = True
                existing.setdefault("detected_from", "x_bio")
                result["data"]["token"] = existing
        except Exception:  # noqa: BLE001
            pass

    # Persist last scan (best-effort)
    try:
        SCAN_STORE.write_text(json.dumps(result["data"], indent=2, default=str))
    except OSError:
        pass

    # Auto-add / update this agent on the public leaderboard (best-effort).
    try:
        _upsert_leaderboard_entry(result["data"])
    except Exception:  # noqa: BLE001 — leaderboard must never break a scan
        pass

    # Auto-save the full 38-control breakdown so the leaderboard click
    # handler can load it via GET /api/report/<agent_id> (best-effort).
    try:
        _save_report(result["data"])
    except Exception:  # noqa: BLE001
        pass

    return jsonify(result), 200


@app.post("/api/scanner/bulk")
def scanner_bulk():
    """Scan multiple agents by X username, sequentially with rate limiting.

    Request body:
        { "usernames": ["aerodromefi", "morpho", ...], "scan_mode": "root" }

    Rate limits:
        - Maximum 10 agents per request (hard cap).
        - 5-second pause between scans to respect downstream services.

    Returns an array of per-agent results in the same format as
    /api/scanner/scan.  Each entry is { username, ok, data?, error? }.

    Gating: same same-origin / X-Scanner-Token policy as the individual
    scan endpoint.
    """
    import time as _time  # noqa: PLC0415

    gate = _require_scanner_token()
    if gate is not None:
        return jsonify(gate[0]), gate[1]
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    payload   = request.get_json(force=True) or {}
    usernames = [str(u).strip().lstrip("@") for u in (payload.get("usernames") or []) if u]
    scan_mode = (payload.get("scan_mode") or "root").strip().lower()
    if scan_mode not in ("root", "exact"):
        scan_mode = "root"

    if not usernames:
        return jsonify({"error": "'usernames' must be a non-empty list"}), 422

    MAX_BULK = 10
    if len(usernames) > MAX_BULK:
        return jsonify({
            "error": f"Too many agents — maximum {MAX_BULK} per request, got {len(usernames)}",
        }), 422

    sc = _get_scanner()
    if sc is None:
        return jsonify({"error": "scanner module not available"}), 503

    results = []
    for i, username in enumerate(usernames):
        if i > 0:
            _time.sleep(5)  # rate-limiting pause between scans

        # Derive a plausible website URL from the username.  For purely
        # social-only agents this will hit the social-media guard in
        # analyze_agent and trigger a limited scan — which is correct.
        url = f"https://twitter.com/{username}"

        try:
            scan = sc.analyze_agent(url, username, scan_mode=scan_mode)
        except Exception as exc:  # noqa: BLE001
            results.append({"username": username, "ok": False, "error": str(exc)})
            continue

        if scan.get("ok") and scan.get("data"):
            scan["data"]["x_username"] = username
            # Auto-update leaderboard + report store (best-effort).
            try:
                _upsert_leaderboard_entry(scan["data"])
            except Exception:  # noqa: BLE001
                pass
            try:
                _save_report(scan["data"])
            except Exception:  # noqa: BLE001
                pass
            results.append({"username": username, "ok": True, "data": scan["data"]})
        else:
            results.append({
                "username": username, "ok": False,
                "error": scan.get("error") or "scan failed",
            })

    return jsonify({"ok": True, "count": len(results), "results": results}), 200


@app.get("/api/score")
def get_score():
    """Return the current score: memory cache → disk → null."""
    data = _current_score or _load_from_disk()
    if data is None:
        return jsonify({"ok": False, "data": None}), 200
    return jsonify({"ok": True, "data": data}), 200


@app.post("/api/score")
def post_score():
    """Accept acpsec or native ASF JSON, normalise, cache, and persist."""
    global _current_score
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    try:
        payload = request.get_json(force=True)
        _current_score = _auto_normalise(payload)
        _save_to_disk(_current_score)
        return jsonify({"ok": True, "data": _current_score}), 200
    except (ValueError, KeyError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/score/manual")
def post_score_manual():
    """
    Accept manually entered control scores and compute aggregate band/verdict.

    CRITICAL-severity controls that have status='fail' incur an additional
    penalty (via acpsec.scorer.ScoringEngine.apply_penalties when the package
    is available, or a local fallback otherwise).

    Request body
    ------------
    agent_name  : str (optional)
    controls    : list of {ctrl, name, score, max, finding?, dimension?, severity?, status?}

    Returns the normalised score object — identical shape to GET /api/score.
    """
    global _current_score
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    payload = request.get_json(force=True)
    controls: list[dict] = payload.get("controls", [])
    if not controls:
        return jsonify({"error": "'controls' list is required and must be non-empty"}), 422

    total_score = sum(float(c.get("score", 0)) for c in controls)
    total_max   = sum(float(c.get("max",   0)) for c in controls)

    # Apply CRITICAL penalties before computing the percentage
    penalised_score = _apply_critical_penalties(total_score, controls)
    score_pct = round(penalised_score / total_max * 100, 1) if total_max > 0 else 0.0

    band, verdict = _calc_band(score_pct)

    normalised: dict[str, Any] = {
        "agent_name":    payload.get("agent_name", "Manual Entry"),
        "agent_version": payload.get("agent_version", ""),
        "band":          band,
        "verdict":       verdict,
        "final_score":   round(penalised_score, 2),
        "timestamp":     payload.get("timestamp", ""),
        "controls":      controls,
        "source":        "manual",
        "acpsec_scoring": ACPSEC_AVAILABLE,
    }

    _current_score = normalised
    _save_to_disk(normalised)
    return jsonify({"ok": True, "data": normalised}), 200


@app.get("/api/controls")
def get_controls():
    """
    Return check/control metadata for the scoring editor.

    When the acpsec package is installed the catalogue is sourced directly
    from acpsec.catalogue.get_check_catalogue() — the package is the single
    source of truth.  Falls back to the static copy in this file only when
    the package is unavailable.
    """
    if ACPSEC_AVAILABLE:
        checks = get_check_catalogue()
        source = "acpsec"
    else:
        # Inline fallback — kept intentionally minimal; install acpsec for
        # the authoritative list.
        checks = _FALLBACK_CHECKS
        source = "static-fallback"

    return jsonify({
        "source":       source,
        "acpsec_available": ACPSEC_AVAILABLE,
        "checks":       checks,
        "asf_controls": _ASF_CONTROLS_DEFAULT,
    }), 200


@app.delete("/api/score")
def clear_score():
    """Clear in-memory cache and remove the persisted file."""
    global _current_score
    _current_score = None
    if STORE_FILE.exists():
        STORE_FILE.unlink(missing_ok=True)
    return jsonify({"ok": True}), 200

# ---------------------------------------------------------------------------
# Minimal static fallback catalogue
# Only consulted when `acpsec` is not installed.
# The authoritative copy lives in acpsec/catalogue.py.
# ---------------------------------------------------------------------------

_FALLBACK_CHECKS: list[dict] = [
    # AUTH — 15 pts
    {"id": "AUTH-01", "name": "Agent identity declared",             "dimension": "AUTH", "dimension_name": "Authentication & Identity",              "max_score": 3, "severity": "HIGH"},
    {"id": "AUTH-02", "name": "API authentication enforced",         "dimension": "AUTH", "dimension_name": "Authentication & Identity",              "max_score": 3, "severity": "HIGH"},
    {"id": "AUTH-03", "name": "Session binding / replay prevention", "dimension": "AUTH", "dimension_name": "Authentication & Identity",              "max_score": 3, "severity": "MEDIUM"},
    {"id": "AUTH-04", "name": "Multi-agent trust chain verified",    "dimension": "AUTH", "dimension_name": "Authentication & Identity",              "max_score": 3, "severity": "HIGH"},
    {"id": "AUTH-05", "name": "Identity spoofing rejected",          "dimension": "AUTH", "dimension_name": "Authentication & Identity",              "max_score": 3, "severity": "CRITICAL"},
    # CTX — 20 pts
    {"id": "CTX-01",  "name": "System prompt not extractable",       "dimension": "CTX",  "dimension_name": "Context Integrity",                     "max_score": 5, "severity": "CRITICAL"},
    {"id": "CTX-02",  "name": "Session context isolation",           "dimension": "CTX",  "dimension_name": "Context Integrity",                     "max_score": 4, "severity": "HIGH"},
    {"id": "CTX-03",  "name": "Injected context sanitization",       "dimension": "CTX",  "dimension_name": "Context Integrity",                     "max_score": 4, "severity": "HIGH"},
    {"id": "CTX-04",  "name": "Long-context poisoning mitigated",    "dimension": "CTX",  "dimension_name": "Context Integrity",                     "max_score": 4, "severity": "MEDIUM"},
    {"id": "CTX-05",  "name": "Conversation history integrity",      "dimension": "CTX",  "dimension_name": "Context Integrity",                     "max_score": 3, "severity": "MEDIUM"},
    # INJ — 20 pts
    {"id": "INJ-01",  "name": "Direct prompt injection rejected",    "dimension": "INJ",  "dimension_name": "Input Validation & Injection Resistance","max_score": 5, "severity": "CRITICAL"},
    {"id": "INJ-02",  "name": "Indirect tool response injection mitigated", "dimension": "INJ", "dimension_name": "Input Validation & Injection Resistance","max_score": 4, "severity": "CRITICAL"},
    {"id": "INJ-03",  "name": "Multi-turn gradual injection rejected","dimension": "INJ",  "dimension_name": "Input Validation & Injection Resistance","max_score": 4, "severity": "HIGH"},
    {"id": "INJ-04",  "name": "Encoded injection payloads blocked",  "dimension": "INJ",  "dimension_name": "Input Validation & Injection Resistance","max_score": 4, "severity": "HIGH"},
    {"id": "INJ-05",  "name": "Metadata/header injection handled",   "dimension": "INJ",  "dimension_name": "Input Validation & Injection Resistance","max_score": 3, "severity": "MEDIUM"},
    # PRIV — 20 pts
    {"id": "PRIV-01", "name": "Tools explicitly scoped",             "dimension": "PRIV", "dimension_name": "Privilege & Tool Authorization",        "max_score": 4, "severity": "HIGH"},
    {"id": "PRIV-02", "name": "Agent cannot self-grant permissions",  "dimension": "PRIV", "dimension_name": "Privilege & Tool Authorization",        "max_score": 5, "severity": "CRITICAL"},
    {"id": "PRIV-03", "name": "Tool arguments validated",            "dimension": "PRIV", "dimension_name": "Privilege & Tool Authorization",        "max_score": 4, "severity": "HIGH"},
    {"id": "PRIV-04", "name": "Dangerous tool combinations blocked", "dimension": "PRIV", "dimension_name": "Privilege & Tool Authorization",        "max_score": 4, "severity": "HIGH"},
    {"id": "PRIV-05", "name": "HITL enforced for high-impact actions","dimension": "PRIV", "dimension_name": "Privilege & Tool Authorization",       "max_score": 3, "severity": "MEDIUM"},
    # OUT — 15 pts
    {"id": "OUT-01",  "name": "Secrets not leaked in outputs",       "dimension": "OUT",  "dimension_name": "Output Safety & Leakage Prevention",   "max_score": 4, "severity": "CRITICAL"},
    {"id": "OUT-02",  "name": "PII not leaked without authorization","dimension": "OUT",  "dimension_name": "Output Safety & Leakage Prevention",   "max_score": 3, "severity": "HIGH"},
    {"id": "OUT-03",  "name": "Internal tool details not leaked",    "dimension": "OUT",  "dimension_name": "Output Safety & Leakage Prevention",   "max_score": 3, "severity": "MEDIUM"},
    {"id": "OUT-04",  "name": "Cross-user data isolation",           "dimension": "OUT",  "dimension_name": "Output Safety & Leakage Prevention",   "max_score": 3, "severity": "HIGH"},
    {"id": "OUT-05",  "name": "Output filtered before downstream",   "dimension": "OUT",  "dimension_name": "Output Safety & Leakage Prevention",   "max_score": 2, "severity": "MEDIUM"},
    # GOV — 10 pts
    {"id": "GOV-01",  "name": "Agent actions logged",                "dimension": "GOV",  "dimension_name": "Governance, Audit & Observability",    "max_score": 3, "severity": "HIGH"},
    {"id": "GOV-02",  "name": "Anomalous behavior alerts configured","dimension": "GOV",  "dimension_name": "Governance, Audit & Observability",    "max_score": 2, "severity": "MEDIUM"},
    {"id": "GOV-03",  "name": "Logs tamper-evident and retained",    "dimension": "GOV",  "dimension_name": "Governance, Audit & Observability",    "max_score": 2, "severity": "MEDIUM"},
    {"id": "GOV-04",  "name": "Incident response procedure exists",  "dimension": "GOV",  "dimension_name": "Governance, Audit & Observability",    "max_score": 2, "severity": "MEDIUM"},
    {"id": "GOV-05",  "name": "Regular security assessments scheduled","dimension": "GOV", "dimension_name": "Governance, Audit & Observability",   "max_score": 1, "severity": "LOW"},
]

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Warm up from disk so state survives server restarts
    _current_score = _load_from_disk()
    if _current_score:
        name  = _current_score.get("agent_name", "unknown")
        score = _current_score.get("final_score", "?")
        print(f"  Loaded persisted score → {name} ({score}/100)")

    pkg_status = "acpsec package active ✓" if ACPSEC_AVAILABLE else "acpsec package NOT installed (fallback mode)"
    print(f"  {pkg_status}")
    print(f"\n  ACP-SEC Dashboard → http://localhost:{PORT}\n")
    # Production hardening: never expose the Werkzeug debugger on a public
    # host.  Opt in to debug ONLY when FLASK_ENV is left unset / "development".
    is_prod = os.environ.get("FLASK_ENV", "").lower() == "production"
    app.run(host="0.0.0.0", port=PORT, debug=not is_prod)
