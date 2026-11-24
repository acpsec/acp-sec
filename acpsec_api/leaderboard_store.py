"""Leaderboard persistence + banding.

Standalone port of the leaderboard helpers in ``dashboard/serve.py`` (copied,
not imported). ``LeaderboardStore`` mirrors ``_load_leaderboard`` /
``_save_leaderboard``; the 6-band tier table mirrors ``_LEADERBOARD_BANDS`` /
``_tier_for_score``.

NOTE: ``tier_for_score`` / ``LEADERBOARD_BANDS`` are used by the scanner-side
upsert (Task 2.5) — the GET /api/leaderboard endpoint reflects the stored
``tier`` field and does not recompute it. They live here so 2.5 can reuse them.

Entry identity is the scanned host (``scan_host``), not a client-supplied name —
see ``LeaderboardStore.upsert``. Entry ids are ``[a-z0-9_]`` (report file names).
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from acpsec_api.utils import atomic_write_text

# Default path: <repo>/acpsec_api/leaderboard_store.py → <repo>/data/leaderboard.json
_DEFAULT_LEADERBOARD_FILE = (
    Path(__file__).resolve().parent.parent / "data" / "leaderboard.json"
)

# Six-band tier scheme (distinct from the 5-band score verdicts in scoring.py).
LEADERBOARD_BANDS = [
    (90, "EXEMPLARY"),
    (70, "SECURE"),
    (50, "HARDENED"),
    (30, "VULNERABLE"),
    (10, "CRITICAL"),
    (0,  "COMPROMISED"),
]


def tier_for_score(score: float) -> str:
    """Return the band name for a 0-100 score (six-band scheme)."""
    for threshold, band in LEADERBOARD_BANDS:
        if score >= threshold:
            return band
    return "COMPROMISED"


def scan_host(url: str) -> str:
    """Leaderboard identity of a scanned site ("" if none).

    The host of the engine's final, post-redirect URL — the server's own
    fetch — lowercased, without a trailing dot or a leading "www.".
    """
    try:
        host = (urlsplit(url or "").hostname or "").rstrip(".").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _id_for_host(host: str, taken: set[str]) -> str:
    """A report-safe id ([a-z0-9_]) for ``host``, distinct from ``taken``.

    Different hosts can fold to the same base (``a-b.com`` / ``a.b.com``), so a
    clash gets a stable hash suffix rather than sharing an entry.
    """
    base = re.sub(r"[^a-z0-9]+", "_", host).strip("_") or "site"
    if base not in taken:
        return base
    digest = hashlib.sha256(host.encode("utf-8")).hexdigest()
    for n in (8, 16, 64):
        candidate = f"{base}_{digest[:n]}"
        if candidate not in taken:
            return candidate
    raise ValueError(f"no free leaderboard id for {host!r}")


def limited_tiebreaker_bonus(token, acp_registered: bool, base_mcp: bool) -> float:
    """Extra points for limited-scan agents based on observable public signals.

    Copied from dashboard/serve.py ``_limited_tiebreaker_bonus``.
    """
    bonus = 0.0
    if token:
        bonus += 1.0
    if acp_registered:
        bonus += 1.0
    if base_mcp:
        bonus += 0.5
    return bonus


class LeaderboardStore:
    """JSON-file persistence for the leaderboard (load/save, never raises).

    ``upsert`` is serialised by a lock and ``save`` replaces the file
    atomically, so concurrent scans (threadpool) neither lose updates nor let a
    reader see a half-written file.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else _DEFAULT_LEADERBOARD_FILE
        self._lock = threading.Lock()

    def load(self) -> dict:
        """Load leaderboard.json (seed + runtime upserts). Never raises."""
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {"updated": "", "checks_per_scan": 38, "agents": []}

    def save(self, board: dict) -> None:
        """Persist leaderboard.json atomically (best-effort; ignores read-only FS)."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(self.path, json.dumps(board, indent=2))
        except OSError:
            pass

    def upsert(self, scan: dict) -> dict | None:
        """Add or update the entry of the site that was actually scanned.

        ``scan`` is the engine's own result (dashboard wire format). Identity is
        ``scan_host(scan["scan_url"])`` — never a display name or X handle the
        client sent: an existing entry is matched on its ``scan_host`` and keeps
        its curated name/handle (only scan-derived fields change); a new one is
        named after the host. Movement is derived later (GET /api/leaderboard)
        from the ``previous_score`` stashed here. Returns a copy of the stored
        entry, or None when nothing was persisted.
        """
        # #81 defense-in-depth: never rank an UNRATED scan (fetch-failed /
        # no-website / social-only). The router already gates on this, but the
        # store must refuse it too so a future caller can't reintroduce the
        # false-danger by upserting an unrated payload directly.
        if scan.get("rated") is False:
            return None

        host = scan_host(scan.get("scan_url") or "")
        if not host:
            return None
        with self._lock:
            return self._upsert_locked(scan, host)

    def _upsert_locked(self, scan: dict, host: str) -> dict:
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

        board = self.load()
        agents = board.setdefault("agents", [])
        existing = next((a for a in agents if a.get("scan_host") == host), None)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # v0.4.1 — extract ticker from scan token block, if present
        token_block = scan.get("token") or {}
        detected_ticker = token_block.get("ticker") if token_block.get("has_token") else None

        is_limited = bool(scan.get("limited_scan", False))

        if existing:
            effective_token = detected_ticker or existing.get("token")
            if is_limited:
                score += limited_tiebreaker_bonus(
                    token=effective_token,
                    acp_registered=bool(scan.get("acp_registered", existing.get("acp_registered", False))),
                    base_mcp=bool(existing.get("base_mcp", False)),
                )
            existing["previous_score"] = existing.get("score", score)
            existing["score"]          = score
            existing["tier"]           = tier_for_score(score)
            existing["critical_fails"] = int(critical_fails)
            existing["limited_scan"]   = is_limited
            existing["last_scan_date"] = today
            # Overwrite token only when scan found one and existing is blank.
            if detected_ticker and not existing.get("token"):
                existing["token"] = detected_ticker
            entry = existing
        else:
            if is_limited:
                score += limited_tiebreaker_bonus(
                    token=detected_ticker,
                    acp_registered=bool(scan.get("acp_registered", False)),
                    base_mcp=False,
                )
            agent_id = _id_for_host(host, {a.get("id") for a in agents})
            entry = {
                "id":             agent_id,
                "name":           host,
                "x_handle":       agent_id,
                "scan_host":      host,
                "score":          score,
                "tier":           tier_for_score(score),
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
            }
            agents.append(entry)

        board["updated"] = today
        self.save(board)
        return dict(entry)
