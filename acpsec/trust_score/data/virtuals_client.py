"""Virtuals data source (Dimension 2) — injectable, scan-mode aware.

Some signals (notably the Agent Card spend limit) are genuinely private: they
live in off-chain operator configuration, not on-chain. They are only reachable
when the operator runs the scan themselves (``scan_mode="self_audit"``) and
supplies a fetcher. In an external scan such data is left Unrated (None) — the
framework never assumes a default and never penalizes for unreachable data.

The fetcher signature is ``(address) -> dict | None`` returning the Agent Card
(or None when the card cannot be reached).
"""

from __future__ import annotations

from typing import Any, Callable

from ..models import DEFAULT_SCAN_MODE, ScanMode

# Sentinel returned by raw getters when a private field is not reachable in an
# external scan (distinct from a genuine None / missing value).
NOT_REACHABLE_EXTERNAL = "__NOT_REACHABLE_EXTERNAL__"


class VirtualsClient:
    def __init__(
        self,
        scan_mode: str | ScanMode = DEFAULT_SCAN_MODE,
        # TODO: default to a real Virtuals Agent Card fetcher for self-audit runs.
        _fetcher: Callable[[str], dict | None] | None = None,
    ) -> None:
        self._scan_mode = ScanMode(scan_mode)
        self._fetcher = _fetcher

    @property
    def scan_mode(self) -> ScanMode:
        return self._scan_mode

    def get_spend_limit(self, address: str) -> Any:
        """Raw Agent Card spend-limit value.

        Returns NOT_REACHABLE_EXTERNAL in external scans (private data), the
        fetched value in self-audit, or None if the card cannot be reached.
        """
        if self._scan_mode != ScanMode.SELF_AUDIT:
            return NOT_REACHABLE_EXTERNAL
        if self._fetcher is None:
            return None
        try:
            card = self._fetcher(address)
        except Exception:
            return None
        return None if card is None else card.get("spend_limit")

    def get_agent_card_no_spend_limit(self, address: str) -> bool | None:
        """Tri-state for Dimension 2.

        True  — Agent Card declares no spend limit (absent / null / <= 0)
        False — a positive spend limit is set
        None  — Unrated (external scan, card unreachable, or non-numeric value)
        """
        if self._scan_mode != ScanMode.SELF_AUDIT:
            return None
        if self._fetcher is None:
            return None
        try:
            card = self._fetcher(address)
        except Exception:
            return None
        if card is None:
            return None
        limit = card.get("spend_limit")
        if limit is None:
            return True
        try:
            return float(limit) <= 0
        except (TypeError, ValueError):
            return None
