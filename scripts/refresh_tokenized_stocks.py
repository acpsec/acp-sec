#!/usr/bin/env python3
"""Out-of-band refresh for the official tokenized-stock allowlist (#66/#55).

Fetches base.org/stocks, extracts ticker->address pairs, diffs them against
``acpsec_api.b20.constants.OFFICIAL_TOKENIZED_STOCKS[8453]``, and if Coinbase has
listed/relisted/removed a stock, prints a PR-ready regenerated constant block and
exits NON-ZERO so a scheduled job opens a PR.

HARD RULE: this produces CODE, not runtime data. It is NEVER imported by the
scanner — the scan path reads only the hardcoded constant. If base.org is down,
only THIS script fails (exit 2); scans are unaffected.

Usage:
    python scripts/refresh_tokenized_stocks.py           # diff only
    python scripts/refresh_tokenized_stocks.py --print    # always print current block

Exit codes: 0 = in sync · 1 = drift (regenerate constants) · 2 = fetch/parse error.
"""
from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request

from acpsec_api.b20.constants import OFFICIAL_TOKENIZED_STOCKS

STOCKS_URL = "https://www.base.org/stocks"
CHAIN = 8453
# Tokenized-stock tickers are an uppercase root + lowercase 'c' (NVDAc, GOOGLc);
# addresses are the B20 0xb2-prefixed form.
_PAIR_RE = re.compile(r"([A-Z]{1,6}c)\b.{0,4000}?(0x[bB]2[0-9a-fA-F]{38})", re.DOTALL)
_ADDR_RE = re.compile(r"0x[bB]2[0-9a-fA-F]{38}")


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "acpsec-refresh/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (trusted host)
        return r.read().decode("utf-8", "replace")


def parse(html: str) -> dict[str, str]:
    """Best-effort ticker->address (lowercased). Pairs a TICKERc token with the
    nearest following b2-address. Falls back to address-only if no ticker context."""
    pairs: dict[str, str] = {}
    for ticker, addr in _PAIR_RE.findall(html):
        pairs.setdefault(ticker.upper(), addr.lower())
    return pairs


def render_block(mapping: dict[str, str]) -> str:
    lines = ["OFFICIAL_TOKENIZED_STOCKS: dict[int, dict[str, str]] = {", f"    {CHAIN}: {{"]
    for t, a in sorted(mapping.items()):
        lines.append(f'        "{t}": "{a}",')
    lines += ["    },", "}"]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    current = {t.upper(): a.lower() for t, a in OFFICIAL_TOKENIZED_STOCKS.get(CHAIN, {}).items()}
    if "--print" in argv:
        print(render_block(current))
        return 0
    try:
        html = fetch(STOCKS_URL)
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"[refresh] FETCH FAILED ({e}) — scans unaffected; retry later.", file=sys.stderr)
        return 2
    fetched = parse(html)
    if not fetched:
        addrs = sorted(set(a.lower() for a in _ADDR_RE.findall(html)))
        print(f"[refresh] parsed 0 ticker/address pairs; found {len(addrs)} b2-addresses. "
              f"Page structure may have changed — inspect manually.", file=sys.stderr)
        return 2

    added = {t: a for t, a in fetched.items() if t not in current}
    changed = {t: (current[t], a) for t, a in fetched.items() if t in current and current[t] != a}
    removed = {t: current[t] for t in current if t not in fetched}
    if not (added or changed or removed):
        print(f"[refresh] in sync — {len(current)} official tokenized stocks on chain {CHAIN}.")
        return 0

    print("[refresh] DRIFT vs constants.OFFICIAL_TOKENIZED_STOCKS:", file=sys.stderr)
    for t, a in added.items():
        print(f"  + ADDED   {t} = {a}", file=sys.stderr)
    for t, (old, new) in changed.items():
        print(f"  ~ CHANGED {t}: {old} -> {new}", file=sys.stderr)
    for t, a in removed.items():
        print(f"  - REMOVED {t} (was {a})", file=sys.stderr)
    print("\n# Regenerated block (verify addresses on BaseScan, then paste into constants.py):\n")
    merged = {**current, **fetched}
    for t in removed:
        merged.pop(t, None)
    print(render_block(merged))
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
