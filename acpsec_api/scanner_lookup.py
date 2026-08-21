"""Standalone X/Twitter profile scraper via Nitter.

Copied verbatim from ``dashboard/scanner.py`` (scrape_x_profile + its module
constants) to keep acpsec_api free of any dashboard/ dependency. Same Nitter
instances, headers, timeout, and error paths as the Flask reference.

``SCRAPER_AVAILABLE`` mirrors Flask's ``_get_scanner() is not None`` check: the
scraper is usable only when its runtime deps (requests, bs4) import cleanly.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any
from urllib.parse import urljoin

try:
    import requests
    from bs4 import BeautifulSoup

    SCRAPER_AVAILABLE = True
except ImportError:
    SCRAPER_AVAILABLE = False

# --- Copied constants (dashboard/scanner.py) -------------------------------

NITTER_INSTANCES = [
    "https://nitter.poast.org",
    "https://nitter.privacydev.net",
    "https://nitter.cz",
    "https://nitter.net",
]

DEFAULT_TIMEOUT = 9   # seconds per request

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Last instance that successfully returned profile data. Tried first on the
# next call to avoid iterating from scratch when one instance is consistently
# healthy. Reset to None only when the instance is removed from NITTER_INSTANCES.
_last_good_instance: str | None = None


def _ordered_instances() -> list[str]:
    """Return NITTER_INSTANCES with _last_good_instance prepended if set."""
    if _last_good_instance and _last_good_instance in NITTER_INSTANCES:
        return [_last_good_instance] + [
            i for i in NITTER_INSTANCES if i != _last_good_instance
        ]
    return list(NITTER_INSTANCES)


def scrape_x_profile(username: str) -> dict[str, Any]:
    """Try to fetch basic X profile info via a Nitter instance.

    Returns a dict with keys:
        username, display_name, bio, website, avatar_url,
        source, error,
        fetch_status, nitter_instance, instance_errors

    fetch_status values:
        "ok"         — one instance served the profile; nitter_instance is set
        "all_failed" — all instances raised exceptions or returned non-200
        "blocked"    — at least one instance returned 200 but no profile elements
                       (X/Nitter actively hiding the profile)
    """
    global _last_good_instance

    username = username.lstrip("@").strip()

    instance_errors: list[dict[str, str]] = []
    any_blocked = False  # True if any instance returned 200 with no profile data

    for instance in _ordered_instances():
        try:
            url  = f"{instance}/{username}"
            resp = requests.get(url, headers=BROWSER_HEADERS,
                                timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if resp.status_code != 200:
                instance_errors.append({
                    "instance": instance,
                    "error": f"HTTP {resp.status_code}",
                })
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Nitter uses several possible class names depending on version
            display_name_el = (
                soup.select_one(".profile-card-fullname")
                or soup.select_one("a.profile-card-fullname")
                or soup.select_one(".fullname")
            )
            bio_el = (
                soup.select_one(".profile-bio")
                or soup.select_one(".bio p")
            )
            website_el = (
                soup.select_one(".profile-website a")
                or soup.select_one(".profile-card-extra a[href]")
            )
            avatar_el = soup.select_one(
                ".profile-card-avatar img, .avatar img, img.avatar"
            )

            display_name = display_name_el.get_text(strip=True) if display_name_el else ""
            bio_text     = bio_el.get_text(strip=True) if bio_el else ""

            # Nitter sometimes proxies links as /url?url=<encoded>
            website_href = ""
            if website_el:
                href = website_el.get("href", "")
                if "/url?url=" in href:
                    m = re.search(r"url=([^&]+)", href)
                    if m:
                        website_href = urllib.parse.unquote(m.group(1))
                elif href.startswith("http"):
                    website_href = href
                elif href:
                    website_href = urljoin(instance, href)

            avatar_url = ""
            if avatar_el:
                src = avatar_el.get("src", "")
                if src:
                    avatar_url = urljoin(instance, src) if not src.startswith("http") else src

            if display_name or bio_text:
                _last_good_instance = instance
                return {
                    "username":        username,
                    "display_name":    display_name,
                    "bio":             bio_text,
                    "website":         website_href,
                    "avatar_url":      avatar_url,
                    "source":          "nitter",
                    "nitter_url":      url,
                    "error":           None,
                    "fetch_status":    "ok",
                    "nitter_instance": instance,
                    "instance_errors": [],
                }

            # 200 but no parseable profile — Nitter is hiding the profile
            any_blocked = True
            instance_errors.append({
                "instance": instance,
                "error":    "HTTP 200 but no profile elements found (blocked or non-existent profile)",
            })

        except Exception as exc:
            instance_errors.append({
                "instance": instance,
                "error":    f"{type(exc).__name__}: {exc}",
            })

    # All instances exhausted — return empty scaffold for manual entry
    fetch_status = "blocked" if any_blocked else "all_failed"
    return {
        "username":        username,
        "display_name":    "",
        "bio":             "",
        "website":         "",
        "avatar_url":      "",
        "source":          "failed",
        "error":           (
            "Could not reach any Nitter instance — X is blocking scrapers. "
            "Please fill in the agent name and website URL manually."
        ),
        "fetch_status":    fetch_status,
        "nitter_instance": None,
        "instance_errors": instance_errors,
    }
