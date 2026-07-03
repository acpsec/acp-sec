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


def scrape_x_profile(username: str) -> dict[str, Any]:
    """Try to fetch basic X profile info via a Nitter instance.

    Returns a dict with keys:
        username, display_name, bio, website, avatar_url, source, error
    source = 'nitter' on success, 'failed' if all instances unreachable.
    """
    username = username.lstrip("@").strip()

    for instance in NITTER_INSTANCES:
        try:
            url  = f"{instance}/{username}"
            resp = requests.get(url, headers=BROWSER_HEADERS,
                                timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if resp.status_code != 200:
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
                return {
                    "username":     username,
                    "display_name": display_name,
                    "bio":          bio_text,
                    "website":      website_href,
                    "avatar_url":   avatar_url,
                    "source":       "nitter",
                    "nitter_url":   url,
                    "error":        None,
                }

        except Exception:
            continue  # try next instance

    # All instances failed — return empty scaffold for manual entry
    return {
        "username":     username,
        "display_name": "",
        "bio":          "",
        "website":      "",
        "avatar_url":   "",
        "source":       "failed",
        "error":        (
            "Could not reach any Nitter instance — X is blocking scrapers. "
            "Please fill in the agent name and website URL manually."
        ),
    }
