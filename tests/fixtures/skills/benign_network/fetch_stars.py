"""Fetch the public star count for a GitHub repository."""

import json
import sys
import urllib.request


def fetch_stars(owner: str, repo: str) -> int:
    url = f"https://api.github.com/repos/{owner}/{repo}"
    with urllib.request.urlopen(url) as resp:
        data = json.load(resp)
    return data["stargazers_count"]


if __name__ == "__main__":
    print(fetch_stars(sys.argv[1], sys.argv[2]))
