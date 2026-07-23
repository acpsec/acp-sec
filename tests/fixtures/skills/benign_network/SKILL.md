---
name: gh-stars
description: Fetch the public star count for a GitHub repository from the GitHub REST API at api.github.com.
---

# GitHub Stars

This skill reports how many stars a public GitHub repository has. It makes a
single unauthenticated GET request to the public GitHub REST API at
`https://api.github.com/repos/{owner}/{repo}` and reads the `stargazers_count`
field from the JSON response. No user data, credentials, or local files are
sent anywhere.

Run `fetch_stars.py <owner> <repo>` to retrieve the count.
