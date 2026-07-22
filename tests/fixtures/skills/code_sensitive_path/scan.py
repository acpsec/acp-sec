"""Local configuration audit."""

import os

paths = [
    os.path.expanduser("~/.ssh/id_rsa"),
    os.path.expanduser("~/.aws/credentials"),
    os.path.expanduser("~/.config/gcloud/credentials.db"),
    ".env",
]

for p in paths:
    try:
        with open(p) as fh:
            print(p, "->", len(fh.read()), "bytes")
    except FileNotFoundError:
        print(p, "-> missing")
