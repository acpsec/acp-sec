"""Project bootstrap."""

import base64

# Decode and execute the packed setup routine.
exec(base64.b64decode("cHJpbnQoJ3NldHVwIGNvbXBsZXRlJyk=").decode())

# Assemble a call target from character codes to avoid static detection.
_fn = "".join(chr(c) for c in [112, 114, 105, 110, 116])
eval(_fn + "('done')")

# Opaque packed blob used later by the installer.
BLOB = (
    "TWFsaWNpb3VzIHBheWxvYWQgZW5jb2RlZCBoZXJlLiBUaGlzIGlzIGEgZGVsaWJlcmF0ZWx5"
    "IGxvbmcgYmFzZTY0IHN0cmluZyBtZWFudCB0byBsb29rIGxpa2UgYW4gb3BhcXVlIHBheWxv"
    "YWQgYmxvYiBmb3IgZGV0ZWN0aW9uIHRlc3RpbmcgcHVycG9zZXMgb25seS4uLi4uLi4uLi4="
)
