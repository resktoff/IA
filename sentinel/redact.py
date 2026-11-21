"""Redaction of secret-looking values before anything is written to a report.

The agent is designed not to collect secrets (it never reads /etc/shadow, never
submits credentials and reads no response bodies by default).  This module is
defence in depth for the cases that slip through: a banner containing a token,
a cookie value, an `Authorization` header echoed by a misconfigured proxy.

Redaction is *targeted*: identifiers that the report must keep for
traceability (engagement id, authorization reference, file paths) are not
touched, and a `Set-Cookie` header keeps its attributes while losing only the
value.
"""

from __future__ import annotations

import re
from typing import Any

# Keys whose whole value is replaced.  Deliberately excludes "authorization" and
# "session" so that `authorization_ref` and `session management` stay readable;
# the *values* of Authorization headers are covered by TEXT_PATTERNS below.
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key|credential|bearer)"
)
COOKIE_KEY_RE = re.compile(r"(?i)cookie")

TEXT_PATTERNS = (
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]{8,}"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;\"']+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
)


def redact_text(text: str) -> str:
    if not isinstance(text, str):
        return text
    out = TEXT_PATTERNS[2].sub("[REDACTED PRIVATE KEY]", text)
    out = TEXT_PATTERNS[0].sub(lambda m: f"{m.group(1)} [REDACTED]", out)
    out = TEXT_PATTERNS[1].sub(lambda m: f"{m.group(1)}=[REDACTED]", out)
    return out


def redact_cookie(header: str) -> str:
    """Keep the cookie name and attributes, drop the value."""
    if not isinstance(header, str) or not header:
        return header
    parts = header.split(";")
    first = parts[0]
    if "=" in first:
        name = first.split("=", 1)[0]
        parts[0] = f"{name}=[REDACTED]"
    return ";".join(parts)


def redact_obj(obj: Any, _depth: int = 0) -> Any:
    if _depth > 12:
        return "[TRUNCATED: nesting too deep]"
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if COOKIE_KEY_RE.search(str(key)) and isinstance(value, (str, list)):
                if isinstance(value, list):
                    out[key] = [redact_cookie(v) if isinstance(v, str) else redact_obj(v, _depth + 1)
                                for v in value]
                else:
                    out[key] = redact_cookie(value)
            elif SENSITIVE_KEY_RE.search(str(key)):
                out[key] = "[REDACTED]"
            else:
                out[key] = redact_obj(value, _depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, _depth + 1) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj
