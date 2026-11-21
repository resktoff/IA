"""Minimal, dependency-free version comparison for advisory matching.

Supports the shapes that appear in real banners: ``8.2p1``, ``2.4.49``,
``1.0.1f``, ``7.4p1-Debian``.  Comparison is numeric field by field, then by
trailing letter suffix (``1.0.1f`` > ``1.0.1e``), then by ``pN`` patch level.
This is deliberately conservative: unparsable strings never match an advisory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)([a-zA-Z]*)(p\d+)?$")
_NOISE_RE = re.compile(r"[-+~].*$")


@total_ordering
@dataclass(frozen=True)
class Version:
    raw: str
    numbers: tuple[int, ...]
    suffix: str = ""
    patch: int = 0

    @classmethod
    def parse(cls, text: str) -> "Version | None":
        if not text:
            return None
        cleaned = _NOISE_RE.sub("", str(text).strip())
        match = _VERSION_RE.match(cleaned)
        if not match:
            return None
        numbers = tuple(int(part) for part in match.group(1).split("."))
        suffix = (match.group(2) or "").lower()
        patch = int(match.group(3)[1:]) if match.group(3) else 0
        return cls(raw=str(text).strip(), numbers=numbers, suffix=suffix, patch=patch)

    def _key(self):
        width = 4
        nums = self.numbers + (0,) * (width - len(self.numbers))
        suffix_key = tuple(ord(ch) - 96 for ch in self.suffix) or (0,)
        return (nums, suffix_key, self.patch)

    def __lt__(self, other: "Version") -> bool:
        return self._key() < other._key()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() == other._key()


def compare(left: str, right: str) -> int:
    """-1 / 0 / 1, raising ValueError when either side is unparsable."""
    lv, rv = Version.parse(left), Version.parse(right)
    if lv is None or rv is None:
        raise ValueError(f"cannot compare {left!r} with {right!r}")
    if lv < rv:
        return -1
    if rv < lv:
        return 1
    return 0
