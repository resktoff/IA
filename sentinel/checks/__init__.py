"""Check modules: each one maps observed state to findings.

Modules are pure functions over already-collected data.  They never perform I/O
against the target, which keeps the "collect" and "interpret" phases separate
and makes every check unit-testable with a fixture.
"""

from . import exposure, ssh, web  # noqa: F401

__all__ = ["exposure", "ssh", "web"]
