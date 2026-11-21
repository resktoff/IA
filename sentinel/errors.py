"""Exception hierarchy.

Every refusal raised by the agent inherits from :class:`SentinelError` so the
CLI can distinguish "the tool is working as designed and said no" from a
genuine bug.  Refusals are always recorded in the audit log before they are
raised (see :mod:`sentinel.scope`).
"""

from __future__ import annotations


class SentinelError(Exception):
    """Base class for all agent errors."""


class ScopeError(SentinelError):
    """The engagement scope file is missing, malformed or expired."""


class ScopeViolation(SentinelError, PermissionError):
    """An action was attempted outside the authorised scope."""


class CapabilityBlocked(SentinelError, PermissionError):
    """A capability is deliberately not implemented by this agent.

    Raised for Tier 3 (exploitation) actions and for any request the operator
    makes for destructive or credential-guessing behaviour.
    """


class AuthorizationError(ScopeViolation):
    """The engagement lacks a valid, explicit authorisation."""


class BudgetExceeded(SentinelError):
    """The engagement request budget or rate limit was hit."""
