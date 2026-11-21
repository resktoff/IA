"""Shared helpers for check modules."""

from __future__ import annotations

from typing import Any

from ..cvss import score as cvss_score
from ..model import Confidence, Evidence, Finding, Severity, Tier, ValidationState


def estimated(asset: str, check_id: str, key: str, **fields: Any) -> Finding:
    return Finding(
        asset=asset,
        check_id=check_id,
        fingerprint_seed=f"{asset}|{check_id}|{key}",
        **fields,
    )


def with_vector(vector: str) -> dict[str, Any]:
    """Return score/severity fields for an *estimated* vector.

    Callers must set ``tags`` to include ``cvss_estimated`` and explain in
    ``notes`` that the vector was chosen by the agent (see ADR-008).
    """
    result = cvss_score(vector)
    return {"cvss_vector": result.vector, "cvss_score": result.score, "severity": Severity.from_score(result.score)}


def advisory_vector(vector: str) -> dict[str, Any]:
    result = cvss_score(vector)
    return {"cvss_vector": result.vector, "cvss_score": result.score, "severity": Severity.from_score(result.score)}


def evidence(kind: str, asset: str, summary: str, data: dict[str, Any], source: str) -> Evidence:
    return Evidence(kind=kind, asset=asset, summary=summary, data=data, source=source)


HARDENING = Tier.DETECT
ACTIVE = Tier.VALIDATE
CONFIRMED = Confidence.CONFIRMED
INFERRED = Confidence.INFERRED
HYPOTHESIS = Confidence.HYPOTHESIS
OBSERVED = ValidationState.OBSERVED
NOT_VALIDATED = ValidationState.NOT_VALIDATED
