"""CVSS v3.1 base score, implemented from the specification.

Reference: FIRST, "Common Vulnerability Scoring System v3.1: Specification
Document", section 7.1 (base equations) and section 7.4 (Roundup).

Only the *base* metric group is implemented.  Temporal and environmental
scores are **not** implemented (see docs/DECISIONS.md, ADR-007): they depend on
data this agent does not collect (exploit maturity, customer-specific asset
criticality) and pretending otherwise would inflate the numbers.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Mapping

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

BASE_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CVSSError(ValueError):
    pass


def roundup(value: float) -> float:
    """CVSS v3.1 Appendix A Roundup.

    Uses integer arithmetic to avoid the floating point bug that produced
    inconsistent scores in v3.0.
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        raise CVSSError("vector must start with 'CVSS:3.1/'")
    parts = vector.split("/")[1:]
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise CVSSError(f"malformed metric segment: {part!r}")
        key, value = part.split(":", 1)
        if key not in BASE_METRIC_ORDER:
            raise CVSSError(f"unsupported metric: {key!r} — not implemented (only base metrics are scored)")
        if key in metrics:
            raise CVSSError(f"duplicate metric: {key!r}")
        if key != "S" and value not in {"N", "A", "L", "P", "H", "R", "C"}:  # permissive, validated below
            raise CVSSError(f"invalid value {value!r} for {key}")
        metrics[key] = value
    missing = [m for m in BASE_METRIC_ORDER if m not in metrics]
    if missing:
        raise CVSSError(f"missing base metrics: {', '.join(missing)}")
    if metrics["S"] not in {"U", "C"}:
        raise CVSSError("S must be U or C")
    allowed = {
        "AV": AV, "AC": AC, "UI": UI, "C": CIA, "I": CIA, "A": CIA,
    }
    for key, table in allowed.items():
        if metrics[key] not in table:
            raise CVSSError(f"invalid value {metrics[key]!r} for {key}")
    if metrics["PR"] not in PR_UNCHANGED:
        raise CVSSError("invalid value for PR")
    return metrics


@dataclass(frozen=True)
class CVSSv31:
    vector: str
    av: str
    ac: str
    pr: str
    ui: str
    scope: str
    c: str
    i: str
    a: str
    score: float
    severity: str

    def to_dict(self) -> dict[str, object]:
        return {
            "vector": self.vector,
            "score": self.score,
            "severity": self.severity,
            "metrics": {
                "AV": self.av, "AC": self.ac, "PR": self.pr, "UI": self.ui,
                "S": self.scope, "C": self.c, "I": self.i, "A": self.a,
            },
        }


def severity_band(score: float) -> str:
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def from_metrics(m: Mapping[str, str], vector: str | None = None) -> CVSSv31:
    changed = m["S"] == "C"
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr_table = PR_CHANGED if changed else PR_UNCHANGED
    exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr_table[m["PR"]] * UI[m["UI"]]
    if impact <= 0:
        score = 0.0
    elif changed:
        score = roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        score = roundup(min(impact + exploitability, 10.0))
    return CVSSv31(
        vector=vector or base_vector(m),
        av=m["AV"], ac=m["AC"], pr=m["PR"], ui=m["UI"], scope=m["S"],
        c=m["C"], i=m["I"], a=m["A"], score=score, severity=severity_band(score),
    )


def base_vector(m: Mapping[str, str]) -> str:
    return "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in BASE_METRIC_ORDER)


def score(vector: str) -> CVSSv31:
    metrics = parse_vector(vector)
    return from_metrics(metrics, vector=base_vector(metrics))
