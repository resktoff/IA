"""Core data model shared by collectors, checks and the reporter.

Design notes
------------
* Findings never claim more than they measured.  ``confidence`` and
  ``validation_state`` are mandatory, so a version-based guess cannot be
  rendered as a confirmed observation.
* Every piece of evidence carries a SHA-256 digest over its canonical JSON,
  which makes the report tamper-evident without needing a database.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score <= 0:
            return cls.NONE
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL

    @property
    def rank(self) -> int:
        return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, Enum):
    """How strongly the evidence supports the finding."""

    CONFIRMED = "confirmed"    # directly observed behaviour / state
    INFERRED = "inferred"      # derived from a version string or config value
    HYPOTHESIS = "hypothesis"  # plausible path, requires manual validation


class ValidationState(str, Enum):
    OBSERVED = "observed"                  # a safe request produced this state
    INFERRED = "inferred"                  # matched against an advisory database
    NOT_VALIDATED = "not_validated"        # identified, not proven exploitable
    BLOCKED_BY_POLICY = "blocked_by_policy"


class Tier(int, Enum):
    """Capability tiers enforced by :class:`sentinel.scope.ScopeGuard`."""

    DETECT = 1     # passive / read-only observation
    VALIDATE = 2   # bounded active probe with no state change
    EXPLOIT = 3    # not implemented (see docs/DECISIONS.md, ADR-002)


@dataclass
class Evidence:
    kind: str
    asset: str
    summary: str
    data: dict[str, Any]
    source: str
    collected_at: str = field(default_factory=utcnow)

    def digest(self) -> str:
        return sha256_hex(canonical_json({"kind": self.kind, "asset": self.asset, "data": self.data}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "asset": self.asset,
            "summary": self.summary,
            "source": self.source,
            "collected_at": self.collected_at,
            "evidence_sha256": self.digest(),
            "data": self.data,
        }


@dataclass
class Service:
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    banner: str | None = None
    product: str | None = None
    version: str | None = None
    tls: dict[str, Any] | None = None
    http: dict[str, Any] | None = None
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "banner": self.banner,
            "product": self.product,
            "version": self.version,
            "tls": self.tls,
            "http": self.http,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class Asset:
    host: str
    role: str = "host"
    os: dict[str, Any] | None = None
    services: list[Service] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "role": self.role,
            "os": self.os,
            "services": [s.to_dict() for s in self.services],
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class Finding:
    check_id: str
    title: str
    category: str
    asset: str
    severity: Severity
    impact: str
    remediation: str
    confidence: Confidence = Confidence.CONFIRMED
    validation_state: ValidationState = ValidationState.OBSERVED
    port: int | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    tier_required: Tier = Tier.DETECT
    prerequisites: list[str] = field(default_factory=list)
    manual_validation_required: bool = False
    notes: str | None = None
    fingerprint_seed: str | None = None

    def __post_init__(self) -> None:
        if self.cvss_score is not None:
            # The score always wins over a hand-assigned severity.
            self.severity = Severity.from_score(self.cvss_score)

    @property
    def id(self) -> str:
        seed = self.fingerprint_seed or f"{self.asset}|{self.port}|{self.check_id}|{self.title}"
        return "F-" + sha256_hex(seed)[:10]

    def sort_key(self) -> tuple:
        return (-(self.cvss_score or 0.0), -self.severity.rank, self.asset, self.port or 0, self.check_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "check_id": self.check_id,
            "title": self.title,
            "category": self.category,
            "asset": self.asset,
            "port": self.port,
            "severity": self.severity.value,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence.value,
            "validation_state": self.validation_state.value,
            "tier_required": int(self.tier_required),
            "impact": self.impact,
            "remediation": self.remediation,
            "references": list(self.references),
            "tags": list(self.tags),
            "prerequisites": list(self.prerequisites),
            "manual_validation_required": self.manual_validation_required,
            "notes": self.notes,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class CapabilityCoverage:
    """Machine-readable statement of what the run actually exercised."""

    id: str
    name: str
    status: str                     # implemented | partial | designed_only | blocked
    exercised_in_run: bool
    detail: str
    code_ref: str
    test_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "exercised_in_run": self.exercised_in_run,
            "detail": self.detail,
            "code_ref": self.code_ref,
            "test_ref": self.test_ref,
        }


@dataclass
class Assessment:
    engagement_id: str
    operator: str
    target_mode: str
    scope_summary: dict[str, Any]
    started_at: str = field(default_factory=utcnow)
    finished_at: str | None = None
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage: list[CapabilityCoverage] = field(default_factory=list)
    audit_path: str | None = None
    audit_chain: dict[str, Any] | None = None
    skipped: list[dict[str, Any]] = field(default_factory=list)
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def add_findings(self, findings: Iterable[Finding]) -> None:
        seen = {f.id for f in self.findings}
        for f in findings:
            if f.id not in seen:
                seen.add(f.id)
                self.findings.append(f)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "sentinel.assessment/1",
            "run_id": self.run_id,
            "engagement_id": self.engagement_id,
            "operator": self.operator,
            "target_mode": self.target_mode,
            "scope": self.scope_summary,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "audit_path": self.audit_path,
            "audit_chain": self.audit_chain,
            "severity_counts": self.counts_by_severity(),
            "assets": [a.to_dict() for a in self.assets],
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "coverage": [c.to_dict() for c in self.coverage],
            "skipped": self.skipped,
        }
