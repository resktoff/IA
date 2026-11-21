"""Engagement scope, authorisation gate and runtime guard.

This module is the primary *control* of the agent.  Every action that touches
the target environment (network packet, local fact collection) must pass
through :class:`ScopeGuard`.  The rules, in order of evaluation:

1. **Kill switch.** If the file named by ``killswitch_path`` exists, every
   action is refused.  The operator can stop a run with ``touch STOP``.
2. **Validity window.** ``not_before <= now < expires_at``.  Expired
   engagements cannot be resumed by editing the clock: the scope is reloaded
   from disk on every run.
3. **Declared authorisation.** ``authorization.authorized`` must be ``true`` and
   must carry non-empty ``reference`` and ``approved_by`` fields. These are
   declarations supplied in the scope; this code does not verify external
   approval, identity, tickets, contracts, or consent. A scope without the
   required declarations is rejected at load time.
4. **Tier.** ``EXPLOIT`` (3) is refused unconditionally, even if the scope file
   asks for it (ADR-002).  Each target also declares its own ``max_tier``.
5. **Target allowlist.** Default deny.  A host must match a declared target;
   the port must be in that target's port set.
6. **Address rules.** Link-local and the configured cloud metadata endpoints
   (including `169.254.169.254` and `fd00:ec2::254`), multicast, broadcast,
   unspecified and reserved ranges are refused even when declared. Public
   addresses require two explicit opt-ins.
7. **Budget and rate.** A hard request budget and a token bucket cap request
   volume, so a mis-scoped run cannot turn into a flood.

Every allow *and* every deny is written to the audit log before the call
returns (or before the exception is raised), which is what makes the control
auditable after the fact.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .audit import AuditLog
from .errors import (
    AuthorizationError,
    BudgetExceeded,
    CapabilityBlocked,
    ScopeError,
    ScopeViolation,
)
from .model import Tier

SCOPE_SCHEMA = "sentinel.scope/1"

ALWAYS_BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local, incl. 169.254.169.254 metadata
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),         # IPv6 multicast
)

METADATA_ADDRESSES = ("169.254.169.254", "fd00:ec2::254")


def _is_metadata_address(ip: ipaddress._BaseAddress) -> bool:
    if str(ip) in METADATA_ADDRESSES:
        return True
    mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
    return mapped is not None and str(mapped) in METADATA_ADDRESSES


class PortSet:
    """Port allowlist parsed from ints or 'a-b' ranges."""

    def __init__(self, spec: Iterable[int | str]) -> None:
        ports: set[int] = set()
        for item in spec:
            if isinstance(item, int):
                ports.add(item)
            elif isinstance(item, str) and "-" in item:
                lo, hi = item.split("-", 1)
                ports.update(range(int(lo), int(hi) + 1))
            elif isinstance(item, str) and item.isdigit():
                ports.add(int(item))
            else:
                raise ScopeError(f"invalid port specification: {item!r}")
        if not ports:
            raise ScopeError("port list is empty")
        bad = [p for p in ports if not 1 <= p <= 65535]
        if bad:
            raise ScopeError(f"port out of range: {bad}")
        self.ports = ports

    def __contains__(self, port: int) -> bool:
        return port in self.ports

    def __iter__(self):
        return iter(sorted(self.ports))

    def __len__(self) -> int:
        return len(self.ports)

    def render(self) -> str:
        items = sorted(self.ports)
        out, start, prev = [], items[0], items[0]
        for p in items[1:]:
            if p == prev + 1:
                prev = p
                continue
            out.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = p
        out.append(f"{start}-{prev}" if start != prev else str(start))
        return ",".join(out)


@dataclass(frozen=True)
class Target:
    kind: str                       # host | cidr | local_host
    value: str
    ports: PortSet
    max_tier: int
    allow_public: bool = False
    note: str = ""

    def render(self) -> str:
        if self.kind == "local_host":
            return f"local_host:{self.value}"
        return f"{self.kind}:{self.value} [{self.ports.render()}]"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "ports": self.ports.render(),
            "max_tier": self.max_tier,
            "allow_public": self.allow_public,
            "note": self.note,
        }


@dataclass
class Scope:
    engagement_id: str
    client: str
    operator: str
    authorization_ref: str
    approved_by: str
    authorized: bool
    not_before: datetime
    expires_at: datetime
    targets: list[Target]
    max_requests: int = 500
    rate_per_second: float = 5.0
    burst: int = 10
    killswitch_path: str | None = None
    source_path: str | None = None
    notes: str = ""
    allow_public: bool = False
    allowed_categories: list[str] = field(default_factory=list)

    # ---------------------------------------------------------------- loading
    @classmethod
    def from_file(cls, path: str) -> "Scope":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise ScopeError(f"scope file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ScopeError(f"scope file is not valid JSON: {exc}") from exc
        scope = cls.from_dict(data, source_path=path)
        return scope

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: str | None = None) -> "Scope":
        if data.get("schema") != SCOPE_SCHEMA:
            raise ScopeError(f"unsupported scope schema: {data.get('schema')!r} (expected {SCOPE_SCHEMA})")

        auth = data.get("authorization") or {}
        if auth.get("authorized") is not True:
            raise AuthorizationError(
                "scope has no explicit authorisation (authorization.authorized must be true; "
                "this field is not externally verified)"
            )
        ref = str(auth.get("reference") or "").strip()
        approved_by = str(auth.get("approved_by") or "").strip()
        if not ref or not approved_by:
            raise AuthorizationError(
                "authorization.reference and authorization.approved_by are required "
                "(ticket or contract id, and the person who approved it)"
            )

        try:
            not_before = _parse_dt(data["valid_from"])
            expires_at = _parse_dt(data["expires_at"])
        except KeyError as exc:
            raise ScopeError(f"missing required field: {exc.args[0]}") from exc
        now = datetime.now(timezone.utc)
        if expires_at <= not_before:
            raise ScopeError("expires_at must be after valid_from")
        if expires_at <= now:
            raise ScopeError(f"engagement expired at {expires_at.isoformat()}")
        if not_before > now:
            raise ScopeError(f"engagement is not valid until {not_before.isoformat()}")

        raw_targets = data.get("targets") or []
        if not raw_targets:
            raise ScopeError("scope declares no targets (default deny)")

        allow_public = bool(data.get("allow_public", False))
        targets: list[Target] = []
        for idx, t in enumerate(raw_targets):
            kind = str(t.get("kind", "")).strip()
            if kind not in {"host", "cidr", "local_host"}:
                raise ScopeError(f"targets[{idx}]: unsupported kind {kind!r}")
            value = str(t.get("value", "")).strip()
            if not value:
                raise ScopeError(f"targets[{idx}]: empty value")
            max_tier = int(t.get("max_tier", int(Tier.VALIDATE)))
            if max_tier >= int(Tier.EXPLOIT):
                # Silently downgrade instead of failing: the operator cannot buy
                # exploitation by editing the scope file (ADR-002).
                max_tier = int(Tier.VALIDATE)
            if max_tier < int(Tier.DETECT):
                raise ScopeError(f"targets[{idx}]: max_tier must be >= 1")
            ports = PortSet(t.get("ports") or [])
            if kind in {"host", "cidr"}:
                _validate_network_target(value, kind, bool(t.get("allow_public", False)), allow_public, idx)
            targets.append(
                Target(
                    kind=kind,
                    value=value,
                    ports=ports,
                    max_tier=max_tier,
                    allow_public=bool(t.get("allow_public", False)),
                    note=str(t.get("note", "")),
                )
            )

        max_requests = int(data.get("max_requests", 500))
        if max_requests <= 0:
            raise ScopeError("max_requests must be positive")
        rate = float(data.get("rate_per_second", 5.0))
        if rate <= 0:
            raise ScopeError("rate_per_second must be positive")

        return cls(
            engagement_id=str(data.get("engagement_id") or "").strip() or "<unnamed>",
            client=str(data.get("client") or "").strip() or "<unnamed>",
            operator=str(data.get("operator") or "").strip() or "<unnamed>",
            authorization_ref=ref,
            approved_by=approved_by,
            authorized=True,
            not_before=not_before,
            expires_at=expires_at,
            targets=targets,
            max_requests=max_requests,
            rate_per_second=rate,
            burst=int(data.get("burst", 10)),
            killswitch_path=data.get("killswitch_path"),
            source_path=source_path,
            notes=str(data.get("notes", "")),
            allow_public=allow_public,
            allowed_categories=list(data.get("allowed_categories") or []),
        )

    # ----------------------------------------------------------------- views
    @property
    def max_tier(self) -> int:
        return max(t.max_tier for t in self.targets)

    def summary(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "client": self.client,
            "operator": self.operator,
            "authorization_ref": self.authorization_ref,
            "approved_by": self.approved_by,
            "valid_from": self.not_before.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "max_tier": self.max_tier,
            "max_requests": self.max_requests,
            "rate_per_second": self.rate_per_second,
            "killswitch_path": self.killswitch_path,
            "scope_file": self.source_path,
            "targets": [t.to_dict() for t in self.targets],
        }

    def targets_for_tier(self, tier: Tier) -> list[Target]:
        return [t for t in self.targets if t.max_tier >= int(tier)]


def _parse_dt(value: str) -> datetime:
    try:
        raw = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
    except (ValueError, AttributeError) as exc:
        raise ScopeError(f"invalid ISO-8601 datetime: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _validate_network_target(value: str, kind: str, target_public: bool, scope_public: bool, idx: int) -> None:
    try:
        if kind == "cidr":
            net = ipaddress.ip_network(value, strict=False)
            candidates = [net.network_address]
            for metadata in METADATA_ADDRESSES:
                metadata_ip = ipaddress.ip_address(metadata)
                aliases = [metadata_ip]
                if metadata_ip.version == 4:
                    aliases.append(ipaddress.IPv6Address(f"::ffff:{metadata_ip}"))
                if any(alias.version == net.version and alias in net for alias in aliases):
                    raise ScopeError(f"targets[{idx}]: {value} contains blocked cloud metadata endpoint {metadata}")
            for blocked in ALWAYS_BLOCKED_NETWORKS:
                if net.version == blocked.version and net.overlaps(blocked):
                    raise ScopeError(f"targets[{idx}]: {value} overlaps always-blocked range {blocked}")
        else:
            candidates = [ipaddress.ip_address(value)]
    except ValueError as exc:
        raise ScopeError(f"targets[{idx}]: {value!r} is not a valid IP or CIDR (hostnames are not accepted as targets)") from exc

    for ip in candidates:
        for blocked in ALWAYS_BLOCKED_NETWORKS:
            if ip.version == blocked.version and ip in blocked:
                raise ScopeError(f"targets[{idx}]: {ip} is in always-blocked range {blocked}")
        if _is_metadata_address(ip):
            raise ScopeError(f"targets[{idx}]: cloud metadata endpoint {METADATA_ADDRESSES} is always blocked")
        if ip.is_global and not (target_public and scope_public):
            raise ScopeError(
                f"targets[{idx}]: {ip} is a public address; it requires allow_public=true on both the "
                "scope and the target (ADR-004)"
            )


class TokenBucket:
    def __init__(self, rate: float, burst: int, clock=time.monotonic, sleeper=time.sleep) -> None:
        self.rate = rate
        self.capacity = max(1, burst)
        self._tokens = float(self.capacity)
        self._last = clock()
        self._clock = clock
        self._sleep = sleeper
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> float:
        """Block until ``tokens`` are available. Returns seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = self._clock()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                deficit = tokens - self._tokens
                delay = deficit / self.rate
            waited += delay
            self._sleep(delay)


@dataclass
class GuardStats:
    allowed: int = 0
    denied: int = 0
    network_ops: int = 0
    seconds_throttled: float = 0.0
    killswitch_tripped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "denied": self.denied,
            "network_ops": self.network_ops,
            "seconds_throttled": round(self.seconds_throttled, 3),
            "killswitch_tripped": self.killswitch_tripped,
        }


class ScopeGuard:
    """Authorises (or refuses) every action, logging the decision."""

    def __init__(
        self,
        scope: Scope,
        audit: AuditLog,
        *,
        clock=datetime.now,
        bucket: TokenBucket | None = None,
        resolver=None,
    ) -> None:
        self.scope = scope
        self.audit = audit
        self.stats = GuardStats()
        self._bucket = bucket or TokenBucket(scope.rate_per_second, scope.burst)
        self._clock = clock
        self._resolver = resolver or socket.getaddrinfo
        self._lock = threading.RLock()

    # --------------------------------------------------------------- helpers
    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now.astimezone(timezone.utc)

    def _deny(self, action: str, target: str | None, reason: str, tier: int, exc: Exception):
        with self._lock:
            self.stats.denied += 1
        self.audit.record(action, "denied", target=target, tier=tier, detail={"reason": reason})
        raise exc(self.refusal_message(action, target, reason))

    @staticmethod
    def refusal_message(action: str, target: str | None, reason: str) -> str:
        return f"REFUSED {action} on {target or '<local>'}: {reason}"

    def _check_killswitch(self, action: str, target: str | None, tier: int) -> None:
        path = self.scope.killswitch_path
        if path and os.path.exists(path):
            self.stats.killswitch_tripped = True
            self._deny(action, target, f"kill switch engaged ({path} exists)", tier, BudgetExceeded)

    def _check_window(self, action: str, target: str | None, tier: int) -> None:
        now = self._now()
        if now < self.scope.not_before:
            self._deny(action, target, f"engagement not valid before {self.scope.not_before.isoformat()}", tier, AuthorizationError)
        if now >= self.scope.expires_at:
            self._deny(action, target, f"engagement expired at {self.scope.expires_at.isoformat()}", tier, AuthorizationError)
        if not self.scope.authorized:
            self._deny(action, target, "engagement is not authorised", tier, AuthorizationError)

    # ------------------------------------------------------------ public API
    def check_local(self, action: str, tier: Tier = Tier.DETECT) -> None:
        """Authorise a local, read-only collection action (no network egress)."""
        if tier is Tier.EXPLOIT:
            self._deny(action, "local", "exploitation is not implemented (ADR-002)", 3, CapabilityBlocked)
        self._check_killswitch(action, "local", int(tier))
        self._check_window(action, "local", int(tier))
        if not any(t.kind == "local_host" for t in self.scope.targets):
            self._deny(action, "local", "scope declares no local_host target", int(tier), ScopeViolation)
        if int(tier) > max(t.max_tier for t in self.scope.targets if t.kind == "local_host"):
            self._deny(action, "local", f"local target does not allow tier {int(tier)}", int(tier), ScopeViolation)
        with self._lock:
            self.stats.allowed += 1
        self.audit.record(action, "allowed", target="local", tier=int(tier))

    def check(
        self,
        action: str,
        host: str,
        port: int | None = None,
        tier: Tier = Tier.VALIDATE,
    ) -> None:
        target_label = f"{host}:{port}" if port is not None else host

        if tier is Tier.EXPLOIT:
            self._deny(action, target_label, "exploitation is not implemented (ADR-002)", 3, CapabilityBlocked)
        if int(tier) > int(self.scope.max_tier):
            self._deny(action, target_label, f"scope allows at most tier {self.scope.max_tier}", int(tier), ScopeViolation)

        self._check_killswitch(action, target_label, int(tier))
        self._check_window(action, target_label, int(tier))

        target = self._match_target(host)
        if target is None:
            self._deny(action, target_label, "host is not in the scope allowlist", int(tier), ScopeViolation)
        if int(tier) > target.max_tier:
            self._deny(action, target_label, f"target {target.render()} allows at most tier {target.max_tier}", int(tier), ScopeViolation)
        if port is not None and port not in target.ports:
            self._deny(action, target_label, f"port {port} is not allowed for {target.render()}", int(tier), ScopeViolation)

        self._consume_budget(action, target_label, int(tier))
        with self._lock:
            self.stats.allowed += 1
        self.audit.record(
            action, "allowed", target=target_label, tier=int(tier),
            detail={"matched_target": target.render()},
        )

    def try_check(self, action: str, host: str, port: int | None = None, tier: Tier = Tier.VALIDATE) -> tuple[bool, str | None]:
        """Non-raising variant for optional probes. Denials are still logged."""
        try:
            self.check(action, host, port, tier)
            return True, None
        except (ScopeViolation, CapabilityBlocked, BudgetExceeded, AuthorizationError) as exc:
            return False, str(exc)

    # --------------------------------------------------------------- internals
    def _consume_budget(self, action: str, target_label: str, tier: int) -> None:
        # Reserve the operation while holding the same lock used for the limit
        # check. This makes the hard budget safe when callers check concurrently.
        with self._lock:
            exhausted = self.stats.network_ops >= self.scope.max_requests
            if not exhausted:
                self.stats.network_ops += 1
        if exhausted:
            # _deny takes the same lock, so it must be called outside it.
            self._deny(
                action, target_label,
                f"request budget exhausted ({self.scope.max_requests} requests)", tier, BudgetExceeded,
            )
        waited = self._bucket.acquire()
        if waited:
            with self._lock:
                self.stats.seconds_throttled += waited

    def _match_target(self, host: str) -> Target | None:
        kinds = ("host", "cidr")
        candidates = [t for t in self.scope.targets if t.kind in kinds]

        try:
            ip = ipaddress.ip_address(host)
            resolved: list[ipaddress._BaseAddress] = [ip]
        except ValueError:
            resolved = []
            for t in candidates:
                if t.kind == "host" and t.value == host:
                    resolved = []
                    break
            else:
                try:
                    infos = self._resolver(host, None)
                except OSError:
                    return None
                for info in infos:
                    try:
                        resolved.append(ipaddress.ip_address(info[4][0]))
                    except ValueError:
                        continue
                if not resolved:
                    return None

        for candidate in resolved:
            if _is_metadata_address(candidate):
                return None
            for blocked in ALWAYS_BLOCKED_NETWORKS:
                if candidate.version == blocked.version and candidate in blocked:
                    return None
            for t in candidates:
                if t.kind == "cidr":
                    net = ipaddress.ip_network(t.value, strict=False)
                    if candidate.version == net.version and candidate in net:
                        if candidate.is_global and not (t.allow_public and self.scope.allow_public):
                            return None
                        return t
                elif t.kind == "host":
                    if str(candidate) == str(ipaddress.ip_address(t.value)):
                        if candidate.is_global and not (t.allow_public and self.scope.allow_public):
                            return None
                        return t
        # Exact-name match for targets declared as hostnames was rejected at load
        # time, so there is nothing else to try.
        return None
