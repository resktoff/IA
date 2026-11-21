"""Scope, authorisation and guard controls."""

from __future__ import annotations

import json
import os
import threading
import unittest

from sentinel.audit import AuditLog, read_records
from sentinel.errors import (
    AuthorizationError,
    BudgetExceeded,
    CapabilityBlocked,
    ScopeError,
    ScopeViolation,
)
from sentinel.model import Tier
from sentinel.scope import PortSet, Scope, ScopeGuard, Target, TokenBucket

from .support import make_guard, scope_dict, tempdir


class TestScopeLoading(unittest.TestCase):
    def test_requires_explicit_authorization(self) -> None:
        with self.assertRaises(AuthorizationError):
            Scope.from_dict(scope_dict(authorization={"authorized": False, "reference": "x", "approved_by": "y"}))

    def test_requires_authorization_reference(self) -> None:
        with self.assertRaises(AuthorizationError):
            Scope.from_dict(scope_dict(authorization={"authorized": True, "reference": " ", "approved_by": "y"}))

    def test_requires_approver(self) -> None:
        with self.assertRaises(AuthorizationError):
            Scope.from_dict(scope_dict(authorization={"authorized": True, "reference": "T-1", "approved_by": ""}))

    def test_expired_engagement_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            Scope.from_dict(scope_dict(valid_from="2020-01-01T00:00:00Z", expires_at="2020-02-01T00:00:00Z"))

    def test_future_engagement_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            Scope.from_dict(scope_dict(valid_from="2998-01-01T00:00:00Z", expires_at="2999-01-01T00:00:00Z"))

    def test_empty_targets_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            Scope.from_dict(scope_dict(targets=[]))

    def test_unsupported_schema_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            Scope.from_dict(scope_dict(schema="sentinel.scope/0"))

    def test_metadata_endpoint_always_blocked(self) -> None:
        with self.assertRaises(ScopeError) as ctx:
            Scope.from_dict(scope_dict(targets=[{"kind": "host", "value": "169.254.169.254", "ports": [80]}]))
        self.assertIn("169.254", str(ctx.exception))

    def test_ipv6_metadata_inside_cidr_is_blocked(self) -> None:
        for cidr in (
            "fd00:ec2::/112",
            "fd00:ec2::200/120",
            "::ffff:169.254.169.0/120",
        ):
            with self.subTest(cidr=cidr), self.assertRaisesRegex(ScopeError, "metadata"):
                Scope.from_dict(scope_dict(targets=[{
                    "kind": "cidr", "value": cidr, "ports": [80], "max_tier": 2,
                }]))

    def test_multicast_blocked(self) -> None:
        with self.assertRaises(ScopeError):
            Scope.from_dict(scope_dict(targets=[{"kind": "host", "value": "224.0.0.1", "ports": [80]}]))

    def test_public_address_requires_double_opt_in(self) -> None:
        with self.assertRaises(ScopeError):
            Scope.from_dict(scope_dict(targets=[{"kind": "host", "value": "8.8.8.8", "ports": [53]}]))

        # opt-in on the target only is not enough
        with self.assertRaises(ScopeError):
            Scope.from_dict(scope_dict(targets=[
                {"kind": "host", "value": "8.8.8.8", "ports": [53], "allow_public": True}]))

        # both opt-ins are required and then it loads
        scope = Scope.from_dict(scope_dict(
            allow_public=True,
            targets=[{"kind": "host", "value": "8.8.8.8", "ports": [53], "allow_public": True}],
        ))
        self.assertEqual(scope.targets[0].value, "8.8.8.8")

    def test_tier_three_in_scope_is_downgraded(self) -> None:
        scope = Scope.from_dict(scope_dict(targets=[
            {"kind": "host", "value": "127.0.0.1", "ports": [18080], "max_tier": 3}]))
        self.assertEqual(scope.max_tier, 2)

    def test_port_ranges(self) -> None:
        ports = PortSet(["22", "8000-8002", 443])
        self.assertEqual(list(ports), [22, 443, 8000, 8001, 8002])
        self.assertIn(8001, ports)
        self.assertEqual(ports.render(), "22,443,8000-8002")

    def test_hostname_target_rejected(self) -> None:
        with self.assertRaises(ScopeError):
            Scope.from_dict(scope_dict(targets=[{"kind": "host", "value": "example.com", "ports": [80]}]))


class TestGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempdir()

    def test_allows_declared_host_and_port(self) -> None:
        _, audit, guard = make_guard(self.dir)
        guard.check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)
        self.assertEqual(guard.stats.allowed, 1)
        records = list(read_records(audit.path))
        self.assertEqual(records[-1]["outcome"], "allowed")

    def test_denies_undeclared_port_and_logs(self) -> None:
        _, audit, guard = make_guard(self.dir)
        with self.assertRaises(ScopeViolation):
            guard.check("tcp_connect", "127.0.0.1", 22, Tier.VALIDATE)
        records = list(read_records(audit.path))
        denied = [r for r in records if r["outcome"] == "denied"]
        self.assertEqual(len(denied), 1)
        self.assertIn("port 22", denied[0]["detail"]["reason"])
        self.assertEqual(guard.stats.denied, 1)

    def test_denies_host_outside_allowlist(self) -> None:
        _, _, guard = make_guard(self.dir)
        with self.assertRaises(ScopeViolation):
            guard.check("tcp_connect", "10.0.0.5", 18080, Tier.VALIDATE)

    def test_denies_when_tier_above_target(self) -> None:
        _, _, guard = make_guard(self.dir, targets=[
            {"kind": "host", "value": "127.0.0.1", "ports": [18080], "max_tier": 1}])
        with self.assertRaises(ScopeViolation):
            guard.check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)

    def test_exploitation_always_blocked(self) -> None:
        _, _, guard = make_guard(self.dir)
        with self.assertRaises(CapabilityBlocked):
            guard.check("deliver_exploit", "127.0.0.1", 18080, Tier.EXPLOIT)
        with self.assertRaises(CapabilityBlocked):
            guard.check_local("execute_command", Tier.EXPLOIT)

    def test_killswitch_blocks_everything(self) -> None:
        path = os.path.join(self.dir, "STOP")
        _, _, guard = make_guard(self.dir, killswitch_path=path)
        guard.check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)  # works before the switch
        open(path, "w").close()
        with self.assertRaises(BudgetExceeded):
            guard.check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)
        self.assertTrue(guard.stats.killswitch_tripped)

    def test_request_budget_is_hard(self) -> None:
        _, audit, guard = make_guard(self.dir, max_requests=2)
        guard.check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)
        guard.check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)
        with self.assertRaises(BudgetExceeded):
            guard.check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)
        denied = [r for r in read_records(audit.path) if r["outcome"] == "denied"]
        self.assertTrue(any("budget" in r["detail"]["reason"] for r in denied))

    def test_request_budget_max_one_is_atomic_under_concurrency(self) -> None:
        scope = Scope.from_dict(scope_dict(max_requests=1))
        audit = AuditLog(os.path.join(self.dir, "concurrent-audit.jsonl"),
                         scope.engagement_id, scope.operator)
        entered_bucket = threading.Event()
        release_bucket = threading.Event()

        class PausingBucket:
            def acquire(self) -> float:
                entered_bucket.set()
                if not release_bucket.wait(timeout=3):
                    raise AssertionError("test did not release the bucket")
                return 0.0

        guard = ScopeGuard(scope, audit, bucket=PausingBucket())
        outcomes: list[str] = []

        def first_check() -> None:
            try:
                guard.check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)
                outcomes.append("allowed")
            except Exception as exc:  # captured for assertion on the test thread
                outcomes.append(type(exc).__name__)

        worker = threading.Thread(target=first_check)
        worker.start()
        self.assertTrue(entered_bucket.wait(timeout=3), "first check did not reach the bucket")
        try:
            with self.assertRaises(BudgetExceeded):
                guard.check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)
        finally:
            release_bucket.set()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes, ["allowed"])
        self.assertEqual(guard.stats.network_ops, 1)
        self.assertEqual(guard.stats.allowed, 1)

    def test_scopeguard_blocks_metadata_even_if_scope_is_injected(self) -> None:
        scope, audit, _ = make_guard(self.dir)
        cases = (
            ("fd00:ec2::/112", "fd00:ec2::254"),
            ("::ffff:169.254.169.0/120", "::ffff:169.254.169.254"),
        )
        for cidr, endpoint in cases:
            with self.subTest(endpoint=endpoint):
                scope.targets = [Target("cidr", cidr, PortSet([80]), 2)]
                guard = ScopeGuard(scope, audit)
                with self.assertRaises(ScopeViolation):
                    guard.check("tcp_connect", endpoint, 80, Tier.VALIDATE)
                self.assertEqual(guard.stats.network_ops, 0)

    def test_try_check_returns_false(self) -> None:
        _, _, guard = make_guard(self.dir)
        ok, reason = guard.try_check("tcp_connect", "127.0.0.1", 22, Tier.VALIDATE)
        self.assertFalse(ok)
        self.assertIn("port 22", reason or "")
        ok, reason = guard.try_check("tcp_connect", "127.0.0.1", 18080, Tier.VALIDATE)
        self.assertTrue(ok)
        self.assertIsNone(reason)

    def test_cidr_target_matches_member(self) -> None:
        _, _, guard = make_guard(self.dir, targets=[
            {"kind": "cidr", "value": "127.0.0.0/30", "ports": [18080], "max_tier": 2}])
        guard.check("tcp_connect", "127.0.0.2", 18080, Tier.VALIDATE)
        with self.assertRaises(ScopeViolation):
            guard.check("tcp_connect", "127.0.0.9", 18080, Tier.VALIDATE)

    def test_local_target_required_for_local_actions(self) -> None:
        _, _, guard = make_guard(self.dir)
        with self.assertRaises(ScopeViolation):
            guard.check_local("collect:identity")

        _, _, guard_local = make_guard(self.dir, targets=[
            {"kind": "local_host", "value": "self", "ports": [65000], "max_tier": 1}])
        guard_local.check_local("collect:identity")
        self.assertEqual(guard_local.stats.allowed, 1)


class TestTokenBucket(unittest.TestCase):
    def test_bucket_consumes_and_refills(self) -> None:
        now = [0.0]
        slept = []

        def clock() -> float:
            return now[0]

        def sleeper(seconds: float) -> None:
            slept.append(seconds)
            now[0] += seconds

        bucket = TokenBucket(rate=2.0, burst=2, clock=clock, sleeper=sleeper)
        self.assertEqual(bucket.acquire(), 0.0)
        self.assertEqual(bucket.acquire(), 0.0)
        waited = bucket.acquire()
        self.assertGreater(waited, 0)
        self.assertAlmostEqual(waited, 0.5, places=2)
        self.assertTrue(slept)


class TestScopeSummary(unittest.TestCase):
    def test_summary_is_serialisable(self) -> None:
        scope = Scope.from_dict(scope_dict())
        json.dumps(scope.summary())


if __name__ == "__main__":
    unittest.main()
