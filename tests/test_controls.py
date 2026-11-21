"""Cross-cutting control assertions and CLI behaviour."""

from __future__ import annotations

import json
import os
import unittest

from sentinel.cli import main
from sentinel.engine import coverage_table
from sentinel.selfcheck import render, run_control_checks, run_pipeline_checks

from .support import scope_dict, tempdir, write_scope


class TestCapabilityMatrix(unittest.TestCase):
    def test_every_capability_has_code_and_test_reference(self) -> None:
        for mode in ("local", "network"):
            for cap in coverage_table(mode):
                with self.subTest(cap=cap.id, mode=mode):
                    self.assertTrue(cap.code_ref)
                    self.assertTrue(cap.test_ref)
                    self.assertIn(cap.status, {"implemented", "partial", "blocked"})

    def test_exploitation_is_blocked_and_not_exercised(self) -> None:
        cap = next(c for c in coverage_table("local") if c.id == "CAP-7")
        self.assertEqual(cap.status, "blocked")
        self.assertFalse(cap.exercised_in_run)
        self.assertIn("ADR-002", cap.detail)

    def test_partial_capabilities_say_what_is_missing(self) -> None:
        for cap in coverage_table("local"):
            if cap.status == "partial":
                self.assertRegex(cap.detail.lower(), r"sin|no se|no hay")

    def test_referenced_test_files_exist(self) -> None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for cap in coverage_table("local"):
            for ref in cap.test_ref.split(","):
                path = os.path.join(root, ref.strip())
                self.assertTrue(os.path.exists(path), msg=f"{cap.id}: {path} missing")


class TestCli(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempdir()

    def test_scope_check_ok(self) -> None:
        path = write_scope(self.dir, scope_dict())
        self.assertEqual(main(["scope-check", path]), 0)

    def test_scope_check_rejects_unauthorized(self) -> None:
        path = write_scope(self.dir, scope_dict(
            authorization={"authorized": False, "reference": "x", "approved_by": "y"}))
        self.assertEqual(main(["scope-check", path]), 2)

    def test_scope_check_rejects_metadata(self) -> None:
        path = write_scope(self.dir, scope_dict(
            targets=[{"kind": "host", "value": "169.254.169.254", "ports": [80]}]))
        self.assertEqual(main(["scope-check", path]), 2)

    def test_verify_audit_exit_codes(self) -> None:
        from sentinel.audit import AuditLog

        path = os.path.join(self.dir, "audit.jsonl")
        log = AuditLog(path, "E", "t")
        log.record("a", "info")
        self.assertEqual(main(["verify-audit", path]), 0)

        with open(path, "a", encoding="utf-8") as fh:
            fh.write('{"seq": 2, "hash": "deadbeef"}\n')
        self.assertEqual(main(["verify-audit", path]), 2)

    def test_capabilities_output(self) -> None:
        self.assertEqual(main(["capabilities"]), 0)


class TestSelfCheckSuite(unittest.TestCase):
    """The self-check is itself a deliverable: every control must pass."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.control = run_control_checks()
        cls.pipeline = run_pipeline_checks()
        cls.all = cls.control + cls.pipeline

    def test_control_checks_pass(self) -> None:
        failures = [f"{r.id}: {r.detail}" for r in self.control if not r.passed]
        self.assertEqual(failures, [])

    def test_pipeline_checks_pass(self) -> None:
        failures = [f"{r.id}: {r.detail}" for r in self.pipeline if not r.passed]
        self.assertEqual(failures, [])

    def test_report_renders_pass_lines(self) -> None:
        text = render(self.all)
        self.assertIn("comprobaciones OK", text)
        self.assertNotIn("| FAIL |", text)

    def test_key_controls_are_represented(self) -> None:
        ids = {r.id for r in self.all}
        for expected in ("CTL-1", "CTL-2:169.254.169.254", "CTL-3b", "CTL-6", "CTL-7:password_spray",
                         "CTL-8", "RUN-1", "RUN-3", "RUN-5"):
            self.assertIn(expected, ids)

    def test_evidence_is_serialisable(self) -> None:
        payload = {r.id: r.evidence for r in self.all if r.evidence}
        json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
