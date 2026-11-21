"""End-to-end runs: local host assessment and network assessment."""

from __future__ import annotations

import json
import os
import unittest

from sentinel.audit import read_records, verify_chain
from sentinel.engine import assess_local, assess_network
from sentinel.errors import SentinelError
from sentinel.report import write_reports

from tests.support import WeakHandler, scope_dict, start_http_server, tempdir, write_scope


class TestLocalAssessment(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = tempdir()
        cls.scope_path = write_scope(cls.dir, scope_dict(
            engagement_id="ENG-LOCAL",
            targets=[{"kind": "local_host", "value": "self", "ports": [65000], "max_tier": 1}],
        ))
        cls.out = os.path.join(cls.dir, "out")
        cls.result = assess_local(cls.scope_path, cls.out)
        cls.report_paths = write_reports(cls.result.assessment, cls.out)

    def test_produces_findings_and_assets(self) -> None:
        self.assertGreater(len(self.result.assessment.findings), 0)
        self.assertEqual(len(self.result.assessment.assets), 1)
        self.assertEqual(self.result.assessment.assets[0].role, "local_host")

    def test_audit_chain_verifies(self) -> None:
        self.assertTrue(self.result.assessment.audit_chain["ok"])
        result = verify_chain(self.result.audit_path)
        self.assertTrue(result["ok"])
        self.assertGreater(result["records"], 5)

    def test_audit_contains_no_network_action(self) -> None:
        actions = {record["action"] for record in read_records(self.result.audit_path)}
        self.assertFalse(any(a.startswith(("tcp_connect", "http_probe", "tls_handshake")) for a in actions))

    def test_coverage_is_attached_and_truthful(self) -> None:
        coverage = {c.id: c for c in self.result.assessment.coverage}
        self.assertEqual(coverage["CAP-1"].status, "implemented")
        self.assertEqual(coverage["CAP-4"].status, "partial")
        self.assertEqual(coverage["CAP-7"].status, "blocked")
        self.assertFalse(coverage["CAP-7"].exercised_in_run)
        self.assertIn("no se ejecutó", coverage["CAP-1"].detail)

    def test_skipped_documents_what_was_not_run(self) -> None:
        reasons = json.dumps(self.result.assessment.skipped)
        self.assertIn("CAP-1.network", reasons)

    def test_no_finding_claims_exploitation(self) -> None:
        for finding in self.result.assessment.findings:
            self.assertNotIn(finding.validation_state.value, {"exploited", "verified_exploit"})
            if finding.confidence.value == "hypothesis":
                self.assertTrue(finding.manual_validation_required, msg=finding.check_id)

    def test_reports_written_and_mention_limits(self) -> None:
        for path in self.report_paths.values():
            self.assertTrue(os.path.exists(path))
        with open(self.report_paths["markdown"], encoding="utf-8") as fh:
            markdown = fh.read()
        self.assertIn("Capacidades no implementadas", markdown)
        self.assertIn("No se ejecutaron binarios SUID", markdown)

    def test_engagement_metadata_in_report(self) -> None:
        with open(self.report_paths["json"], encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertEqual(payload["engagement_id"], "ENG-LOCAL")
        self.assertEqual(payload["scope"]["authorization_ref"], "TEST-AUTH-1")

    def test_local_mode_cannot_be_run_without_local_target(self) -> None:
        path = write_scope(self.dir, scope_dict(targets=[
            {"kind": "host", "value": "127.0.0.1", "ports": [18080]}]), name="no-local.json")
        with self.assertRaises(SentinelError):
            assess_local(path, os.path.join(self.dir, "out2"))


class TestNetworkAssessment(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = start_http_server(WeakHandler)
        cls.dir = tempdir()
        cls.scope_path = write_scope(cls.dir, scope_dict(
            engagement_id="ENG-NET",
            targets=[{"kind": "host", "value": "127.0.0.1", "ports": [cls.server.port], "max_tier": 2}],
        ))
        cls.out = os.path.join(cls.dir, "out")
        cls.result = assess_network(cls.scope_path, cls.out)
        cls.report_paths = write_reports(cls.result.assessment, cls.out)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_discovers_service_and_findings(self) -> None:
        asset = self.result.assessment.assets[0]
        self.assertEqual(len(asset.services), 1)
        check_ids = {f.check_id for f in self.result.assessment.findings}
        self.assertIn("ADV-MATCH", check_ids)
        self.assertIn("WEB-HEADER", check_ids)
        self.assertIn("AUTH-COOKIE-FLAGS", check_ids)

    def test_advisory_finding_is_inferred(self) -> None:
        finding = next(f for f in self.result.assessment.findings if f.check_id == "ADV-MATCH")
        self.assertEqual(finding.confidence.value, "inferred")
        self.assertEqual(finding.validation_state.value, "inferred")

    def test_audit_records_the_network_actions(self) -> None:
        actions = [r["action"] for r in read_records(self.result.audit_path)]
        self.assertTrue(any(a.startswith("tcp_connect") for a in actions))
        self.assertTrue(all(r["outcome"] in {"allowed", "denied", "info"} for r in read_records(self.result.audit_path)))

    def test_scope_ports_are_the_only_ones_contacted(self) -> None:
        records = [r for r in read_records(self.result.audit_path) if r["action"].startswith("tcp_connect")]
        self.assertTrue(records)
        for record in records:
            self.assertTrue(record["target"].endswith(f":{self.server.port}"))

    def test_report_states_auth_not_attempted(self) -> None:
        with open(self.report_paths["markdown"], encoding="utf-8") as fh:
            markdown = fh.read()
        self.assertIn("auth-probe", markdown)


if __name__ == "__main__":
    unittest.main()
