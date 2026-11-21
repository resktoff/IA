"""Report rendering: honesty, structure, self-containment and redaction."""

from __future__ import annotations

import json
import os
import unittest

from sentinel.engine import coverage_table
from sentinel.model import (
    Assessment,
    Confidence,
    Evidence,
    Finding,
    Severity,
    ValidationState,
)
from sentinel.report import build_html, build_json, build_markdown, write_reports

from .support import tempdir


def sample_assessment() -> Assessment:
    assessment = Assessment(
        engagement_id="ENG-TEST",
        operator="tester",
        target_mode="network",
        scope_summary={
            "engagement_id": "ENG-TEST",
            "client": "ACME",
            "operator": "tester",
            "authorization_ref": "AUTH-42",
            "approved_by": "CISO",
            "valid_from": "2026-01-01T00:00:00+00:00",
            "expires_at": "2026-12-31T00:00:00+00:00",
            "max_tier": 2,
            "max_requests": 100,
            "rate_per_second": 5.0,
            "killswitch_path": "STOP",
            "scope_file": "scope.json",
            "targets": [{"kind": "host", "value": "10.0.0.5", "ports": "443", "max_tier": 2}],
        },
    )
    assessment.coverage = coverage_table("network")
    assessment.findings = [
        Finding(
            check_id="ADV-MATCH",
            title="CVE-2021-41773: apache_httpd 2.4.49 figura como afectado",
            category="vulnerability",
            asset="10.0.0.5",
            port=443,
            severity=Severity.HIGH,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_score=7.5,
            confidence=Confidence.INFERRED,
            validation_state=ValidationState.INFERRED,
            impact="Traversal de rutas.",
            remediation="Actualizar a 2.4.51.",
            manual_validation_required=True,
            evidence=[Evidence(kind="advisory_match", asset="10.0.0.5", summary="match",
                               data={"password": "hunter2", "note": "visible"}, source="test")],
        ),
        Finding(
            check_id="WEB-HEADER",
            title="Content-Security-Policy ausente",
            category="web_configuration",
            asset="10.0.0.5",
            port=443,
            severity=Severity.MEDIUM,
            impact="Sin CSP.",
            remediation="Añadir CSP.",
            confidence=Confidence.CONFIRMED,
            validation_state=ValidationState.OBSERVED,
            evidence=[Evidence(kind="http_headers", asset="10.0.0.5", summary="headers",
                               data={"Server": "nginx/1.18.0"}, source="test")],
        ),
    ]
    assessment.finished_at = "2026-01-02T00:00:00+00:00"
    assessment.audit_path = "/tmp/audit.jsonl"
    assessment.audit_chain = {"ok": True, "records": 12, "head": "f" * 64}
    assessment.skipped = [{"check": "auth-probe", "reason": "no se enviaron credenciales"}]
    return assessment


class TestMarkdown(unittest.TestCase):
    def setUp(self) -> None:
        self.md = build_markdown(sample_assessment())

    def test_has_required_sections(self) -> None:
        for heading in ("Resumen ejecutivo", "Autorización, alcance y controles", "Metodología y límites",
                        "Cobertura de capacidades", "Hallazgos", "Capacidades no implementadas",
                        "Registro de decisiones de seguridad", "Anexos"):
            self.assertIn(heading, self.md)

    def test_lists_blocked_capability(self) -> None:
        self.assertIn("CAP-7", self.md)
        self.assertIn("blocked", self.md)
        self.assertIn("ADR-002", self.md)

    def test_marks_inferred_findings(self) -> None:
        self.assertIn("inferido", self.md)
        self.assertIn("validación manual requerida", self.md.lower())

    def test_marks_estimated_vectors(self) -> None:
        self.assertIn("(estimado)", self.md)

    def test_evidence_digest_present(self) -> None:
        finding = sample_assessment().findings[0]
        self.assertIn(finding.evidence[0].digest()[:32], self.md)

    def test_redacts_secrets(self) -> None:
        self.assertNotIn("hunter2", self.md)

    def test_explicitly_states_what_was_not_done(self) -> None:
        self.assertIn("No se envió ningún exploit", self.md)
        self.assertIn("No se enviaron credenciales", self.md)

    def test_counts_match_findings(self) -> None:
        self.assertIn("2 hallazgos", self.md)


class TestHtml(unittest.TestCase):
    def setUp(self) -> None:
        self.html = build_html(sample_assessment())

    def test_is_self_contained(self) -> None:
        self.assertNotIn("<script", self.html)
        self.assertNotIn('src="http', self.html)
        self.assertNotIn('href="http', self.html)
        self.assertIn("<style>", self.html)

    def test_escapes_html_in_titles(self) -> None:
        assessment = sample_assessment()
        assessment.findings[0].title = "<script>alert(1)</script>"
        html = build_html(assessment)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_contains_severity_badges_and_coverage(self) -> None:
        self.assertIn("sev-high", self.html)
        self.assertIn("CAP-7", self.html)
        self.assertIn("Capacidades no implementadas", self.html)

    def test_redacts_secrets(self) -> None:
        self.assertNotIn("hunter2", self.html)


class TestJson(unittest.TestCase):
    def test_schema_and_structure(self) -> None:
        payload = build_json(sample_assessment())
        self.assertEqual(payload["schema"], "sentinel.assessment/1")
        self.assertIn("findings", payload)
        self.assertIn("coverage", payload)
        self.assertEqual(payload["findings"][0]["confidence"], "inferred")
        self.assertIn("not_implemented", payload["report"])
        self.assertTrue(all("adr" in item for item in payload["report"]["not_implemented"]))

    def test_redacted(self) -> None:
        payload = build_json(sample_assessment())
        serialised = json.dumps(payload)
        self.assertNotIn("hunter2", serialised)
        self.assertIn("[REDACTED]", serialised)

    def test_finding_ids_are_stable(self) -> None:
        first = build_json(sample_assessment())["findings"]
        second = build_json(sample_assessment())["findings"]
        self.assertEqual([f["id"] for f in first], [f["id"] for f in second])

    def test_findings_sorted_by_score(self) -> None:
        assessment = sample_assessment()
        assessment.findings.reverse()
        payload = build_json(assessment)
        scores = [f["cvss_score"] or 0 for f in payload["findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestRedactionGranularity(unittest.TestCase):
    def test_cookie_value_removed_but_flags_kept(self) -> None:
        from sentinel.redact import redact_obj

        result = redact_obj({"set_cookie": "sessionid=SECRETVALUE123; Secure; HttpOnly; SameSite=Lax"})
        self.assertNotIn("SECRETVALUE123", result["set_cookie"])
        self.assertIn("sessionid=[REDACTED]", result["set_cookie"])
        self.assertIn("HttpOnly", result["set_cookie"])

    def test_authorization_reference_is_preserved(self) -> None:
        from sentinel.redact import redact_obj

        result = redact_obj({"authorization_ref": "AUTH-42", "approved_by": "CISO"})
        self.assertEqual(result["authorization_ref"], "AUTH-42")


class TestWriteReports(unittest.TestCase):
    def test_writes_three_artefacts(self) -> None:
        directory = tempdir()
        paths = write_reports(sample_assessment(), directory, basename="r")
        self.assertEqual(set(paths), {"markdown", "html", "json"})
        for path in paths.values():
            self.assertTrue(os.path.getsize(path) > 500)
        with open(paths["json"], encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["schema"], "sentinel.assessment/1")


if __name__ == "__main__":
    unittest.main()
