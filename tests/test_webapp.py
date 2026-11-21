"""Web interface integration tests against real Sentinel code and loopback HTTP."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request

from sentinel.audit import AuditLog, read_records, verify_chain
from sentinel.errors import ScopeError
from sentinel.model import Assessment
from sentinel.scope import Scope
from sentinel.webapp import ScanContext, SentinelWeb, create_server, main
from tests.support import WeakHandler, scope_dict, start_http_server, tempdir


class DelayedHandler(WeakHandler):
    def do_HEAD(self) -> None:  # noqa: N802
        time.sleep(0.25)
        self._respond(False)


class TestWebBackend(unittest.TestCase):
    def setUp(self) -> None:
        self.http = start_http_server(WeakHandler)
        self.data_dir = tempdir()
        self.app = SentinelWeb(self.data_dir, timeout=1.5)
        self.server = create_server("127.0.0.1", 0, self.app)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.http.stop()

    def get(self, path: str):
        with urllib.request.urlopen(self.base + path, timeout=5) as response:
            return response.status, response.headers, response.read()

    def post(self, path: str, payload: dict, headers: dict | None = None):
        data = json.dumps(payload).encode()
        request = urllib.request.Request(self.base + path, data=data, method="POST",
                                         headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.headers, exc.read()

    def authorized_scope(self) -> dict:
        return scope_dict(
            engagement_id="../../WEB-E2E",  # hostile filename characters must not escape the run directory
            targets=[{"kind": "host", "value": "127.0.0.1", "ports": [self.http.port], "max_tier": 2}],
            max_requests=20,
        )

    def test_web_assets_and_health_are_served(self) -> None:
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        page = body.decode()
        self.assertIn('id="scan-button"', page)
        self.assertIn('id="analyze-button"', page)
        self.assertIn('id="report-button"', page)
        self.assertEqual(page.count('class="primary-action'), 3)
        self.assertEqual(page.count("<button "), 3)
        self.assertIn("Content-Security-Policy", headers)
        script = self.get("/app.js")[2].decode()
        self.assertIn("/api/scan", script)
        self.assertIn("/api/analyze", script)
        self.assertIn("/api/report", script)
        health = json.loads(self.get("/api/health")[2])
        self.assertTrue(health["ok"])
        state = json.loads(self.get("/api/state")[2])
        self.assertEqual(state["operations"], [])

    def test_invalid_or_unauthorized_scope_is_rejected_before_scan(self) -> None:
        payload = self.authorized_scope()
        payload["authorization"]["authorized"] = False
        status, _, response_body = self.post("/api/scan", {"scope": payload})
        self.assertEqual(status, 400)
        self.assertIn("authorisation", json.loads(response_body)["error"])
        self.assertEqual(self.app.state()["operations"], [])

    def test_cross_origin_post_is_rejected(self) -> None:
        status, _, _ = self.post("/api/scan", {"scope": self.authorized_scope()},
                                 {"Origin": "https://attacker.invalid"})
        self.assertEqual(status, 403)
        self.assertEqual(self.app.state()["operations"], [])

    def test_scan_analyze_and_report_call_real_backend_and_download_evidence(self) -> None:
        # ESCANEAR: real TCP connection to an authorized test HTTP service.
        status, _, response_body = self.post("/api/scan", {"scope": self.authorized_scope()})
        self.assertEqual(status, 202)
        operation_id = json.loads(response_body)["id"]
        deadline = time.time() + 12
        operation = None
        while time.time() < deadline:
            operation = json.loads(self.get(f"/api/operations/{operation_id}")[2])
            if operation["status"] not in {"queued", "running"}:
                break
            time.sleep(0.04)
        self.assertIsNotNone(operation)
        self.assertEqual(operation["status"], "completed", operation)
        scan = operation["result"]
        self.assertEqual(scan["open_services"], 1)
        self.assertEqual(scan["assets"][0]["services"][0]["http"]["status"], 200)
        self.assertIn("Apache", scan["assets"][0]["services"][0]["banner"])
        self.assertTrue(scan["audit_chain"]["ok"])

        # ANALIZAR: real checks/exposure engine over captured Service data; no extra network calls.
        audit_file = os.path.join(self.data_dir, scan["scan_id"], scan["audit_path"])
        network_actions_before = [record["action"] for record in read_records(audit_file)
                                  if record["action"].startswith(("tcp_connect", "http_probe", "tls_handshake"))]
        status, _, response_body = self.post("/api/analyze", {"scan_id": scan["scan_id"]})
        self.assertEqual(status, 200)
        analysis = json.loads(response_body)
        check_ids = {finding["check_id"] for finding in analysis["findings"]}
        self.assertIn("WEB-HEADER", check_ids)
        self.assertIn("WEB-BANNER", check_ids)
        self.assertIn("ADV-MATCH", check_ids)
        self.assertEqual(analysis["service_count"], 1)
        self.assertTrue(analysis["audit_chain"]["ok"])
        network_actions_after = [record["action"] for record in read_records(audit_file)
                                 if record["action"].startswith(("tcp_connect", "http_probe", "tls_handshake"))]
        self.assertEqual(network_actions_after, network_actions_before)

        # INFORME: report.write_reports creates actual Markdown/HTML/JSON; API serves all formats.
        status, _, response_body = self.post("/api/report", {"scan_id": scan["scan_id"]})
        self.assertEqual(status, 200)
        report = json.loads(response_body)
        self.assertEqual(report["findings"], len(analysis["findings"]))
        self.assertTrue(report["audit_chain"]["ok"])
        for kind in ("markdown", "html", "json"):
            status, headers, body = self.get(f"/api/reports/{scan['scan_id']}/{kind}")
            self.assertEqual(status, 200)
            self.assertGreater(len(body), 1000)
            self.assertIn("attachment", headers.get("Content-Disposition", ""))
        html = self.get(f"/api/reports/{scan['scan_id']}/view")[2].decode()
        self.assertIn("WEB-HEADER", html)
        self.assertTrue(verify_chain(audit_file)["ok"])
        run_directory = os.path.realpath(os.path.join(self.data_dir, scan["scan_id"]))
        report_file = os.path.realpath(os.path.join(run_directory, report["report_paths"]["json"]))
        audit_file = os.path.realpath(audit_file)
        self.assertEqual(os.path.dirname(report_file), run_directory)
        self.assertEqual(os.path.dirname(audit_file), run_directory)
        self.assertTrue(os.path.isfile(report_file))

        with self.assertRaises(ScopeError):
            self.app.analyze(scan["scan_id"])

    def test_public_target_without_double_opt_in_is_rejected_before_scan(self) -> None:
        payload = self.authorized_scope()
        payload["targets"][0]["value"] = "8.8.8.8"
        status, _, _ = self.post("/api/scan", {"scope": payload})
        self.assertEqual(status, 400)  # public targets require double opt-in in the core scope parser
        self.assertFalse(self.app.operations)

    def test_tampered_audit_chain_blocks_analysis(self) -> None:
        scope = Scope.from_dict(self.authorized_scope())
        run_dir = os.path.join(self.data_dir, "tampered")
        os.makedirs(run_dir)
        audit_path = os.path.join(run_dir, "audit.jsonl")
        audit = AuditLog(audit_path, scope.engagement_id, scope.operator, run_id="tampered")
        audit.record("run_start", "info")
        assessment = Assessment(scope.engagement_id, scope.operator, "network", scope.summary(),
                                run_id="tampered", audit_path=audit_path)
        context = ScanContext("tampered", scope, assessment, Path(run_dir))
        self.app.scans[context.id] = context
        with open(audit_path, "a", encoding="utf-8") as stream:
            stream.write('{"tampered": true}\n')
        with self.assertRaisesRegex(ScopeError, "cadena de auditoría inválida"):
            self.app.analyze(context.id)

    def test_scan_can_be_cancelled_through_the_real_api(self) -> None:
        slow_server = start_http_server(DelayedHandler)
        try:
            scope = scope_dict(targets=[{
                "kind": "host", "value": "127.0.0.1", "ports": [slow_server.port], "max_tier": 2,
            }], max_requests=20)
            status, _, response_body = self.post("/api/scan", {"scope": scope})
            self.assertEqual(status, 202)
            operation_id = json.loads(response_body)["id"]
            status, _, _ = self.post(f"/api/cancel/{operation_id}", {})
            self.assertEqual(status, 202)
            deadline = time.time() + 10
            operation = None
            while time.time() < deadline:
                operation = json.loads(self.get(f"/api/operations/{operation_id}")[2])
                if operation["status"] not in {"queued", "running"}:
                    break
                time.sleep(0.04)
            self.assertIsNotNone(operation)
            self.assertEqual(operation["status"], "cancelled", operation)
            self.assertTrue(operation["result"]["audit_chain"]["ok"])
        finally:
            slow_server.stop()

    def test_analysis_cannot_precede_scan_and_report_cannot_precede_analysis(self) -> None:
        with self.assertRaises(ScopeError, msg="analysis must reject an unknown scan"):
            self.app.analyze("unknown")
        with self.assertRaises(ScopeError, msg="report must reject an unknown scan"):
            self.app.create_report("unknown")


class TestWebLimits(unittest.TestCase):
    def test_server_defaults_to_loopback(self) -> None:
        server = create_server(port=0)
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
        finally:
            server.server_close()

    def test_explicit_non_loopback_host_emits_security_warning(self) -> None:
        server = Mock()
        server.serve_forever.side_effect = KeyboardInterrupt
        with patch("sentinel.webapp.create_server", return_value=server), \
             patch("sys.argv", ["sentinel-web", "--host", "0.0.0.0"]), \
             patch("sys.stderr", new_callable=io.StringIO) as stderr, \
             patch("sys.stdout", new_callable=io.StringIO):
            main()
        self.assertIn("no incluye autenticación ni TLS", stderr.getvalue())
        server.server_close.assert_called_once()

    def test_metadata_cidr_rejected_before_any_connection(self) -> None:
        app = SentinelWeb(tempdir())
        scope = scope_dict(targets=[{
            "kind": "cidr", "value": "fd00:ec2::/112", "ports": [80], "max_tier": 2,
        }])
        with patch("sentinel.discovery.socket.create_connection") as connect:
            with self.assertRaisesRegex(ScopeError, "metadata"):
                app.start_scan(scope)
            connect.assert_not_called()
        self.assertEqual(app.operations, {})
        self.assertEqual(app.scans, {})

    def test_cartesian_scan_limit_rejected_before_expansion_or_network(self) -> None:
        app = SentinelWeb(tempdir())
        scope = scope_dict(targets=[{
            "kind": "cidr", "value": "10.0.0.0/8", "ports": ["80-82"], "max_tier": 2,
        }])
        with self.assertRaisesRegex(ScopeError, "512"):
            app.start_scan(scope)
        self.assertEqual(app.operations, {})
        self.assertEqual(app.scans, {})


if __name__ == "__main__":
    unittest.main()
