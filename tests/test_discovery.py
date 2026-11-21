"""Active discovery against loopback fixtures (real sockets, real TLS)."""

from __future__ import annotations

import os
import unittest

from sentinel.checks import exposure, web
from sentinel.discovery import (
    decode_certificate,
    fingerprint_service,
    parse_banner,
    probe_http,
    scan_host,
    tls_handshake,
)
from sentinel.errors import ScopeViolation
from sentinel.model import Severity, ValidationState

from .support import (
    BannerServer,
    HardenedHandler,
    WeakHandler,
    closed_port,
    make_guard,
    make_self_signed_cert,
    start_http_server,
    tempdir,
)


class TestBannerParsing(unittest.TestCase):
    def test_openssh(self) -> None:
        result = parse_banner("SSH-2.0-OpenSSH_8.2p1 Debian-4")
        self.assertEqual(result["product"], "openssh")
        self.assertEqual(result["version"], "8.2p1")

    def test_apache(self) -> None:
        result = parse_banner("Apache/2.4.49 (Debian)")
        self.assertEqual(result["product"], "apache_httpd")
        self.assertEqual(result["version"], "2.4.49")

    def test_nginx(self) -> None:
        result = parse_banner("nginx/1.18.0")
        self.assertEqual(result["product"], "nginx")
        self.assertEqual(result["version"], "1.18.0")

    def test_garbage(self) -> None:
        self.assertEqual(parse_banner("hello"), {"banner": "hello"})
        self.assertEqual(parse_banner(None), {})


class TestHttpScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = start_http_server(WeakHandler)
        cls.dir = tempdir()
        cls.scope, cls.audit, cls.guard = make_guard(cls.dir, targets=[
            {"kind": "host", "value": "127.0.0.1", "ports": [cls.server.port], "max_tier": 2}])

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_scan_finds_service_and_fingerprint(self) -> None:
        asset = scan_host(self.guard, "127.0.0.1", [self.server.port])
        self.assertEqual(len(asset.services), 1)
        service = asset.services[0]
        self.assertEqual(service.state, "open")
        self.assertEqual(service.product, "apache_httpd")
        self.assertEqual(service.version, "2.4.49")
        self.assertEqual(service.http["status"], 200)
        self.assertTrue(service.evidence)

    def test_scan_evidence_reports_scan_type(self) -> None:
        asset = scan_host(self.guard, "127.0.0.1", [self.server.port])
        data = asset.evidence[0].to_dict()["data"]
        self.assertIn("TCP connect", data["scan_type"])

    def test_advisory_correlation_is_inferred_not_validated(self) -> None:
        asset = scan_host(self.guard, "127.0.0.1", [self.server.port])
        findings = exposure.analyze_service(asset.services[0])
        cve = next(f for f in findings if f.check_id == "ADV-MATCH")
        self.assertEqual(cve.cvss_score, 7.5)
        self.assertEqual(cve.validation_state, ValidationState.INFERRED)
        self.assertIn("CVE-2021-41773", cve.title)
        self.assertTrue(cve.manual_validation_required)
        self.assertIn("No se envió ningún payload", cve.notes)

    def test_header_and_cookie_findings(self) -> None:
        asset = scan_host(self.guard, "127.0.0.1", [self.server.port])
        findings = web.analyze_service_web(asset.services[0])
        check_ids = {f.check_id for f in findings}
        self.assertIn("WEB-HEADER", check_ids)
        self.assertIn("WEB-FRAME", check_ids)
        self.assertIn("WEB-BANNER", check_ids)
        self.assertIn("AUTH-COOKIE-FLAGS", check_ids)
        cookie = next(f for f in findings if f.check_id == "AUTH-COOKIE-FLAGS")
        self.assertIn("sessionid", cookie.title)

    def test_scan_of_port_outside_allowlist_is_refused(self) -> None:
        with self.assertRaises(ScopeViolation):
            scan_host(self.guard, "127.0.0.1", [22])

    def test_probe_is_single_request(self) -> None:
        result = probe_http(make_guard(tempdir(), targets=[
            {"kind": "host", "value": "127.0.0.1", "ports": [self.server.port]}])[2],
            "127.0.0.1", self.server.port, method="HEAD")
        self.assertTrue(result["ok"])
        self.assertEqual(result["body_bytes_read"], 0)

    def test_closed_port_is_reported_not_crashed(self) -> None:
        port = closed_port()
        guard = make_guard(tempdir(), targets=[
            {"kind": "host", "value": "127.0.0.1", "ports": [port]}])[2]
        asset = scan_host(guard, "127.0.0.1", [port])
        self.assertEqual(asset.services, [])
        self.assertEqual(asset.evidence[0].to_dict()["data"]["closed_or_filtered"], [port])


class TestHardenedServer(unittest.TestCase):
    def test_no_missing_header_findings(self) -> None:
        server = start_http_server(HardenedHandler)
        try:
            guard = make_guard(tempdir(), targets=[
                {"kind": "host", "value": "127.0.0.1", "ports": [server.port]}])[2]
            asset = scan_host(guard, "127.0.0.1", [server.port])
            findings = web.analyze_service_web(asset.services[0])
            self.assertEqual([f for f in findings if f.check_id == "WEB-HEADER"], [])
            self.assertEqual([f for f in findings if f.check_id == "AUTH-COOKIE-FLAGS"], [])
        finally:
            server.stop()


class TestBannerService(unittest.TestCase):
    def test_ssh_banner_and_advisory(self) -> None:
        server = BannerServer()
        try:
            guard = make_guard(tempdir(), targets=[
                {"kind": "host", "value": "127.0.0.1", "ports": [server.port]}])[2]
            service = fingerprint_service(guard, "127.0.0.1", server.port)
            self.assertEqual(service.state, "open")
            self.assertEqual(service.product, "openssh")
            self.assertEqual(service.version, "8.2p1")
            findings = exposure.analyze_advisories(service)
            self.assertTrue(any("CVE-2023-38408" in f.title for f in findings))
        finally:
            server.stop()


class TestTls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = tempdir()
        material = make_self_signed_cert(cls.dir)
        if material is None:
            raise unittest.SkipTest("openssl not available")
        cert, key = material
        cls.server = start_http_server(WeakHandler, certfile=cert, keyfile=key)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def test_handshake_records_negotiated_parameters(self) -> None:
        port = self.server.port
        guard = make_guard(tempdir(), targets=[
            {"kind": "host", "value": "127.0.0.1", "ports": [port], "max_tier": 2}])[2]
        result = tls_handshake(guard, "127.0.0.1", port)
        self.assertTrue(result["ok"])
        self.assertIn(result["protocol"], {"TLSv1.2", "TLSv1.3"})
        cert = result["certificate"]
        self.assertTrue(cert["decoded"])
        self.assertTrue(cert["self_signed"])
        self.assertEqual(len(cert["sha256"]), 64)

    def test_self_signed_finding(self) -> None:
        port = self.server.port
        guard = make_guard(tempdir(), targets=[
            {"kind": "host", "value": "127.0.0.1", "ports": [port], "max_tier": 2}])[2]
        tls = tls_handshake(guard, "127.0.0.1", port)
        findings = web.analyze_tls("127.0.0.1", port, tls)
        self.assertIn("TLS-CERT-SELFSIGNED", {f.check_id for f in findings})
        self.assertIn("TLS-VERIFY-METHOD", {f.check_id for f in findings})

    def test_expired_certificate_finding(self) -> None:
        tls = {
            "ok": True,
            "protocol": "TLSv1.2",
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
            "verification": "disabled (observation only)",
            "certificate": {
                "decoded": True,
                "self_signed": False,
                "subject": "CN=example.test",
                "issuer": "CN=Test CA",
                "not_before": "Jan  1 00:00:00 2020 GMT",
                "not_after": "Jan  1 00:00:00 2021 GMT",
                "sha256": "a" * 64,
            },
        }
        findings = web.analyze_tls("example.test", 443, tls)
        expired = next(f for f in findings if f.check_id == "TLS-CERT-EXPIRED")
        self.assertIs(expired.severity, Severity.HIGH)

    def test_decode_certificate_handles_garbage(self) -> None:
        result = decode_certificate(b"not a certificate")
        self.assertFalse(result["decoded"])
        self.assertIn("decode_error", result)


class TestExposureTable(unittest.TestCase):
    def test_docker_api_is_critical(self) -> None:
        from sentinel.model import Service

        service = Service(host="h", port=2375, state="open")
        finding = exposure.analyze_exposure(service)[0]
        self.assertIs(finding.severity, Severity.CRITICAL)
        self.assertIn("no se intentó autenticación", finding.notes.lower())

    def test_unlisted_port_no_finding(self) -> None:
        from sentinel.model import Service

        self.assertEqual(exposure.analyze_exposure(Service(host="h", port=9999)), [])


if __name__ == "__main__":
    unittest.main()
