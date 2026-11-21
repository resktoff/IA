"""HTTP/TLS configuration checks as pure functions over captured observations."""

from __future__ import annotations

import unittest

from sentinel.checks import web
from sentinel.model import Severity, ValidationState

HARDENED_HEADERS = {
    "Content-Type": "text/html",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
}


def probe(headers: dict[str, str], tls: bool = True, status: int = 200) -> dict:
    return {"ok": True, "status": status, "tls": tls, "headers": headers, "set_cookies": []}


def ids(findings) -> set[str]:
    return {f.check_id for f in findings}


class TestHttpHeaders(unittest.TestCase):
    def test_hardened_response_has_no_findings(self) -> None:
        self.assertEqual(web.analyze_http("h", 443, probe(HARDENED_HEADERS)), [])

    def test_missing_headers_reported_individually(self) -> None:
        findings = web.analyze_http("h", 443, probe({"Content-Type": "text/html"}))
        titles = " ".join(f.title for f in findings)
        for expected in ("HSTS", "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy",
                         "clickjacking"):
            self.assertIn(expected, titles)

    def test_hsts_only_checked_over_tls(self) -> None:
        findings = web.analyze_http("h", 80, probe({"Content-Type": "text/html"}, tls=False))
        self.assertFalse(any("HSTS" in f.title for f in findings))

    def test_csp_frame_ancestors_satisfies_framing(self) -> None:
        headers = dict(HARDENED_HEADERS)
        del headers["X-Frame-Options"]
        self.assertNotIn("WEB-FRAME", ids(web.analyze_http("h", 443, probe(headers))))

    def test_banner_disclosure(self) -> None:
        headers = dict(HARDENED_HEADERS)
        headers["Server"] = "nginx/1.18.0"
        headers["X-Powered-By"] = "PHP/7.4.3"
        finding = next(f for f in web.analyze_http("h", 443, probe(headers)) if f.check_id == "WEB-BANNER")
        self.assertIn("nginx/1.18.0", finding.impact + str(finding.evidence[0].to_dict()))

    def test_plaintext_service(self) -> None:
        findings = web.analyze_http("h", 8080, probe(HARDENED_HEADERS, tls=False))
        self.assertIn("WEB-PLAINTEXT", ids(findings))

    def test_failed_probe_yields_nothing(self) -> None:
        self.assertEqual(web.analyze_http("h", 443, {"ok": False, "error": "timeout"}), [])

    def test_cookies_are_delegated_to_auth(self) -> None:
        data = probe(HARDENED_HEADERS)
        data["set_cookies"] = ["sid=abc123; Path=/"]
        findings = web.analyze_http("h", 443, data)
        self.assertIn("AUTH-COOKIE-FLAGS", ids(findings))


class TestTlsChecks(unittest.TestCase):
    def tls(self, **overrides) -> dict:
        base = {
            "ok": True,
            "protocol": "TLSv1.2",
            "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "verification": "disabled (observation only)",
            "certificate": {
                "decoded": True, "self_signed": False,
                "subject": "CN=example.test", "issuer": "CN=Real CA",
                "not_before": "Jan  1 00:00:00 2026 GMT", "not_after": "Jan  1 00:00:00 2027 GMT",
                "sha256": "b" * 64,
            },
        }
        base.update(overrides)
        return base

    def test_obsolete_protocol_is_high(self) -> None:
        findings = web.analyze_tls("h", 443, self.tls(protocol="TLSv1.1"))
        finding = next(f for f in findings if f.check_id == "TLS-PROTOCOL")
        self.assertIs(finding.severity, Severity.HIGH)

    def test_tls12_reported_as_informational_limit(self) -> None:
        findings = web.analyze_tls("h", 443, self.tls())
        finding = next(f for f in findings if f.check_id == "TLS-VERSION")
        self.assertIs(finding.severity, Severity.LOW)
        self.assertIn("no se enumeraron", finding.notes)

    def test_weak_cipher(self) -> None:
        findings = web.analyze_tls("h", 443, self.tls(cipher="ECDHE-RSA-AES128-SHA"))
        self.assertIn("TLS-CIPHER", ids(findings))

    def test_expired_and_self_signed(self) -> None:
        tls = self.tls()
        tls["certificate"] = dict(tls["certificate"], not_after="Jan  1 00:00:00 2021 GMT", self_signed=True)
        findings = web.analyze_tls("h", 443, tls)
        self.assertEqual({"TLS-CERT-EXPIRED", "TLS-CERT-SELFSIGNED"} - ids(findings), set())

    def test_undecodable_certificate_is_not_hidden(self) -> None:
        tls = self.tls()
        tls["certificate"] = {"decoded": False, "sha256": "c" * 64, "decode_error": "ValueError"}
        finding = next(f for f in web.analyze_tls("h", 443, tls) if f.check_id == "TLS-CERT-DECODE")
        self.assertEqual(finding.validation_state, ValidationState.NOT_VALIDATED)

    def test_verification_mode_is_disclosed(self) -> None:
        findings = web.analyze_tls("h", 443, self.tls())
        method = next(f for f in findings if f.check_id == "TLS-VERIFY-METHOD")
        self.assertIn("deshabilitó la verificación", method.impact)

    def test_failed_handshake_yields_nothing(self) -> None:
        self.assertEqual(web.analyze_tls("h", 443, {"ok": False, "error": "sslv3 alert"}), [])


class TestCombined(unittest.TestCase):
    def test_service_analysis_combines_tls_and_http(self) -> None:
        from sentinel.model import Service

        service = Service(
            host="h", port=443,
            tls={"ok": True, "protocol": "TLSv1.1", "cipher": "RC4-SHA",
                 "certificate": {"decoded": True, "self_signed": True, "subject": "CN=h", "issuer": "CN=h",
                                 "not_after": "Jan  1 00:00:00 2099 GMT", "sha256": "d" * 64}},
            http=probe({"Server": "Apache/2.4.49"}),
        )
        check_ids = ids(web.analyze_service_web(service))
        self.assertIn("TLS-PROTOCOL", check_ids)
        self.assertIn("TLS-CIPHER", check_ids)
        self.assertIn("TLS-CERT-SELFSIGNED", check_ids)
        self.assertIn("WEB-HEADER", check_ids)


if __name__ == "__main__":
    unittest.main()
