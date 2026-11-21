"""sshd_config checks: defaults, first-match semantics and Include expansion."""

from __future__ import annotations

import os
import unittest

from sentinel.checks import ssh
from sentinel.collectors import first_directive, sshd_effective_config
from sentinel.model import Confidence, Severity, ValidationState

from .support import SSHD_HARD, SSHD_WEAK, make_facts, tempdir


def ids(findings) -> set[str]:
    return {f.check_id for f in findings}


class TestWeakConfiguration(unittest.TestCase):
    def setUp(self) -> None:
        self.facts = make_facts(files={**make_facts().files, "sshd_config": SSHD_WEAK})
        self.findings = ssh.analyze_sshd(self.facts)

    def test_detects_empty_passwords_as_critical(self) -> None:
        finding = next(f for f in self.findings if f.check_id == "SSH-EMPTY-PW")
        self.assertIs(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.cvss_score, 9.8)
        self.assertEqual(finding.validation_state, ValidationState.OBSERVED)

    def test_detects_root_login(self) -> None:
        finding = next(f for f in self.findings if f.check_id == "SSH-ROOT-LOGIN")
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertIn("yes", finding.title)

    def test_detects_password_auth_and_x11(self) -> None:
        self.assertIn("SSH-PASSWORD-AUTH", ids(self.findings))
        self.assertIn("SSH-X11-FORWARD", ids(self.findings))

    def test_every_finding_has_evidence_and_digest(self) -> None:
        for finding in self.findings:
            self.assertTrue(finding.evidence)
            for ev in finding.evidence:
                self.assertEqual(len(ev.to_dict()["evidence_sha256"]), 64)

    def test_config_findings_point_to_a_source_or_default(self) -> None:
        for finding in self.findings:
            if finding.check_id.startswith("SSH-") and finding.check_id != "SSH-WEAK-CIPHERS":
                data = finding.evidence[0].to_dict()["data"]
                self.assertIn("effective_value", data)
                self.assertTrue(data["source"])


class TestAbsentDirectives(unittest.TestCase):
    def test_default_password_authentication_is_reported(self) -> None:
        facts = make_facts(files={**make_facts().files,
                                  "sshd_config": "Port 22\nLogLevel INFO\n"})
        findings = ssh.analyze_sshd(facts)
        finding = next(f for f in findings if f.check_id == "SSH-PASSWORD-AUTH")
        data = finding.evidence[0].to_dict()["data"]
        self.assertTrue(data["from_default"])
        self.assertIn("no está definido", finding.notes)

    def test_default_agent_forwarding_is_reported(self) -> None:
        facts = make_facts(files={**make_facts().files, "sshd_config": "PermitRootLogin no\n"})
        findings = ssh.analyze_sshd(facts)
        self.assertIn("SSH-AGENT-FORWARD", ids(findings))


class TestHardenedConfiguration(unittest.TestCase):
    def test_no_high_findings(self) -> None:
        facts = make_facts(files={**make_facts().files, "sshd_config": SSHD_HARD})
        findings = ssh.analyze_sshd(facts)
        high = [f for f in findings if f.severity.rank >= Severity.HIGH.rank]
        self.assertEqual(high, [], msg=f"unexpected high findings: {[f.check_id for f in high]}")
        self.assertNotIn("SSH-ROOT-LOGIN", ids(findings))
        self.assertNotIn("SSH-EMPTY-PW", ids(findings))
        self.assertNotIn("SSH-PASSWORD-AUTH", ids(findings))

    def test_weak_crypto_only_reported_when_explicitly_configured(self) -> None:
        config = ("PermitRootLogin no\nPasswordAuthentication no\n"
                  "Ciphers aes128-cbc,aes256-gcm@openssh.com\nMACs hmac-md5\n")
        facts = make_facts(files={**make_facts().files, "sshd_config": config})
        findings = ssh.analyze_sshd(facts)
        weak = [f for f in findings if f.check_id.startswith("SSH-WEAK-")]
        self.assertEqual({f.check_id for f in weak}, {"SSH-WEAK-CIPHERS", "SSH-WEAK-MACS"})

    def test_weak_crypto_after_a_good_line_is_ignored(self) -> None:
        # sshd keeps the first value, so a later weak line never takes effect.
        config = ("Ciphers aes256-gcm@openssh.com\n"
                  "Ciphers aes128-cbc\n")
        facts = make_facts(files={**make_facts().files, "sshd_config": config})
        self.assertEqual([f for f in ssh.analyze_sshd(facts) if f.check_id.startswith("SSH-WEAK-")], [])


class TestParsingSemantics(unittest.TestCase):
    def test_first_value_wins(self) -> None:
        config = "PermitRootLogin no\nPermitRootLogin yes\n"
        facts = make_facts(files={**make_facts().files, "sshd_config": config})
        findings = ssh.analyze_sshd(facts)
        self.assertNotIn("SSH-ROOT-LOGIN", ids(findings))

    def test_include_is_expanded(self) -> None:
        directory = tempdir()
        include_dir = os.path.join(directory, "sshd_config.d")
        os.makedirs(include_dir)
        with open(os.path.join(include_dir, "99-weak.conf"), "w", encoding="utf-8") as fh:
            fh.write("PermitRootLogin yes\n")
        config = f"Include {include_dir}/*.conf\nPasswordAuthentication no\n"
        facts = make_facts(files={**make_facts().files, "sshd_config": config})
        findings = ssh.analyze_sshd(facts)
        root = next(f for f in findings if f.check_id == "SSH-ROOT-LOGIN")
        self.assertIn("99-weak.conf", root.evidence[0].to_dict()["data"]["source"])

    def test_comments_and_blank_lines_ignored(self) -> None:
        facts = make_facts(files={**make_facts().files,
                                  "sshd_config": "#PermitRootLogin yes\n\n   \n"})
        directives = sshd_effective_config(facts)
        self.assertEqual(directives, [])

    def test_missing_config_produces_no_findings(self) -> None:
        facts = make_facts(files={**make_facts().files, "sshd_config": None})
        self.assertEqual(ssh.analyze_sshd(facts), [])

    def test_first_directive_helper_is_case_insensitive(self) -> None:
        facts = make_facts(files={**make_facts().files, "sshd_config": "permitrootlogin no\n"})
        directives = sshd_effective_config(facts)
        self.assertIsNotNone(first_directive(directives, "PermitRootLogin"))


class TestConfidenceLabels(unittest.TestCase):
    def test_config_findings_are_confirmed(self) -> None:
        facts = make_facts(files={**make_facts().files, "sshd_config": SSHD_WEAK})
        for finding in ssh.analyze_sshd(facts):
            self.assertIs(finding.confidence, Confidence.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
