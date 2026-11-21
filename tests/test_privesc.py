"""Privilege-escalation analysis: hypotheses, never exploits."""

from __future__ import annotations

import unittest

from sentinel import privesc
from sentinel.model import Confidence, Severity, ValidationState

from .support import make_facts, sudo_result

SUDO_LISTING = """\
Matching Defaults entries for analyst on host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin

User analyst may run the following commands on host:
    (root) NOPASSWD: /usr/bin/find
    (ALL : ALL) ALL
"""


class TestSudoParsing(unittest.TestCase):
    def test_parses_rules_and_flags(self) -> None:
        rules = privesc.parse_sudo_listing(SUDO_LISTING)
        self.assertEqual(len(rules), 2)
        self.assertTrue(rules[0]["nopasswd"])
        self.assertEqual(rules[0]["command"], "/usr/bin/find")
        self.assertTrue(rules[1]["all"])

    def test_full_sudo_is_aggregated_into_one_finding(self) -> None:
        listing = """\
User analyst may run the following commands on host:
    (ALL : ALL) ALL
    (ALL : ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
"""
        facts = make_facts(sudo=sudo_result(listing))
        findings, skipped = privesc.analyze_sudo(facts)
        self.assertEqual(skipped, [])
        all_findings = [f for f in findings if f.check_id == "PRIV-SUDO-ALL"]
        self.assertEqual(len(all_findings), 1)
        self.assertIs(all_findings[0].severity, Severity.CRITICAL)  # NOPASSWD present
        self.assertIn("sin contraseña", all_findings[0].title)
        data = all_findings[0].evidence[0].to_dict()["data"]
        self.assertEqual(len(data["rules"]), 3)

    def test_full_sudo_without_nopasswd_is_high(self) -> None:
        facts = make_facts(sudo=sudo_result("User a may run the following commands on h:\n    (ALL : ALL) ALL\n"))
        findings, _ = privesc.analyze_sudo(facts)
        self.assertIs(findings[0].severity, Severity.HIGH)


class TestSudoBinaries(unittest.TestCase):
    def test_gtfobin_rule_becomes_hypothesis(self) -> None:
        listing = "User a may run the following commands on h:\n    (root) NOPASSWD: /usr/bin/find\n"
        findings, _ = privesc.analyze_sudo(make_facts(sudo=sudo_result(listing)))
        finding = findings[0]
        self.assertEqual(finding.check_id, "PRIV-SUDO-GTFOBIN")
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertIs(finding.confidence, Confidence.HYPOTHESIS)
        self.assertEqual(finding.validation_state, ValidationState.NOT_VALIDATED)
        self.assertTrue(finding.manual_validation_required)
        self.assertTrue(finding.prerequisites)

    def test_no_command_sequence_in_the_finding(self) -> None:
        """The finding must describe a technique class, not a runnable payload."""
        listing = "User a may run the following commands on h:\n    (root) NOPASSWD: /usr/bin/vim\n"
        finding = privesc.analyze_sudo(make_facts(sudo=sudo_result(finding_listing := listing)))[0][0]
        text = (finding.title + finding.impact + finding.remediation + str(finding.notes)).lower()
        self.assertIn("shell escape", text)
        for token in ("sudo vim", "-c ", "/bin/sh", "-exec", "bash -i"):
            self.assertNotIn(token, text)

    def test_wildcard_rule_is_medium(self) -> None:
        listing = "User a may run the following commands on h:\n    (root) /usr/local/bin/backup-now *\n"
        findings, _ = privesc.analyze_sudo(make_facts(sudo=sudo_result(listing)))
        self.assertIs(findings[0].severity, Severity.MEDIUM)

    def test_sudo_unavailable_is_skipped_not_silently_ignored(self) -> None:
        facts = make_facts(sudo=sudo_result(""))
        facts.sudo.ok = False
        facts.sudo.stderr = "sudo: a password is required"
        findings, skipped = privesc.analyze_sudo(facts)
        self.assertEqual(findings, [])
        self.assertEqual(skipped[0]["check"], "PRIV-SUDO")
        self.assertIn("contraseña", skipped[0]["reason"])


class TestSuid(unittest.TestCase):
    def test_baseline_only_is_not_a_finding(self) -> None:
        facts = make_facts(suid={"available": True, "paths": ["/usr/bin/sudo", "/usr/bin/passwd"]})
        self.assertEqual(privesc.analyze_suid(facts), [])

    def test_unexpected_suid_is_medium(self) -> None:
        facts = make_facts(suid={"available": True, "paths": ["/usr/bin/sudo", "/usr/bin/backup-tool"]})
        finding = privesc.analyze_suid(facts)[0]
        self.assertEqual(finding.check_id, "PRIV-SUID-UNEXPECTED")
        self.assertIs(finding.severity, Severity.MEDIUM)
        self.assertIs(finding.confidence, Confidence.HYPOTHESIS)

    def test_suid_in_home_is_high(self) -> None:
        facts = make_facts(suid={"available": True, "paths": ["/home/analyst/tool"]})
        self.assertIs(privesc.analyze_suid(facts)[0].severity, Severity.HIGH)

    def test_unavailable_inventory_yields_nothing(self) -> None:
        facts = make_facts(suid={"available": False, "reason": "find missing", "paths": []})
        self.assertEqual(privesc.analyze_suid(facts), [])


class TestCapabilities(unittest.TestCase):
    def test_setuid_capability(self) -> None:
        facts = make_facts(capabilities={"available": True,
                                         "entries": ["/usr/bin/helper cap_setuid+ep"]})
        finding = privesc.analyze_capabilities(facts)[0]
        self.assertEqual(finding.check_id, "PRIV-CAP-RISKY")
        self.assertIs(finding.severity, Severity.HIGH)

    def test_capability_on_interpreter_is_critical(self) -> None:
        facts = make_facts(capabilities={"available": True,
                                         "entries": ["/usr/bin/python3.11 cap_setuid,cap_setgid+ep"]})
        self.assertIs(privesc.analyze_capabilities(facts)[0].severity, Severity.CRITICAL)

    def test_harmless_capability_ignored(self) -> None:
        facts = make_facts(capabilities={"available": True,
                                         "entries": ["/usr/bin/ping cap_net_raw=ep"]})
        self.assertEqual(privesc.analyze_capabilities(facts), [])


class TestWritableJobs(unittest.TestCase):
    def test_world_writable_cron_script_is_high(self) -> None:
        facts = make_facts(cron=[{"path": "/etc/cron.daily/backup", "present": True, "mode": "-rwxrwxrwx",
                                  "mode_octal": "0o777", "world_writable": True, "is_symlink": False}])
        finding = privesc.analyze_writable_jobs(facts)[0]
        self.assertIs(finding.severity, Severity.HIGH)

    def test_world_writable_cron_directory_is_critical(self) -> None:
        facts = make_facts(cron=[{"path": "/etc/cron.d", "present": True, "mode": "drwxrwxrwx",
                                  "mode_octal": "0o777", "world_writable": True, "is_symlink": False}])
        self.assertIs(privesc.analyze_writable_jobs(facts)[0].severity, Severity.CRITICAL)

    def test_symlinked_masked_unit_is_not_a_finding(self) -> None:
        facts = make_facts(systemd_units=[{"path": "/etc/systemd/system/x.service", "present": True,
                                           "mode": "lrwxrwxrwx", "mode_octal": "0o777", "world_writable": False,
                                           "is_symlink": True, "symlink_target": "/dev/null"}])
        self.assertEqual(privesc.analyze_writable_jobs(facts), [])

    def test_writable_path_directory(self) -> None:
        facts = make_facts(path_dirs=[{"path": "/usr/local/bin", "present": True,
                                       "writable_by_current_user": True}])
        finding = privesc.analyze_writable_jobs(facts)[0]
        self.assertEqual(finding.check_id, "PRIV-PATH-WRITABLE")
        self.assertIs(finding.severity, Severity.MEDIUM)


class TestAggregate(unittest.TestCase):
    def test_posture_summary_states_no_exploitation(self) -> None:
        from sentinel.audit import AuditLog
        from sentinel.scope import Scope, ScopeGuard

        import os

        from .support import scope_dict, tempdir

        directory = tempdir()
        scope = Scope.from_dict(scope_dict(targets=[
            {"kind": "local_host", "value": "self", "ports": [65000], "max_tier": 1}]))
        guard = ScopeGuard(scope, AuditLog(os.path.join(directory, "a.jsonl"), "E", "t"))
        facts = make_facts(sudo=sudo_result(SUDO_LISTING))
        findings, skipped, posture = privesc.analyze_all(guard, facts)
        self.assertFalse(posture["exploitation_attempted"])
        self.assertGreaterEqual(posture["hypotheses"] + posture["observed"], 2)
        self.assertFalse(any("exploit" in (f.impact or "").lower() and "no se" not in f.impact.lower()
                             for f in findings))


if __name__ == "__main__":
    unittest.main()
