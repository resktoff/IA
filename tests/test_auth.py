"""Authentication policy analysis and the credential-attack refusal."""

from __future__ import annotations

import unittest

from sentinel import auth
from sentinel.errors import CapabilityBlocked
from sentinel.model import Confidence, Severity, ValidationState

from .support import make_facts

LOGIN_DEFS = """\
PASS_MAX_DAYS\t99999
PASS_MIN_DAYS\t0
PASS_WARN_AGE\t7
ENCRYPT_METHOD SHA512
"""

PAM_WEAK = "password [success=1 default=ignore] pam_unix.so obscure md5\n"
PAM_STRONG = "password [success=1 default=ignore] pam_unix.so obscure yescrypt\n"
PWQUALITY = "minlen = 14\ndictcheck = 1\n"


def ids(findings) -> set[str]:
    return {f.check_id for f in findings}


class TestPasswordPolicy(unittest.TestCase):
    def test_short_or_absent_minimum_length(self) -> None:
        facts = make_facts(files={**make_facts().files, "login_defs": LOGIN_DEFS, "pam_common_password": PAM_STRONG})
        findings = auth.analyze_password_policy(facts)
        self.assertIn("AUTH-PW-MINLEN", ids(findings))

    def test_weak_hash_is_high(self) -> None:
        facts = make_facts(files={**make_facts().files, "login_defs": LOGIN_DEFS,
                                  "pam_common_password": PAM_WEAK, "pwquality": PWQUALITY})
        finding = next(f for f in auth.analyze_password_policy(facts) if f.check_id == "AUTH-PW-HASH")
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertIn("md5", finding.title.lower())

    def test_yescrypt_is_not_flagged(self) -> None:
        facts = make_facts(files={**make_facts().files, "login_defs": "PASS_MIN_LEN 14\nPASS_MAX_DAYS 90\n",
                                  "pam_common_password": PAM_STRONG, "pwquality": PWQUALITY})
        findings = auth.analyze_password_policy(facts)
        self.assertNotIn("AUTH-PW-HASH", ids(findings))
        self.assertNotIn("AUTH-PW-MINLEN", ids(findings))
        self.assertNotIn("AUTH-PW-COMPLEXITY", ids(findings))

    def test_no_expiry_is_reported_as_low(self) -> None:
        facts = make_facts(files={**make_facts().files, "login_defs": LOGIN_DEFS,
                                  "pam_common_password": PAM_STRONG, "pwquality": PWQUALITY})
        finding = next(f for f in auth.analyze_password_policy(facts) if f.check_id == "AUTH-PW-MAXAGE")
        self.assertIs(finding.severity, Severity.LOW)

    def test_missing_pwquality(self) -> None:
        facts = make_facts(files={**make_facts().files, "login_defs": LOGIN_DEFS,
                                  "pam_common_password": PAM_STRONG})
        self.assertIn("AUTH-PW-COMPLEXITY", ids(auth.analyze_password_policy(facts)))


class TestAccountDatabase(unittest.TestCase):
    def test_world_readable_shadow_is_critical(self) -> None:
        facts = make_facts(permissions={"shadow": {"present": True, "mode": "-rw-r--r--",
                                                   "mode_octal": "0o644", "other_read": True,
                                                   "other_write": False}})
        finding = next(f for f in auth.analyze_account_database(facts) if f.check_id == "AUTH-SHADOW-PERMS")
        self.assertIs(finding.severity, Severity.CRITICAL)

    def test_correct_shadow_permissions_not_flagged(self) -> None:
        facts = make_facts(permissions={"shadow": {"present": True, "mode": "-rw-r-----",
                                                   "mode_octal": "0o640", "other_read": False}})
        self.assertNotIn("AUTH-SHADOW-PERMS", ids(auth.analyze_account_database(facts)))

    def test_world_readable_sudoers(self) -> None:
        facts = make_facts(permissions={"sudoers": {"present": True, "mode": "-rw-r--r--",
                                                    "other_read": True}})
        finding = next(f for f in auth.analyze_account_database(facts) if f.check_id == "AUTH-SUDOERS-PERMS")
        self.assertIs(finding.severity, Severity.HIGH)

    def test_multiple_uid_zero(self) -> None:
        accounts = [
            {"name": "root", "uid": 0, "gid": 0, "shell": "/bin/bash", "is_system": False, "is_root": True,
             "login_shell": True},
            {"name": "toor", "uid": 0, "gid": 0, "shell": "/bin/bash", "is_system": False, "is_root": True,
             "login_shell": True},
        ]
        facts = make_facts(accounts=accounts)
        finding = next(f for f in auth.analyze_account_database(facts) if f.check_id == "AUTH-UID0-MULTIPLE")
        self.assertIs(finding.severity, Severity.HIGH)

    def test_empty_password_field_is_critical(self) -> None:
        facts = make_facts(files={**make_facts().files,
                                  "passwd": "root::0:0:root:/root:/bin/bash\nguest::1001:1001::/home/guest:/bin/sh\n"})
        finding = next(f for f in auth.analyze_account_database(facts) if f.check_id == "AUTH-EMPTY-PASSWORD")
        self.assertIs(finding.severity, Severity.CRITICAL)

    def test_hashes_in_passwd_flagged(self) -> None:
        facts = make_facts(files={**make_facts().files,
                                  "passwd": "root:$6$abc$def:0:0:root:/root:/bin/bash\n"})
        self.assertIn("AUTH-NO-SHADOW", ids(auth.analyze_account_database(facts)))


class TestCookies(unittest.TestCase):
    def test_missing_flags(self) -> None:
        findings = auth.analyze_cookies("host", ["sessionid=abc123; Path=/"], secure_context=True)
        self.assertEqual(findings[0].check_id, "AUTH-COOKIE-FLAGS")
        self.assertIn("Secure", findings[0].title)
        self.assertIn("HttpOnly", findings[0].title)

    def test_hardened_cookie_not_flagged(self) -> None:
        cookie = ("sessionid=" + "a1b2c3d4" * 6 +
                  "; Secure; HttpOnly; SameSite=Lax; Path=/")
        findings = auth.analyze_cookies("host", [cookie], secure_context=True)
        self.assertEqual(findings, [])

    def test_low_entropy_token(self) -> None:
        findings = auth.analyze_cookies("host", ["sid=aaaaaaaaaaaaaaaa; Secure; HttpOnly; SameSite=Lax"],
                                        secure_context=True)
        self.assertTrue(any(f.check_id == "AUTH-COOKIE-ENTROPY" for f in findings))
        entropy = next(f for f in findings if f.check_id == "AUTH-COOKIE-ENTROPY")
        self.assertIs(entropy.confidence, Confidence.INFERRED)

    def test_entropy_calculation(self) -> None:
        result = auth.estimate_token_strength("abababab")
        self.assertEqual(result["alphabet"], 2)
        self.assertAlmostEqual(result["entropy_bits"], 1.0, places=3)
        self.assertAlmostEqual(result["lower_bound_bits"], 8.0, places=1)

    def test_parse_set_cookie(self) -> None:
        parsed = auth.parse_set_cookie("a=b; Path=/; HttpOnly")
        self.assertEqual(parsed["name"], "a")
        self.assertEqual(parsed["value"], "b")
        self.assertIn("httponly", parsed["attributes"])


class TestCredentialAttackRefusal(unittest.TestCase):
    def test_all_entry_points_raise(self) -> None:
        for fn in (auth.credential_attack_guard, auth.login_endpoint_attack,
                   auth.password_spray, auth.default_credential_test):
            with self.subTest(fn=fn.__name__):
                with self.assertRaises(CapabilityBlocked):
                    fn("host", 22, "admin", "admin")

    def test_refusal_message_explains_reason(self) -> None:
        with self.assertRaises(CapabilityBlocked) as ctx:
            auth.password_spray("10.0.0.1", 22, ["Spring2024!"])
        self.assertIn("does not submit credentials", str(ctx.exception))


class TestLoginEndpointFindings(unittest.TestCase):
    def test_missing_rate_limit_headers_is_inferred(self) -> None:
        probe = {"ok": True, "status": 200, "headers": {"Server": "nginx/1.18.0"},
                 "rate_limit_headers": {}, "server_header": "nginx/1.18.0"}
        findings = auth.analyze_login_endpoint("h", 443, probe)
        rate = next(f for f in findings if f.check_id == "AUTH-LOGIN-RATE")
        self.assertIs(rate.confidence, Confidence.INFERRED)
        self.assertEqual(rate.validation_state, ValidationState.NOT_VALIDATED)
        self.assertIn("No se enviaron credenciales", rate.notes)

    def test_rate_limit_headers_present(self) -> None:
        probe = {"ok": True, "status": 200, "headers": {"X-RateLimit-Limit": "5"},
                 "rate_limit_headers": {"x-ratelimit-limit": "5"}, "server_header": None}
        self.assertNotIn("AUTH-LOGIN-RATE", ids(auth.analyze_login_endpoint("h", 443, probe)))


if __name__ == "__main__":
    unittest.main()
