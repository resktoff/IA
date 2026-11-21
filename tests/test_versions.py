"""Version parsing and advisory boundary conditions."""

from __future__ import annotations

import unittest

from sentinel.checks.exposure import load_advisories, match_advisories
from sentinel.versions import Version, compare


class TestVersionParsing(unittest.TestCase):
    def test_ordering(self) -> None:
        self.assertLess(Version.parse("1.0.1e"), Version.parse("1.0.1f"))
        self.assertLess(Version.parse("8.2p1"), Version.parse("8.2p2"))
        self.assertLess(Version.parse("9.2p1"), Version.parse("9.3p2"))
        self.assertLess(Version.parse("2.4.49"), Version.parse("2.4.50"))
        self.assertGreater(Version.parse("1.10"), Version.parse("1.9"))

    def test_distribution_suffix_is_ignored(self) -> None:
        self.assertEqual(Version.parse("7.4p1-Debian"), Version.parse("7.4p1"))
        self.assertEqual(Version.parse("1.1.1n+deb12u1"), Version.parse("1.1.1n"))

    def test_unparsable_returns_none(self) -> None:
        self.assertIsNone(Version.parse(""))
        self.assertIsNone(Version.parse("OpenSSH_8.2p1"))

    def test_compare_raises_on_garbage(self) -> None:
        with self.assertRaises(ValueError):
            compare("banana", "1.0")


class TestAdvisoryMatching(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.advisories = load_advisories()

    def test_openssh_range(self) -> None:
        ids = [a.id for a in match_advisories("openssh", "8.2p1", self.advisories)]
        self.assertIn("CVE-2023-38408", ids)

    def test_fixed_version_is_not_affected(self) -> None:
        ids = [a.id for a in match_advisories("openssh", "9.3p2", self.advisories)]
        self.assertNotIn("CVE-2023-38408", ids)

    def test_below_introduced_is_not_affected(self) -> None:
        ids = [a.id for a in match_advisories("openssh", "7.9", self.advisories)]
        self.assertNotIn("CVE-2023-38408", ids)
        # 7.9 is above the fix for the user-enumeration bug (7.8)
        self.assertNotIn("CVE-2018-15473", ids)

    def test_old_openssh_matches_user_enumeration(self) -> None:
        ids = [a.id for a in match_advisories("openssh", "7.4", self.advisories)]
        self.assertIn("CVE-2018-15473", ids)

    def test_apache_boundary(self) -> None:
        ids = [a.id for a in match_advisories("apache_httpd", "2.4.49", self.advisories)]
        self.assertEqual(ids, ["CVE-2021-41773"])
        ids = [a.id for a in match_advisories("apache_httpd", "2.4.50", self.advisories)]
        self.assertEqual(ids, ["CVE-2021-42013"])

    def test_unknown_product_or_missing_version(self) -> None:
        self.assertEqual(match_advisories("nginx", "1.18.0", self.advisories), [])
        self.assertEqual(match_advisories("openssh", None, self.advisories), [])
        self.assertEqual(match_advisories(None, "8.2", self.advisories), [])

    def test_all_advisories_have_parseable_vectors_and_ranges(self) -> None:
        from sentinel.cvss import score as cvss

        for advisory in self.advisories:
            with self.subTest(cve=advisory.id):
                self.assertTrue(advisory.vector.startswith("CVSS:3.1/"))
                cvss(advisory.vector)
                self.assertLess(Version.parse(advisory.introduced), Version.parse(advisory.fixed))


if __name__ == "__main__":
    unittest.main()
