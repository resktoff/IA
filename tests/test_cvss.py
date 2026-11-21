"""CVSS v3.1 base score against vectors with published values."""

from __future__ import annotations

import unittest

from sentinel.cvss import CVSSError, roundup, score, severity_band

# (vector, published base score) — values from the FIRST/NVD calculator.
KNOWN = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # critical RCE, scope unchanged
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # scope changed
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),   # Heartbleed
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # local privesc
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),   # user enumeration class
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
]


class TestKnownScores(unittest.TestCase):
    def test_published_vectors(self) -> None:
        for vector, expected in KNOWN:
            with self.subTest(vector=vector):
                self.assertAlmostEqual(score(vector).score, expected, places=1)

    def test_severity_bands(self) -> None:
        self.assertEqual(severity_band(0.0), "none")
        self.assertEqual(severity_band(3.9), "low")
        self.assertEqual(severity_band(4.0), "medium")
        self.assertEqual(severity_band(6.9), "medium")
        self.assertEqual(severity_band(7.0), "high")
        self.assertEqual(severity_band(8.9), "high")
        self.assertEqual(severity_band(9.0), "critical")
        self.assertEqual(severity_band(10.0), "critical")

    def test_scope_change_increases_pr_impact(self) -> None:
        unchanged = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        changed = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
        self.assertGreater(changed.score, unchanged.score)

    def test_roundup_spec_examples(self) -> None:
        self.assertEqual(roundup(4.0), 4.0)
        self.assertEqual(roundup(4.02), 4.1)
        self.assertEqual(roundup(4.000001), 4.0)  # spec: only the 5th decimal moves the score
        self.assertEqual(roundup(4.11), 4.2)
        self.assertEqual(roundup(9.9999), 10.0)


class TestParsing(unittest.TestCase):
    def test_rejects_wrong_prefix(self) -> None:
        with self.assertRaises(CVSSError):
            score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        with self.assertRaises(CVSSError):
            score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_rejects_missing_metric(self) -> None:
        with self.assertRaises(CVSSError) as ctx:
            score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
        self.assertIn("A", str(ctx.exception))

    def test_rejects_invalid_value(self) -> None:
        with self.assertRaises(CVSSError):
            score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_rejects_temporal_metrics(self) -> None:
        with self.assertRaises(CVSSError) as ctx:
            score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F")
        self.assertIn("not implemented", str(ctx.exception))

    def test_vector_is_round_tripped_and_normalised(self) -> None:
        result = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.to_dict()["metrics"]["S"], "U")


if __name__ == "__main__":
    unittest.main()
