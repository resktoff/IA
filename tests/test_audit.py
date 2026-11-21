"""Hash-chained audit log: integrity and tamper detection."""

from __future__ import annotations

import json
import os
import unittest

from sentinel.audit import GENESIS, AuditLog, verify_chain

from .support import tempdir


class TestAuditChain(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempdir()
        self.path = os.path.join(self.dir, "audit.jsonl")
        self.log = AuditLog(self.path, "ENG-1", "tester")

    def test_records_are_chained(self) -> None:
        first = self.log.record("run_start", "info")
        second = self.log.record("tcp_connect", "allowed", target="127.0.0.1:80", tier=2)
        self.assertEqual(first["prev_hash"], GENESIS)
        self.assertEqual(second["prev_hash"], first["hash"])
        result = verify_chain(self.path)
        self.assertTrue(result["ok"])
        self.assertEqual(result["records"], 2)
        self.assertEqual(result["head"], second["hash"])

    def test_detects_modified_record(self) -> None:
        for i in range(3):
            self.log.record(f"action_{i}", "info")
        lines = open(self.path, encoding="utf-8").read().splitlines()
        record = json.loads(lines[1])
        record["outcome"] = "allowed"
        lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        open(self.path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

        result = verify_chain(self.path)
        self.assertFalse(result["ok"])
        self.assertIn("hash mismatch", result["reason"])

    def test_detects_deleted_record(self) -> None:
        for i in range(4):
            self.log.record(f"action_{i}", "info")
        lines = open(self.path, encoding="utf-8").read().splitlines()
        del lines[2]
        open(self.path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

        result = verify_chain(self.path)
        self.assertFalse(result["ok"])
        self.assertIn("prev_hash mismatch", result["reason"])

    def test_detects_reordered_records(self) -> None:
        for i in range(3):
            self.log.record(f"action_{i}", "info")
        lines = open(self.path, encoding="utf-8").read().splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        open(self.path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

        self.assertFalse(verify_chain(self.path)["ok"])

    def test_detects_truncated_head(self) -> None:
        for i in range(3):
            self.log.record(f"action_{i}", "info")
        lines = open(self.path, encoding="utf-8").read().splitlines()
        open(self.path, "w", encoding="utf-8").write("\n".join(lines[:2]) + "\n")
        # A truncated log is internally consistent; only the missing tail reveals
        # it. The verifier therefore reports the record count so the caller can
        # compare it against the run's own accounting.
        result = verify_chain(self.path)
        self.assertTrue(result["ok"])
        self.assertEqual(result["records"], 2)

    def test_resume_appends_to_existing_chain(self) -> None:
        self.log.record("run_start", "info")
        resumed = AuditLog(self.path, "ENG-1", "tester")
        third = resumed.record("run_finish", "info")
        self.assertEqual(verify_chain(self.path)["records"], 2)
        self.assertEqual(third["prev_hash"], json.loads(
            open(self.path, encoding="utf-8").read().splitlines()[0])["hash"])

    def test_denials_are_recorded_before_raising(self) -> None:
        self.log.record("collect:identity", "denied", target="local",
                        detail={"reason": "kill switch engaged"})
        records = [json.loads(line) for line in open(self.path, encoding="utf-8")]
        self.assertEqual(records[0]["outcome"], "denied")
        self.assertEqual(records[0]["detail"]["reason"], "kill switch engaged")

    def test_missing_file_is_reported_not_crashed(self) -> None:
        result = verify_chain(os.path.join(self.dir, "nope.jsonl"))
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["reason"])


if __name__ == "__main__":
    unittest.main()
