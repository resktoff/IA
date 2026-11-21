"""Read-only local collection: parsing helpers and a real collection run."""

from __future__ import annotations

import os
import unittest

from sentinel.collectors import (
    CRON_DIRS,
    READABLE_FILES,
    _parse_os_release,
    _parse_passwd,
    _perm_info,
    _read_text,
    collect_local_facts,
    first_directive,
    sshd_effective_config,
)
from sentinel.errors import ScopeViolation
from sentinel.model import Evidence

from .support import make_facts, make_guard, scope_dict, tempdir


class TestParsers(unittest.TestCase):
    def test_parse_passwd(self) -> None:
        text = ("root:x:0:0:root:/root:/bin/bash\n"
                "www-data:x:33:33::/var/www:/usr/sbin/nologin\n"
                "analyst:x:1000:1000::/home/analyst:/bin/bash\n"
                "broken-line\n")
        accounts = {a["name"]: a for a in _parse_passwd(text)}
        self.assertEqual(accounts["root"]["uid"], 0)
        self.assertTrue(accounts["root"]["is_root"])
        self.assertFalse(accounts["www-data"]["login_shell"])
        self.assertTrue(accounts["www-data"]["is_system"])
        self.assertTrue(accounts["analyst"]["login_shell"])
        self.assertNotIn("broken-line", accounts)

    def test_parse_os_release(self) -> None:
        text = 'PRETTY_NAME="Debian GNU/Linux 12"\nVERSION_ID="12"\n# comment\n'
        parsed = _parse_os_release(text)
        self.assertEqual(parsed["PRETTY_NAME"], "Debian GNU/Linux 12")
        self.assertNotIn("# comment", parsed)

    def test_perm_info_world_writable(self) -> None:
        directory = tempdir()
        path = os.path.join(directory, "open.conf")
        open(path, "w").close()
        os.chmod(path, 0o666)
        info = _perm_info(path)
        self.assertTrue(info["world_writable"])
        self.assertEqual(info["mode_octal"], "0o666")
        self.assertFalse(info["is_symlink"])

    def test_perm_info_does_not_follow_symlinks(self) -> None:
        directory = tempdir()
        target = os.path.join(directory, "target")
        link = os.path.join(directory, "link")
        open(target, "w").close()
        os.chmod(target, 0o644)
        os.symlink(target, link)
        info = _perm_info(link)
        self.assertTrue(info["is_symlink"])
        self.assertFalse(info["world_writable"])  # the link's own 0777 is not a permission

    def test_perm_info_missing_file(self) -> None:
        self.assertFalse(_perm_info("/nonexistent/path")["present"])

    def test_read_text_handles_missing(self) -> None:
        self.assertIsNone(_read_text("/etc/definitely-not-here"))


class TestSshdParsing(unittest.TestCase):
    def test_include_and_source_lines(self) -> None:
        directory = tempdir()
        include_dir = os.path.join(directory, "conf.d")
        os.makedirs(include_dir)
        path = os.path.join(include_dir, "50-x.conf")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("MaxAuthTries 2\n")
        facts = make_facts(files={**make_facts().files,
                                  "sshd_config": f"Include {include_dir}/*.conf\nPort 22\n"})
        directives = sshd_effective_config(facts)
        self.assertEqual([d["key"] for d in directives], ["MaxAuthTries", "Port"])
        self.assertEqual(directives[0]["file"], path)
        self.assertIsNotNone(first_directive(directives, "port"))

    def test_missing_config_returns_empty(self) -> None:
        facts = make_facts(files={**make_facts().files, "sshd_config": None})
        self.assertEqual(sshd_effective_config(facts), [])


class TestRealCollection(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = tempdir()
        scope, cls.audit, guard = make_guard(cls.dir, targets=[
            {"kind": "local_host", "value": "self", "ports": [65000], "max_tier": 1}])
        cls.facts = collect_local_facts(guard)
        cls.scope = scope

    def test_collects_identity_and_os(self) -> None:
        self.assertTrue(self.facts.identity.get("user"))
        self.assertIn("PRETTY_NAME", self.facts.os)
        self.assertTrue(self.facts.host)

    def test_records_every_command(self) -> None:
        self.assertTrue(self.facts.commands)
        for command in self.facts.commands:
            self.assertIsInstance(command.argv, list)
            self.assertNotIn("shell=True", command.argv)

    def test_never_reads_shadow(self) -> None:
        self.assertNotIn("/etc/shadow", READABLE_FILES.values())
        self.assertNotIn("shadow", self.facts.files)

    def test_permissions_are_collected_without_secrets(self) -> None:
        shadow = self.facts.permissions.get("shadow", {})
        if shadow.get("present"):
            self.assertNotIn("content", shadow)
            self.assertTrue(shadow["mode"].startswith("-"))

    def test_cron_paths_are_known_directories(self) -> None:
        for entry in self.facts.cron:
            self.assertTrue(any(entry["path"].startswith(d) for d in CRON_DIRS))

    def test_evidence_digest(self) -> None:
        self.assertEqual(len(self.facts.evidence[0].digest()), 64)

    def test_audit_trail_covers_collection(self) -> None:
        from sentinel.audit import read_records

        actions = [r["action"] for r in read_records(self.audit.path)]
        self.assertIn("collect:identity", actions)
        self.assertIn("collect:suid_scan", actions)

    def test_collection_requires_a_local_target(self) -> None:
        _, _, other_guard = make_guard(tempdir(), targets=scope_dict()["targets"])
        with self.assertRaises(ScopeViolation):
            collect_local_facts(other_guard)


class TestEvidenceModel(unittest.TestCase):
    def test_digest_is_deterministic_and_sensitive_to_data(self) -> None:
        first = Evidence(kind="k", asset="a", summary="s", data={"x": 1}, source="t")
        second = Evidence(kind="k", asset="a", summary="s", data={"x": 1}, source="t")
        third = Evidence(kind="k", asset="a", summary="s", data={"x": 2}, source="t")
        self.assertEqual(first.digest(), second.digest())
        self.assertNotEqual(first.digest(), third.digest())


if __name__ == "__main__":
    unittest.main()
