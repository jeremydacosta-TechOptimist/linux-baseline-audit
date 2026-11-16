"""Tests for the account and privilege checks."""

from __future__ import annotations

import unittest

from baseaudit.checks import users
from baseaudit.model import Status
from tests.support import AuditTestCase

CLEAN_FILES = {
    "etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
        "labadmin:x:1000:1000:Lab Admin:/home/labadmin:/bin/bash\n"
    ),
    "etc/shadow": (
        "root:$6$labhash:19000:0:90:14:::\n"
        "daemon:*:19000:0:99999:7:::\n"
        "labadmin:$6$labhash2:19000:0:90:14:::\n"
    ),
    "etc/login.defs": "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 14\nUID_MIN 1000\n",
    "etc/sudoers": "Defaults use_pty\n%sudo ALL=(ALL:ALL) ALL\n",
}


class UsersCheckTests(AuditTestCase):
    def run_check(self, overrides: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
        files = dict(CLEAN_FILES)
        if overrides:
            for key, value in overrides.items():
                if value == "":
                    files.pop(key, None)
                else:
                    files[key] = value
        tree = self.make_tree(files)
        return users.run(tree.target)

    def test_clean_host_passes_every_rule(self) -> None:
        findings = self.run_check()
        self.assertEqual(len(findings), len(users.RULES))
        for finding in findings:
            self.assertEqual(finding.status, Status.PASS, f"{finding.rule.rule_id}: {finding.evidence}")

    def test_second_uid_zero_account_fails(self) -> None:
        findings = self.run_check(
            {
                "etc/passwd": CLEAN_FILES["etc/passwd"]
                + "backdoor:x:0:0:Service:/root:/sbin/nologin\n"
            }
        )
        self.assertStatus(findings, "USR-01", Status.FAIL)
        mapping = self.findings_by_id(findings)
        self.assertIn("backdoor", mapping["USR-01"].details)

    def test_empty_password_fails(self) -> None:
        findings = self.run_check(
            {
                "etc/shadow": CLEAN_FILES["etc/shadow"]
                + "legacy::19500:0:99999:7:::\n"
            }
        )
        self.assertStatus(findings, "USR-02", Status.FAIL)

    def test_missing_shadow_is_skipped(self) -> None:
        findings = self.run_check({"etc/shadow": ""})
        self.assertStatus(findings, "USR-02", Status.SKIP)

    def test_missing_login_defs_warns(self) -> None:
        findings = self.run_check({"etc/login.defs": ""})
        self.assertStatus(findings, "USR-03", Status.WARN)

    def test_bad_aging_values_fail(self) -> None:
        findings = self.run_check(
            {"etc/login.defs": "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 0\n"}
        )
        self.assertStatus(findings, "USR-03", Status.FAIL)

    def test_duplicate_uid_warns(self) -> None:
        findings = self.run_check(
            {
                "etc/passwd": CLEAN_FILES["etc/passwd"]
                + "cloned:x:1000:1000:Clone:/home/cloned:/bin/bash\n"
            }
        )
        self.assertStatus(findings, "USR-04", Status.WARN)

    def test_interactive_system_account_warns(self) -> None:
        findings = self.run_check(
            {
                "etc/passwd": CLEAN_FILES["etc/passwd"].replace(
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                    "daemon:x:1:1:daemon:/usr/sbin:/bin/bash",
                )
            }
        )
        self.assertStatus(findings, "USR-05", Status.WARN)

    def test_nopasswd_in_sudoers_drop_in_fails(self) -> None:
        findings = self.run_check(
            {"etc/sudoers.d/50-lab-admin": "labadmin ALL=(ALL) NOPASSWD: ALL\n"}
        )
        self.assertStatus(findings, "USR-06", Status.FAIL)
        mapping = self.findings_by_id(findings)
        self.assertTrue(any("sudoers.d/50-lab-admin" in detail for detail in mapping["USR-06"].details))

    def test_missing_use_pty_warns(self) -> None:
        findings = self.run_check({"etc/sudoers": "%sudo ALL=(ALL:ALL) ALL\n"})
        self.assertStatus(findings, "USR-07", Status.WARN)

    def test_missing_sudoers_skips_sudo_rules(self) -> None:
        findings = self.run_check({"etc/sudoers": ""})
        self.assertStatus(findings, "USR-06", Status.SKIP)
        self.assertStatus(findings, "USR-07", Status.SKIP)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
