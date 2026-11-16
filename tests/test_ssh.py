"""Tests for the SSH server hardening checks."""

from __future__ import annotations

import unittest

from baseaudit.checks import ssh
from baseaudit.model import Status
from tests.support import AuditTestCase, patch_posix

CLEAN_CONFIG = """\
# hardened lab configuration
Port 22
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
LoginGraceTime 60
Banner /etc/issue.net
ClientAliveInterval 300
"""


class SshCheckTests(AuditTestCase):
    def run_check(self, config: str | None = CLEAN_CONFIG):  # type: ignore[no-untyped-def]
        files = {}
        if config is not None:
            files["etc/ssh/sshd_config"] = config
        tree = self.make_tree(files)
        return ssh.run(tree.target)

    def test_clean_configuration_passes(self) -> None:
        findings = self.run_check()
        for rule_id in ("SSH-01", "SSH-02", "SSH-03", "SSH-04", "SSH-05", "SSH-06", "SSH-07", "SSH-08"):
            self.assertStatus(findings, rule_id, Status.PASS)

    def test_missing_configuration_is_skipped(self) -> None:
        findings = self.run_check(config=None)
        self.assertEqual(len(findings), len(ssh.RULES))
        for finding in findings:
            self.assertEqual(finding.status, Status.SKIP)

    def test_root_login_enabled_fails(self) -> None:
        findings = self.run_check(CLEAN_CONFIG.replace("PermitRootLogin no", "PermitRootLogin yes"))
        self.assertStatus(findings, "SSH-01", Status.FAIL)

    def test_root_login_with_keys_warns(self) -> None:
        findings = self.run_check(
            CLEAN_CONFIG.replace("PermitRootLogin no", "PermitRootLogin prohibit-password")
        )
        self.assertStatus(findings, "SSH-01", Status.WARN)

    def test_missing_root_login_warns(self) -> None:
        findings = self.run_check(CLEAN_CONFIG.replace("PermitRootLogin no\n", ""))
        self.assertStatus(findings, "SSH-01", Status.WARN)

    def test_password_authentication_enabled_fails(self) -> None:
        findings = self.run_check(
            CLEAN_CONFIG.replace("PasswordAuthentication no", "PasswordAuthentication yes")
        )
        self.assertStatus(findings, "SSH-02", Status.FAIL)

    def test_empty_passwords_fail(self) -> None:
        findings = self.run_check(
            CLEAN_CONFIG.replace("PermitEmptyPasswords no", "PermitEmptyPasswords yes")
        )
        self.assertStatus(findings, "SSH-03", Status.FAIL)

    def test_max_auth_tries_boundaries(self) -> None:
        too_many = self.run_check(CLEAN_CONFIG.replace("MaxAuthTries 3", "MaxAuthTries 6"))
        self.assertStatus(too_many, "SSH-04", Status.FAIL)
        not_a_number = self.run_check(CLEAN_CONFIG.replace("MaxAuthTries 3", "MaxAuthTries many"))
        self.assertStatus(not_a_number, "SSH-04", Status.WARN)

    def test_x11_forwarding_fails(self) -> None:
        findings = self.run_check(CLEAN_CONFIG.replace("X11Forwarding no", "X11Forwarding yes"))
        self.assertStatus(findings, "SSH-05", Status.FAIL)

    def test_login_grace_time_units(self) -> None:
        minutes = self.run_check(CLEAN_CONFIG.replace("LoginGraceTime 60", "LoginGraceTime 1m"))
        self.assertStatus(minutes, "SSH-06", Status.PASS)
        too_long = self.run_check(CLEAN_CONFIG.replace("LoginGraceTime 60", "LoginGraceTime 120"))
        self.assertStatus(too_long, "SSH-06", Status.FAIL)
        zero = self.run_check(CLEAN_CONFIG.replace("LoginGraceTime 60", "LoginGraceTime 0"))
        self.assertStatus(zero, "SSH-06", Status.WARN)

    def test_missing_banner_fails(self) -> None:
        findings = self.run_check(CLEAN_CONFIG.replace("Banner /etc/issue.net\n", ""))
        self.assertStatus(findings, "SSH-07", Status.FAIL)

    def test_defaults_are_used_for_absent_keywords(self) -> None:
        findings = self.run_check("Port 22\nBanner /etc/issue.net\n")
        self.assertStatus(findings, "SSH-03", Status.PASS)  # default: no
        self.assertStatus(findings, "SSH-05", Status.PASS)  # default: no
        self.assertStatus(findings, "SSH-08", Status.WARN)  # no keep-alive

    def test_include_drop_in_can_supply_missing_keyword(self) -> None:
        tree = self.make_tree(
            {
                "etc/ssh/sshd_config": (
                    "Port 22\nPermitRootLogin no\nPasswordAuthentication yes\n"
                    "Include /etc/ssh/sshd_config.d/*.conf\n"
                ),
                "etc/ssh/sshd_config.d/50-hardening.conf": "PasswordAuthentication no\n",
            }
        )
        findings = ssh.run(tree.target)
        # sshd keeps the first value, so the drop-in must not override the base file.
        self.assertStatus(findings, "SSH-02", Status.FAIL)

    def test_drop_in_supplies_absent_keyword(self) -> None:
        tree = self.make_tree(
            {
                "etc/ssh/sshd_config": "Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\n",
                "etc/ssh/sshd_config.d/50-hardening.conf": "PermitRootLogin no\n",
            }
        )
        findings = ssh.run(tree.target)
        self.assertStatus(findings, "SSH-01", Status.PASS)

    def test_configuration_permissions(self) -> None:
        tree = self.make_tree({"etc/ssh/sshd_config": CLEAN_CONFIG})
        with patch_posix(tree.target, {"etc/ssh/sshd_config": 0o100644}):
            findings = ssh.run(tree.target)
        self.assertStatus(findings, "SSH-09", Status.PASS)

        with patch_posix(tree.target, {"etc/ssh/sshd_config": 0o100666}):
            findings = ssh.run(tree.target)
        self.assertStatus(findings, "SSH-09", Status.FAIL)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
