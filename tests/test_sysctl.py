"""Tests for the sysctl kernel hardening checks."""

from __future__ import annotations

import unittest

from baseaudit.checks import sysctl
from baseaudit.model import Status
from tests.support import AuditTestCase

HARDENED = """\
# kernel network hardening
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
kernel.randomize_va_space = 2
"""


class SysctlCheckTests(AuditTestCase):
    def run_check(self, files: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
        tree = self.make_tree(files if files is not None else {"etc/sysctl.d/99-hardening.conf": HARDENED})
        return sysctl.run(tree.target)

    def test_hardened_configuration_passes(self) -> None:
        findings = self.run_check()
        self.assertEqual(len(findings), len(sysctl.RULES))
        for finding in findings:
            self.assertEqual(finding.status, Status.PASS, finding.evidence)

    def test_wrong_redirect_setting_fails(self) -> None:
        findings = self.run_check(
            {"etc/sysctl.d/99-hardening.conf": HARDENED.replace("accept_redirects = 0", "accept_redirects = 1")}
        )
        self.assertStatus(findings, "SYS-03", Status.FAIL)

    def test_ip_forwarding_is_a_warning(self) -> None:
        findings = self.run_check(
            {"etc/sysctl.d/99-hardening.conf": HARDENED.replace("ip_forward = 0", "ip_forward = 1")}
        )
        self.assertStatus(findings, "SYS-01", Status.WARN)

    def test_missing_setting_warns(self) -> None:
        findings = self.run_check(
            {"etc/sysctl.d/99-hardening.conf": HARDENED.replace("net.ipv4.tcp_syncookies = 1\n", "")}
        )
        self.assertStatus(findings, "SYS-06", Status.WARN)

    def test_missing_configuration_skips_every_rule(self) -> None:
        findings = self.run_check({})
        for finding in findings:
            self.assertEqual(finding.status, Status.SKIP)

    def test_sysctl_conf_overrides_drop_in(self) -> None:
        findings = self.run_check(
            {
                "etc/sysctl.d/99-hardening.conf": HARDENED.replace(
                    "accept_redirects = 0", "accept_redirects = 1"
                ),
                "etc/sysctl.conf": "net.ipv4.conf.all.accept_redirects = 0\n",
            }
        )
        self.assertStatus(findings, "SYS-03", Status.PASS)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
