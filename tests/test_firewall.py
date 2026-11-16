"""Tests for the host firewall checks."""

from __future__ import annotations

import unittest

from baseaudit.checks import firewall
from baseaudit.model import Status
from tests.support import AuditTestCase


class FirewallCheckTests(AuditTestCase):
    def run_check(self, files: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
        tree = self.make_tree(files or {})
        return firewall.run(tree.target)

    def test_active_ufw_with_deny_policy_and_boot_unit_passes(self) -> None:
        findings = self.run_check(
            {
                "etc/ufw/ufw.conf": "ENABLED=yes\n",
                "etc/default/ufw": 'DEFAULT_INPUT_POLICY="DROP"\n',
                "etc/systemd/system/multi-user.target.wants/ufw.service": "/lib/systemd/system/ufw.service\n",
            }
        )
        self.assertStatus(findings, "FW-01", Status.PASS)
        self.assertStatus(findings, "FW-02", Status.PASS)
        self.assertStatus(findings, "FW-03", Status.PASS)

    def test_disabled_ufw_and_accept_policy_fails(self) -> None:
        findings = self.run_check(
            {
                "etc/ufw/ufw.conf": "ENABLED=no\n",
                "etc/default/ufw": 'DEFAULT_INPUT_POLICY="ACCEPT"\n',
            }
        )
        self.assertStatus(findings, "FW-01", Status.FAIL)
        self.assertStatus(findings, "FW-02", Status.FAIL)
        self.assertStatus(findings, "FW-03", Status.WARN)

    def test_no_firewall_configuration_is_skipped(self) -> None:
        findings = self.run_check()
        for finding in findings:
            self.assertEqual(finding.status, Status.SKIP)

    def test_nftables_ruleset_is_detected(self) -> None:
        findings = self.run_check(
            {
                "etc/nftables.conf": (
                    "table inet filter {\n"
                    "  chain input { type filter hook input priority 0; policy drop; }\n"
                    "}\n"
                )
            }
        )
        self.assertStatus(findings, "FW-01", Status.PASS)
        self.assertStatus(findings, "FW-02", Status.PASS)

    def test_iptables_rules_file_detected(self) -> None:
        findings = self.run_check({"etc/iptables/rules.v4": "-A INPUT -p tcp --dport 22 -j ACCEPT\n"})
        self.assertStatus(findings, "FW-01", Status.PASS)
        self.assertStatus(findings, "FW-02", Status.SKIP)
        self.assertStatus(findings, "FW-03", Status.WARN)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
