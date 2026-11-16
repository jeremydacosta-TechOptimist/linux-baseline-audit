"""Tests for the systemd service exposure checks."""

from __future__ import annotations

import unittest

from baseaudit.checks import services
from baseaudit.model import Status
from tests.support import AuditTestCase


def wanted_units(*names: str) -> dict[str, str]:
    return {
        f"etc/systemd/system/multi-user.target.wants/{name}": f"/usr/lib/systemd/system/{name}\n"
        for name in names
    }


class ServiceCheckTests(AuditTestCase):
    def run_check(self, *units: str):  # type: ignore[no-untyped-def]
        tree = self.make_tree(wanted_units(*units))
        return services.run(tree.target)

    def test_ssh_enabled_passes_and_risky_units_fail(self) -> None:
        findings = self.run_check("ssh.service", "telnet.socket", "avahi-daemon.service")
        self.assertStatus(findings, "SVC-01", Status.PASS)
        self.assertStatus(findings, "SVC-02", Status.FAIL)
        self.assertStatus(findings, "SVC-03", Status.WARN)
        self.assertStatus(findings, "SVC-04", Status.PASS)

    def test_minimal_server_passes(self) -> None:
        findings = self.run_check("ssh.service")
        for rule_id in ("SVC-01", "SVC-02", "SVC-03", "SVC-04"):
            self.assertStatus(findings, rule_id, Status.PASS)

    def test_missing_ssh_fails(self) -> None:
        findings = self.run_check("cron.service")
        self.assertStatus(findings, "SVC-01", Status.FAIL)

    def test_rpcbind_warns(self) -> None:
        findings = self.run_check("ssh.service", "rpcbind.service")
        self.assertStatus(findings, "SVC-04", Status.WARN)

    def test_no_systemd_tree_skips(self) -> None:
        tree = self.make_tree()
        findings = services.run(tree.target)
        for finding in findings:
            self.assertEqual(finding.status, Status.SKIP)

    def test_enabled_units_helper(self) -> None:
        tree = self.make_tree(wanted_units("ssh.service", "cups.service"))
        self.assertEqual(services.enabled_units(tree.target), {"ssh.service", "cups.service"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
