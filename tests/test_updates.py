"""Tests for the patch management checks."""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone

from baseaudit.checks import updates
from baseaudit.model import Status
from tests.support import AuditTestCase

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

APT_ENABLED = {
    "etc/apt/apt.conf.d/20auto-upgrades": (
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
    )
}


class UpdateCheckTests(AuditTestCase):
    def run_check(self, files: dict[str, str] | None = None, now: datetime | None = NOW):  # type: ignore[no-untyped-def]
        tree = self.make_tree(files if files is not None else APT_ENABLED)
        return updates.run(tree.target, now=now)

    def test_apt_automatic_updates_pass(self) -> None:
        findings = self.run_check()
        self.assertStatus(findings, "UPD-01", Status.PASS)

    def test_apt_unattended_upgrades_disabled_fails(self) -> None:
        findings = self.run_check(
            {
                "etc/apt/apt.conf.d/20auto-upgrades": (
                    'APT::Periodic::Update-Package-Lists "1";\n'
                    'APT::Periodic::Unattended-Upgrade "0";\n'
                )
            }
        )
        self.assertStatus(findings, "UPD-01", Status.FAIL)

    def test_dnf_automatic_applies_updates(self) -> None:
        findings = self.run_check(
            {"etc/dnf/automatic.conf": "[commands]\napply_updates = yes\n"}
        )
        self.assertStatus(findings, "UPD-01", Status.PASS)

    def test_dnf_automatic_without_apply_fails(self) -> None:
        findings = self.run_check(
            {"etc/dnf/automatic.conf": "[commands]\napply_updates = no\n"}
        )
        self.assertStatus(findings, "UPD-01", Status.FAIL)

    def test_no_automatic_update_configuration_skips(self) -> None:
        findings = self.run_check({})
        self.assertStatus(findings, "UPD-01", Status.SKIP)
        self.assertStatus(findings, "UPD-02", Status.SKIP)

    def test_fresh_metadata_passes(self) -> None:
        tree = self.make_tree(APT_ENABLED)
        stamp = tree.root / "var/lib/apt/periodic/update-success-stamp"
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text("", encoding="utf-8")
        fresh = (NOW - timedelta(days=1)).timestamp()
        os.utime(stamp, (fresh, fresh))
        findings = updates.run(tree.target, now=NOW)
        self.assertStatus(findings, "UPD-02", Status.PASS)

    def test_stale_metadata_warns(self) -> None:
        tree = self.make_tree(APT_ENABLED)
        stamp = tree.root / "var/lib/apt/periodic/update-success-stamp"
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text("", encoding="utf-8")
        stale = (NOW - timedelta(days=30)).timestamp()
        os.utime(stamp, (stale, stale))
        findings = updates.run(tree.target, now=NOW)
        self.assertStatus(findings, "UPD-02", Status.WARN)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
