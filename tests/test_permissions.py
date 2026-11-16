"""Tests for the file permission checks."""

from __future__ import annotations

import unittest
from unittest import mock

from baseaudit.checks import permissions
from baseaudit.model import Status
from baseaudit.target import AuditTarget
from tests.support import AuditTestCase, patch_posix

GOOD_MODES = {
    "etc/passwd": 0o100644,
    "etc/shadow": 0o100640,
    "etc/group": 0o100644,
    "etc/gshadow": 0o100640,
    "etc/ssh/sshd_config": 0o100600,
    "etc/sudoers": 0o100440,
}


class PermissionCheckTests(AuditTestCase):
    def test_restrictive_modes_pass(self) -> None:
        tree = self.make_tree({"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
        with patch_posix(tree.target, GOOD_MODES):
            findings = permissions.run(tree.target)
        self.assertEqual(len(findings), len(permissions.RULES))
        for finding in findings:
            self.assertEqual(finding.status, Status.PASS, finding.evidence)

    def test_world_readable_shadow_fails(self) -> None:
        modes = dict(GOOD_MODES, **{"etc/shadow": 0o100644})
        tree = self.make_tree()
        with patch_posix(tree.target, modes):
            findings = permissions.run(tree.target)
        self.assertStatus(findings, "PERM-02", Status.FAIL)

    def test_group_writable_passwd_fails(self) -> None:
        modes = dict(GOOD_MODES, **{"etc/passwd": 0o100664})
        tree = self.make_tree()
        with patch_posix(tree.target, modes):
            findings = permissions.run(tree.target)
        self.assertStatus(findings, "PERM-01", Status.FAIL)

    def test_sudoers_must_be_read_only(self) -> None:
        modes = dict(GOOD_MODES, **{"etc/sudoers": 0o100444})
        tree = self.make_tree()
        with patch_posix(tree.target, modes):
            findings = permissions.run(tree.target)
        self.assertStatus(findings, "PERM-06", Status.FAIL)

    def test_missing_file_is_skipped(self) -> None:
        modes = dict(GOOD_MODES)
        modes.pop("etc/gshadow")
        tree = self.make_tree()
        with patch_posix(tree.target, modes):
            findings = permissions.run(tree.target)
        self.assertStatus(findings, "PERM-04", Status.SKIP)

    def test_non_posix_platform_skips_every_rule(self) -> None:
        tree = self.make_tree()
        with mock.patch.object(
            AuditTarget, "is_posix", new_callable=mock.PropertyMock, return_value=False
        ):
            findings = permissions.run(tree.target)
        for finding in findings:
            self.assertEqual(finding.status, Status.SKIP)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
