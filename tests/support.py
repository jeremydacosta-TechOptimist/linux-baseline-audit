"""Shared helpers for the baseaudit test suite."""

from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from baseaudit.model import Finding
from baseaudit.target import AuditTarget

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_ROOT = REPO_ROOT / "examples" / "lab-server"


class TempTree:
    """A disposable directory tree that mimics an audit root."""

    def __init__(self, files: dict[str, str] | None = None) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="baseaudit-test-")
        self.root = Path(self._tmp.name)
        self._target = AuditTarget(self.root)
        if files:
            self.write(files)

    def write(self, files: dict[str, str]) -> None:
        """Create or overwrite files (keys are target-relative paths)."""

        for relative, content in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")

    @property
    def target(self) -> AuditTarget:
        return self._target

    def close(self) -> None:
        self._tmp.cleanup()


class AuditTestCase(unittest.TestCase):
    """Base class with fixtures and finding assertions."""

    def make_tree(self, files: dict[str, str] | None = None) -> TempTree:
        tree = TempTree(files)
        self.addCleanup(tree.close)
        return tree

    @staticmethod
    def findings_by_id(findings: list[Finding]) -> dict[str, Finding]:
        return {finding.rule.rule_id: finding for finding in findings}

    def assertStatus(
        self,
        findings: list[Finding],
        rule_id: str,
        expected: object,
        message: str = "",
    ) -> None:
        mapping = self.findings_by_id(findings)
        self.assertIn(rule_id, mapping, f"missing finding {rule_id}")
        actual = mapping[rule_id].status
        self.assertEqual(actual, expected, message or f"{rule_id}: {mapping[rule_id].evidence}")


def patch_posix(target: AuditTarget, modes: dict[str, int]) -> mock._patch:
    """Force POSIX mode and a deterministic ``os.stat`` table on ``target``."""

    def fake_stat(relative: str) -> types.SimpleNamespace | None:
        mode = modes.get(relative)
        if mode is None:
            return None
        return types.SimpleNamespace(st_mode=mode)

    target.stat = fake_stat  # type: ignore[method-assign]
    return mock.patch.object(
        AuditTarget, "is_posix", new_callable=mock.PropertyMock, return_value=True
    )
