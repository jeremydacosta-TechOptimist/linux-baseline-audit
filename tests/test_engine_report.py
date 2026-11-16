"""End-to-end tests for the engine and the report renderers."""

from __future__ import annotations

import json
import unittest

from baseaudit.engine import available_categories, iter_rules, run_audit
from baseaudit.model import CATEGORIES, Status
from baseaudit.report import (
    build_delta,
    delta_to_markdown,
    delta_to_text,
    from_json,
    to_html,
    to_json,
    to_markdown,
    to_text,
)
from baseaudit.target import AuditTarget
from tests.support import EXAMPLE_ROOT, AuditTestCase


class EngineTests(AuditTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.target = AuditTarget(EXAMPLE_ROOT)
        cls.report = run_audit(cls.target)

    def test_rule_catalogue_is_complete(self) -> None:
        self.assertEqual(len(list(iter_rules())), 41)
        self.assertEqual(available_categories(), CATEGORIES)

    def test_report_contains_every_rule(self) -> None:
        self.assertEqual(len(self.report.findings), 41)
        counts = self.report.counts()
        self.assertEqual(sum(counts.values()), 41)
        self.assertLessEqual(self.report.score(), 100)

    def test_example_host_has_expected_failures(self) -> None:
        for rule_id in (
            "SSH-01",
            "USR-01",
            "USR-02",
            "USR-06",
            "SYS-03",
            "SVC-02",
            "FW-01",
            "FW-02",
            "UPD-01",
        ):
            self.assertStatus(self.report.findings, rule_id, Status.FAIL)

    def test_example_host_has_expected_warnings(self) -> None:
        for rule_id in ("SYS-01", "USR-04", "SVC-03", "FW-03"):
            self.assertStatus(self.report.findings, rule_id, Status.WARN)

    def test_example_host_has_expected_passes(self) -> None:
        for rule_id in ("SSH-02", "USR-03", "SYS-06", "SVC-01"):
            self.assertStatus(self.report.findings, rule_id, Status.PASS)

    def test_platform_dependent_rules(self) -> None:
        for rule_id in ("SSH-09", "PERM-01", "PERM-02", "PERM-03", "PERM-04", "PERM-05", "PERM-06"):
            status = self.report.status_of(rule_id)
            self.assertIn(status, (Status.PASS, Status.FAIL, Status.SKIP))
        # Package metadata age depends on the checkout date, so it is PASS or WARN.
        self.assertIn(self.report.status_of("UPD-02"), (Status.PASS, Status.WARN))

    def test_category_filter(self) -> None:
        ssh_only = run_audit(self.target, categories=["ssh"])
        self.assertEqual(len(ssh_only.findings), 9)
        self.assertTrue(all(finding.rule.category == "ssh" for finding in ssh_only.findings))

    def test_severity_gate(self) -> None:
        from baseaudit.model import Severity

        self.assertTrue(self.report.has_failures_at_or_above(Severity.CRITICAL))
        self.assertFalse(self.report.has_failures_at_or_above(Severity.INFO) is None)


class ReportRenderTests(AuditTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = run_audit(AuditTarget(EXAMPLE_ROOT))

    def test_json_round_trip_preserves_findings(self) -> None:
        restored = from_json(to_json(self.report))
        self.assertEqual(restored.target, self.report.target)
        self.assertEqual(restored.score(), self.report.score())
        self.assertEqual(
            [finding.status for finding in restored.findings],
            [finding.status for finding in self.report.findings],
        )
        payload = json.loads(to_json(self.report))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["summary"]["total"], 41)
        self.assertEqual(len(payload["findings"]), 41)

    def test_json_rejects_unknown_payload(self) -> None:
        with self.assertRaises(ValueError):
            from_json("not json")
        with self.assertRaises(ValueError):
            from_json("{}")

    def test_text_report_contains_failures_and_summary(self) -> None:
        text = to_text(self.report)
        self.assertIn("FAILURES", text)
        self.assertIn("SSH-01", text)
        self.assertIn("CATEGORY SUMMARY", text)
        self.assertIn("Score:", text)

    def test_markdown_report_contains_tables(self) -> None:
        markdown = to_markdown(self.report)
        self.assertIn("| `SSH-01` | critical | **FAIL** |", markdown)
        self.assertIn("## Summary", markdown)
        self.assertIn("## Remediation", markdown)

    def test_html_report_is_standalone(self) -> None:
        document = to_html(self.report)
        self.assertTrue(document.startswith("<!DOCTYPE html>"))
        self.assertIn("<style>", document)
        self.assertIn("status-FAIL", document)
        self.assertNotIn("<script", document)
        self.assertNotIn("http://", document)

    def test_fixing_a_failure_improves_the_score(self) -> None:
        payload = json.loads(to_json(self.report))
        for finding in payload["findings"]:
            if finding["id"] == "SSH-01":
                finding["status"] = "PASS"
        improved = from_json(json.dumps(payload))
        delta = build_delta(self.report, improved)
        self.assertGreaterEqual(delta.score_change, 0)
        self.assertEqual(len(delta.fixes), 1)
        self.assertIn("FIXES (1)", delta_to_text(delta))
        self.assertIn("SSH-01", delta_to_markdown(delta))

    def test_regression_is_reported(self) -> None:
        payload = json.loads(to_json(self.report))
        for finding in payload["findings"]:
            if finding["id"] == "SSH-01":
                finding["status"] = "PASS"
        cleaner = from_json(json.dumps(payload))
        delta = build_delta(cleaner, self.report)
        self.assertEqual(len(delta.regressions), 1)
        self.assertLessEqual(delta.score_change, 0)
        self.assertIn("REGRESSIONS (1)", delta_to_text(delta))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
