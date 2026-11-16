"""End-to-end tests for the command line interface."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.support import EXAMPLE_ROOT, REPO_ROOT

ENV = dict(os.environ)
ENV["PYTHONPATH"] = str(REPO_ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", "")


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "baseaudit", *args],
        cwd=str(REPO_ROOT),
        env=ENV,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("baseaudit 1.0.0", result.stdout)

    def test_help(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("CIS-aligned", result.stdout)

    def test_unknown_command_is_a_usage_error(self) -> None:
        result = run_cli("nonsense")
        self.assertEqual(result.returncode, 2)

    def test_rules_catalogue_text(self) -> None:
        result = run_cli("rules")
        self.assertEqual(result.returncode, 0)
        self.assertIn("41 rules", result.stdout)
        self.assertIn("SSH-01", result.stdout)
        self.assertIn("FW-02", result.stdout)

    def test_rules_catalogue_json_and_category_filter(self) -> None:
        result = run_cli("rules", "--category", "ssh", "--format", "json")
        self.assertEqual(result.returncode, 0)
        rules = json.loads(result.stdout)
        self.assertEqual(len(rules), 9)
        self.assertTrue(all(rule["category"] == "ssh" for rule in rules))

    def test_audit_text_reports_failures_and_gates(self) -> None:
        result = run_cli("audit", "--root", str(EXAMPLE_ROOT), "--format", "text")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAILURES", result.stdout)
        self.assertIn("SSH-01", result.stdout)

    def test_audit_json_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            result = run_cli(
                "audit",
                "--root",
                str(EXAMPLE_ROOT),
                "--format",
                "json",
                "--fail-on",
                "none",
                "-o",
                str(output),
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("report written to", result.stdout)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["summary"]["total"], 41)
            self.assertGreater(payload["summary"]["FAIL"], 0)

    def test_audit_category_filter_limits_rules(self) -> None:
        result = run_cli(
            "audit",
            "--root",
            str(EXAMPLE_ROOT),
            "--category",
            "ssh",
            "--format",
            "json",
            "--fail-on",
            "none",
        )
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(len(payload["findings"]), 9)
        self.assertTrue(all(item["category"] == "ssh" for item in payload["findings"]))

    def test_audit_markdown_and_html_outputs(self) -> None:
        markdown = run_cli("audit", "--root", str(EXAMPLE_ROOT), "--format", "markdown", "--fail-on", "none")
        self.assertEqual(markdown.returncode, 0)
        self.assertIn("| `SSH-01` |", markdown.stdout)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.html"
            html = run_cli(
                "audit",
                "--root",
                str(EXAMPLE_ROOT),
                "--format",
                "html",
                "--fail-on",
                "none",
                "-o",
                str(output),
            )
            self.assertEqual(html.returncode, 0)
            document = output.read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", document)
            self.assertIn("status-FAIL", document)

    def test_audit_missing_root_is_an_error(self) -> None:
        result = run_cli("audit", "--root", str(REPO_ROOT / "does-not-exist"), "--fail-on", "none")
        self.assertEqual(result.returncode, 2)
        self.assertIn("does not exist", result.stderr)

    @unittest.skipIf(os.name == "posix", "on POSIX the default root is /")
    def test_audit_requires_root_on_non_posix(self) -> None:
        result = run_cli("audit", "--fail-on", "none")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--root is required", result.stderr)

    def test_report_command_rerenders_saved_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "report.json"
            run_cli(
                "audit",
                "--root",
                str(EXAMPLE_ROOT),
                "--format",
                "json",
                "--fail-on",
                "none",
                "-o",
                str(data),
            )
            result = run_cli("report", str(data), "--format", "markdown")
            self.assertEqual(result.returncode, 0)
            self.assertIn("| `SSH-01` |", result.stdout)

    def test_diff_command_reports_regressions_and_fixes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp) / "baseline.json"
            run_cli(
                "audit",
                "--root",
                str(EXAMPLE_ROOT),
                "--format",
                "json",
                "--fail-on",
                "none",
                "-o",
                str(baseline),
            )
            payload = json.loads(baseline.read_text(encoding="utf-8"))
            for finding in payload["findings"]:
                if finding["id"] == "SSH-01":
                    finding["status"] = "PASS"
            improved = Path(tmp) / "improved.json"
            improved.write_text(json.dumps(payload), encoding="utf-8")
            result = run_cli("diff", str(baseline), str(improved))
            self.assertEqual(result.returncode, 0)
            self.assertIn("Report comparison", result.stdout)
            self.assertIn("FIXES (1)", result.stdout)
            self.assertIn("SSH-01", result.stdout)

    def test_invalid_report_file_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken.json"
            broken.write_text("{}", encoding="utf-8")
            result = run_cli("report", str(broken))
            self.assertEqual(result.returncode, 1)
            self.assertIn("unsupported report schema", result.stderr)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
