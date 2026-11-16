"""Command line interface for baseaudit."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .engine import available_categories, iter_rules, run_audit
from .model import CATEGORIES, Severity
from .report import (
    build_delta,
    delta_to_markdown,
    delta_to_text,
    from_json,
    render,
)
from .target import AuditTarget

RENDER_FORMATS = ("text", "json", "markdown", "html")
FAIL_ON_CHOICES = ("none", "low", "medium", "high", "critical")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``baseaudit`` command."""

    parser = argparse.ArgumentParser(
        prog="baseaudit",
        description=(
            "CIS-aligned Linux server baseline auditor. Reads configuration files "
            "only: it never modifies the audited host."
        ),
        epilog=(
            "Exit codes: 0 audit clean, 1 finding at or above --fail-on, "
            "2 usage error."
        ),
    )
    parser.add_argument("--version", action="version", version=f"baseaudit {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser(
        "audit",
        help="run the baseline against a filesystem tree",
        description="Run every selected rule against a filesystem tree.",
    )
    audit.add_argument(
        "--root",
        default=None,
        help=(
            "directory to audit (the root of a host or of an extracted snapshot); "
            "defaults to / on POSIX, and is required elsewhere"
        ),
    )
    audit.add_argument(
        "--category",
        action="append",
        choices=available_categories(),
        help="limit the audit to a category (repeatable)",
    )
    audit.add_argument(
        "--format",
        choices=RENDER_FORMATS,
        default="text",
        help="report format (default: text)",
    )
    audit.add_argument(
        "-o",
        "--output",
        default=None,
        help="write the report to a file instead of standard output",
    )
    audit.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="high",
        help="return exit code 1 when a failure at or above this severity exists (default: high)",
    )

    rules = subparsers.add_parser(
        "rules",
        help="list the rule catalogue",
        description="List every rule the auditor can evaluate.",
    )
    rules.add_argument(
        "--category",
        action="append",
        choices=available_categories(),
        help="limit the catalogue to a category (repeatable)",
    )
    rules.add_argument("--format", choices=("text", "json"), default="text")

    report = subparsers.add_parser(
        "report",
        help="re-render a saved JSON report",
        description="Re-render a JSON report produced by 'baseaudit audit --format json'.",
    )
    report.add_argument("input", help="JSON report file")
    report.add_argument("--format", choices=("text", "markdown", "html"), default="text")
    report.add_argument("-o", "--output", default=None, help="write to a file")

    diff = subparsers.add_parser(
        "diff",
        help="compare two JSON reports",
        description="Compare two JSON reports and list regressions and fixes.",
    )
    diff.add_argument("old", help="older JSON report")
    diff.add_argument("new", help="newer JSON report")
    diff.add_argument("--format", choices=("text", "markdown"), default="text")
    diff.add_argument("-o", "--output", default=None, help="write to a file")

    return parser


def _default_root() -> str | None:
    """Return the platform default audit root, if there is one."""

    return os.sep if os.name == "posix" else None


def _emit(text: str, output: str | None) -> None:
    if output:
        path = Path(output)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"report written to {path}")
    else:
        sys.stdout.write(text)


def _cmd_audit(args: argparse.Namespace) -> int:
    root = args.root or _default_root()
    if root is None:
        print(
            "baseaudit: error: --root is required on this platform "
            "(for example: --root /mnt/snapshot)",
            file=sys.stderr,
        )
        return 2
    root_path = Path(root)
    if not root_path.exists():
        print(f"baseaudit: error: audit root does not exist: {root_path}", file=sys.stderr)
        return 2
    if not root_path.is_dir():
        print(f"baseaudit: error: audit root is not a directory: {root_path}", file=sys.stderr)
        return 2

    audit_report = run_audit(AuditTarget(root_path), categories=args.category)
    _emit(render(audit_report, args.format), args.output)

    if args.fail_on != "none" and audit_report.has_failures_at_or_above(
        Severity(args.fail_on)
    ):
        return 1
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    selected = set(args.category or [])
    rules = [rule for rule in iter_rules() if not selected or rule.category in selected]
    if args.format == "json":
        payload = [
            {
                "id": rule.rule_id,
                "title": rule.title,
                "category": rule.category,
                "severity": rule.severity.value,
                "remediation": rule.remediation,
                "reference": rule.reference,
            }
            for rule in rules
        ]
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0
    lines = [f"baseaudit {__version__} rule catalogue ({len(rules)} rules)", ""]
    lines.append(f"{'RULE':<8} {'SEVERITY':<9} {'CATEGORY':<12} {'TITLE':<46} REFERENCE")
    for rule in rules:
        lines.append(
            f"{rule.rule_id:<8} {rule.severity.value:<9} {rule.category:<12} "
            f"{rule.title:<46} {rule.reference}"
        )
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def _read_report_file(path: str):
    return from_json(Path(path).read_text(encoding="utf-8"))


def _cmd_report(args: argparse.Namespace) -> int:
    report = _read_report_file(args.input)
    _emit(render(report, args.format), args.output)
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    old = _read_report_file(args.old)
    new = _read_report_file(args.new)
    delta = build_delta(old, new)
    text = delta_to_markdown(delta) if args.format == "markdown" else delta_to_text(delta)
    _emit(text, args.output)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point used by the console script and by ``python -m baseaudit``."""

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            return _cmd_audit(args)
        if args.command == "rules":
            return _cmd_rules(args)
        if args.command == "report":
            return _cmd_report(args)
        if args.command == "diff":
            return _cmd_diff(args)
    except (OSError, ValueError) as exc:
        print(f"baseaudit: error: {exc}", file=sys.stderr)
        return 1
    return 2  # pragma: no cover - argparse guarantees a known command


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
