"""Report renderers: JSON (round-trippable), plain text, Markdown and standalone HTML.

All renderers are deterministic and ASCII-only so their output can be piped,
diffed or pasted into a ticket without encoding surprises.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from typing import Any

from . import __version__
from .model import (
    CATEGORIES,
    CATEGORY_TITLES,
    AuditReport,
    Finding,
    Rule,
    Severity,
    Status,
)

# ---------------------------------------------------------------------------
# JSON — the canonical machine-readable format, also used by report/diff
# ---------------------------------------------------------------------------


def report_to_dict(report: AuditReport) -> dict[str, Any]:
    """Convert a report into a JSON-serialisable dictionary."""

    counts = report.counts()
    categories = report.category_counts()
    return {
        "schema_version": 1,
        "tool": "baseaudit",
        "version": __version__,
        "target": report.target,
        "platform": report.platform,
        "generated_at": report.generated_at,
        "summary": {
            "total": len(report.findings),
            "evaluated": report.evaluated(),
            "score": report.score(),
            **counts,
        },
        "categories": {
            name: categories.get(name, {status.value: 0 for status in Status})
            for name in CATEGORIES
        },
        "findings": [
            {
                "id": finding.rule.rule_id,
                "title": finding.rule.title,
                "category": finding.rule.category,
                "severity": finding.rule.severity.value,
                "status": finding.status.value,
                "evidence": finding.evidence,
                "details": list(finding.details),
                "remediation": finding.rule.remediation,
                "reference": finding.rule.reference,
            }
            for finding in report.findings
        ],
    }


def to_json(report: AuditReport, indent: int = 2) -> str:
    """Render a report as pretty-printed JSON."""

    return json.dumps(report_to_dict(report), indent=indent, sort_keys=False) + "\n"


def from_json(text: str) -> AuditReport:
    """Rebuild a report from :func:`to_json` output.

    Raises :class:`ValueError` when the payload is not a supported report.
    """

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON report: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported report schema (expected schema_version 1)")
    raw_findings = data.get("findings")
    if not isinstance(raw_findings, list):
        raise ValueError("report is missing the findings list")
    findings: list[Finding] = []
    for item in raw_findings:
        try:
            rule = Rule(
                rule_id=str(item["id"]),
                title=str(item["title"]),
                category=str(item["category"]),
                severity=Severity(str(item["severity"])),
                remediation=str(item.get("remediation", "")),
                reference=str(item.get("reference", "")),
            )
            findings.append(
                Finding.of(
                    rule,
                    Status(str(item["status"])),
                    str(item.get("evidence", "")),
                    tuple(str(detail) for detail in item.get("details", [])),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed finding in report: {exc}") from exc
    return AuditReport(
        target=str(data.get("target", "")),
        platform=str(data.get("platform", "")),
        generated_at=str(data.get("generated_at", "")),
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------


def _summary_line(report: AuditReport) -> str:
    counts = report.counts()
    return (
        f"Score: {report.score()}/100   rules={len(report.findings)}   "
        f"PASS={counts['PASS']}  FAIL={counts['FAIL']}  WARN={counts['WARN']}  SKIP={counts['SKIP']}"
    )


def to_text(report: AuditReport) -> str:
    """Render a compact terminal report."""

    lines = [
        f"baseaudit {__version__} audit report",
        f"Target   : {report.target}",
        f"Platform : {report.platform}",
        f"Generated: {report.generated_at}",
        "",
        _summary_line(report),
        "",
    ]
    sections = (
        (Status.FAIL, "FAILURES"),
        (Status.WARN, "WARNINGS"),
        (Status.SKIP, "SKIPPED (not applicable)"),
    )
    for status, header in sections:
        group = [finding for finding in report.findings if finding.status is status]
        if not group:
            continue
        lines.append(f"{header} ({len(group)})")
        for finding in group:
            lines.append(
                f"  {finding.rule.rule_id:<8} [{finding.rule.severity.value.upper():<8}] "
                f"{finding.rule.title}"
            )
            lines.append(f"           evidence: {finding.evidence}")
            for detail in finding.details:
                lines.append(f"           - {detail}")
            if status is not Status.SKIP:
                lines.append(f"           fix: {finding.rule.remediation}")
        lines.append("")

    lines.append("CATEGORY SUMMARY")
    lines.append(f"  {'category':<12} {'PASS':>4} {'FAIL':>4} {'WARN':>4} {'SKIP':>4}")
    for category in CATEGORIES:
        counts = report.category_counts().get(category)
        if counts is None or sum(counts.values()) == 0:
            continue
        lines.append(
            f"  {category:<12} {counts['PASS']:>4} {counts['FAIL']:>4} "
            f"{counts['WARN']:>4} {counts['SKIP']:>4}"
        )
    lines.append("")
    if report.failures():
        lines.append(f"{len(report.failures())} failure(s) need attention.")
    else:
        lines.append("No failures: every evaluated rule passed.")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def to_markdown(report: AuditReport) -> str:
    """Render a report as GitHub-flavoured Markdown."""

    counts = report.counts()
    lines = [
        "# Linux baseline audit",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Platform:** {report.platform}",
        f"- **Generated:** {report.generated_at}",
        f"- **Score:** {report.score()}/100 ({report.evaluated()} evaluated rules)",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | ---: |",
        f"| PASS | {counts['PASS']} |",
        f"| FAIL | {counts['FAIL']} |",
        f"| WARN | {counts['WARN']} |",
        f"| SKIP | {counts['SKIP']} |",
        "",
        "## Findings by category",
        "",
    ]
    for category in CATEGORIES:
        group = [finding for finding in report.findings if finding.rule.category == category]
        if not group:
            continue
        lines.append(f"### {CATEGORY_TITLES.get(category, category)}")
        lines.append("")
        lines.append("| Rule | Severity | Status | Evidence |")
        lines.append("| --- | --- | --- | --- |")
        for finding in group:
            lines.append(
                f"| `{finding.rule.rule_id}` | {finding.rule.severity.value} | "
                f"**{finding.status.value}** | {_md_cell(finding.evidence)} |"
            )
        lines.append("")
    actionable = [
        finding
        for finding in report.findings
        if finding.status in (Status.FAIL, Status.WARN)
    ]
    if actionable:
        lines.extend(["## Remediation", ""])
        for finding in actionable:
            lines.append(f"- **{finding.rule.rule_id}** ({finding.rule.severity.value}): {finding.rule.remediation}")
        lines.append("")
    lines.append(f"_Generated by baseaudit {__version__} (MIT license)._")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Standalone HTML
# ---------------------------------------------------------------------------

_HTML_STYLE = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; padding: 0 24px 48px; font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
       background: #f6f7f9; color: #1f2933; }
header { max-width: 1080px; margin: 0 auto; padding: 32px 0 8px; }
h1 { margin: 0 0 4px; font-size: 26px; }
.meta { color: #52606d; font-size: 13px; margin: 2px 0; }
.meta code { background: #e4e7eb; padding: 1px 5px; border-radius: 4px; }
.cards {display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0 8px; }
.card { flex: 1 1 130px; background: #fff; border: 1px solid #d9e2ec; border-radius: 10px; padding: 12px 16px; }
.card .value { font-size: 24px; font-weight: 700; }
.card .label { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: #616e7c; }
.card.fail .value { color: #b91c1c; } .card.warn .value { color: #b45309; }
.card.pass .value { color: #047857; } .card.skip .value { color: #6b7280; }
main { max-width: 1080px; margin: 0 auto; }
h2 { font-size: 19px; margin: 28px 0 10px; border-bottom: 2px solid #d9e2ec; padding-bottom: 6px; }
h3 { font-size: 15px; margin: 22px 0 8px; color: #323f4b; }
table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d9e2ec;
        border-radius: 10px; overflow: hidden; font-size: 13px; margin-bottom: 8px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #edf2f7; vertical-align: top; }
th { background: #eef2f7; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: #52606d; }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }
.status-PASS { background: #d1fae5; color: #065f46; }
.status-FAIL { background: #fee2e2; color: #991b1b; }
.status-WARN { background: #fef3c7; color: #92400e; }
.status-SKIP { background: #e5e7eb; color: #4b5563; }
.sev { font-weight: 700; font-size: 11px; text-transform: uppercase; }
.sev-critical { color: #7f1d1d; } .sev-high { color: #991b1b; }
.sev-medium { color: #92400e; } .sev-low { color: #4b5563; } .sev-info { color: #6b7280; }
.fix { color: #52606d; font-size: 12px; margin: 2px 0 0; }
footer { max-width: 1080px; margin: 40px auto 0; color: #6b7280; font-size: 12px; }
"""


def _html_page(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{html.escape(title)}</title>\n<style>{_HTML_STYLE}</style>\n"
        f"</head>\n<body>\n{body}\n</body>\n</html>\n"
    )


def to_html(report: AuditReport) -> str:
    """Render a standalone HTML report (no external assets)."""

    counts = report.counts()
    parts: list[str] = [
        "<header>",
        "<h1>Linux baseline audit</h1>",
        f"<p class=\"meta\">Target: <code>{html.escape(report.target)}</code></p>",
        f"<p class=\"meta\">Platform: {html.escape(report.platform)} &middot; "
        f"Generated: {html.escape(report.generated_at)}</p>",
        "<div class=\"cards\">",
        f"<div class=\"card\"><div class=\"value\">{report.score()}/100</div>"
        "<div class=\"label\">Weighted score</div></div>",
        f"<div class=\"card pass\"><div class=\"value\">{counts['PASS']}</div><div class=\"label\">Pass</div></div>",
        f"<div class=\"card fail\"><div class=\"value\">{counts['FAIL']}</div><div class=\"label\">Fail</div></div>",
        f"<div class=\"card warn\"><div class=\"value\">{counts['WARN']}</div><div class=\"label\">Warn</div></div>",
        f"<div class=\"card skip\"><div class=\"value\">{counts['SKIP']}</div><div class=\"label\">Skip</div></div>",
        "</div>",
        "</header>",
        "<main>",
        "<h2>Categories</h2>",
        "<table><thead><tr><th>Category</th><th>PASS</th><th>FAIL</th><th>WARN</th><th>SKIP</th></tr></thead><tbody>",
    ]
    for category in CATEGORIES:
        category_counts = report.category_counts().get(category)
        if category_counts is None or sum(category_counts.values()) == 0:
            continue
        parts.append(
            f"<tr><td>{html.escape(CATEGORY_TITLES.get(category, category))}</td>"
            f"<td>{category_counts['PASS']}</td><td>{category_counts['FAIL']}</td>"
            f"<td>{category_counts['WARN']}</td><td>{category_counts['SKIP']}</td></tr>"
        )
    parts.append("</tbody></table>")
    parts.append("<h2>Findings</h2>")
    for category in CATEGORIES:
        group = [finding for finding in report.findings if finding.rule.category == category]
        if not group:
            continue
        parts.append(f"<section><h3>{html.escape(CATEGORY_TITLES.get(category, category))}</h3>")
        parts.append(
            "<table><thead><tr><th>Rule</th><th>Severity</th><th>Status</th>"
            "<th>Evidence</th><th>Remediation</th></tr></thead><tbody>"
        )
        for finding in group:
            status_class = f"status-{finding.status.value}"
            severity_class = f"sev-{finding.rule.severity.value}"
            details = ""
            if finding.details:
                details = "<br><small>" + "<br>".join(
                    html.escape(detail) for detail in finding.details
                ) + "</small>"
            parts.append(
                f"<tr><td><code>{html.escape(finding.rule.rule_id)}</code><br>"
                f"{html.escape(finding.rule.title)}</td>"
                f"<td><span class=\"sev {severity_class}\">{html.escape(finding.rule.severity.value)}</span></td>"
                f"<td><span class=\"badge {status_class}\">{html.escape(finding.status.value)}</span></td>"
                f"<td>{html.escape(finding.evidence)}{details}</td>"
                f"<td class=\"fix\">{html.escape(finding.rule.remediation)}</td></tr>"
            )
        parts.append("</tbody></table></section>")
    parts.append("</main>")
    parts.append(
        f"<footer>Generated by baseaudit {__version__} &middot; MIT license &middot; "
        "reads configuration files only, never changes the host.</footer>"
    )
    return _html_page(f"baseaudit report - {report.target}", "\n".join(parts))


RENDERERS = {
    "text": to_text,
    "markdown": to_markdown,
    "html": to_html,
    "json": to_json,
}


def render(report: AuditReport, fmt: str) -> str:
    """Render a report in the requested format."""

    try:
        renderer = RENDERERS[fmt]
    except KeyError as exc:  # pragma: no cover - guarded by argparse
        raise ValueError(f"unknown report format: {fmt!r}") from exc
    return renderer(report)


# ---------------------------------------------------------------------------
# Diff between two saved reports
# ---------------------------------------------------------------------------

_SEVERITY_LABEL = {severity.value: severity.value for severity in Severity}


@dataclass
class ReportDelta:
    """Difference between two reports, rule by rule."""

    old: AuditReport
    new: AuditReport
    regressions: list[tuple[Finding, Finding]]
    fixes: list[tuple[Finding, Finding]]
    added: list[Finding]
    removed: list[Finding]

    @property
    def score_change(self) -> int:
        return self.new.score() - self.old.score()


def build_delta(old: AuditReport, new: AuditReport) -> ReportDelta:
    """Compare two reports by rule id and classify the changes."""

    old_by_id = {finding.rule.rule_id: finding for finding in old.findings}
    new_by_id = {finding.rule.rule_id: finding for finding in new.findings}
    regressions: list[tuple[Finding, Finding]] = []
    fixes: list[tuple[Finding, Finding]] = []
    for rule_id, new_finding in new_by_id.items():
        old_finding = old_by_id.get(rule_id)
        if old_finding is None:
            continue
        old_status, new_status = old_finding.status, new_finding.status
        if new_status is Status.FAIL and old_status is not Status.FAIL:
            regressions.append((old_finding, new_finding))
        elif new_status is Status.WARN and old_status is Status.PASS:
            regressions.append((old_finding, new_finding))
        elif old_status is Status.FAIL and new_status is not Status.FAIL:
            fixes.append((old_finding, new_finding))
        elif old_status is Status.WARN and new_status is Status.PASS:
            fixes.append((old_finding, new_finding))
    added = [finding for rule_id, finding in new_by_id.items() if rule_id not in old_by_id]
    removed = [finding for rule_id, finding in old_by_id.items() if rule_id not in new_by_id]
    return ReportDelta(
        old=old,
        new=new,
        regressions=regressions,
        fixes=fixes,
        added=added,
        removed=removed,
    )


def _delta_header(delta: ReportDelta) -> list[str]:
    old_counts, new_counts = delta.old.counts(), delta.new.counts()
    sign = "+" if delta.score_change >= 0 else ""
    return [
        f"Old report: {delta.old.target}  (generated {delta.old.generated_at})",
        f"New report: {delta.new.target}  (generated {delta.new.generated_at})",
        f"Score: {delta.old.score()} -> {delta.new.score()} ({sign}{delta.score_change})",
        f"Failures: {old_counts['FAIL']} -> {new_counts['FAIL']}   "
        f"Warnings: {old_counts['WARN']} -> {new_counts['WARN']}   "
        f"Passes: {old_counts['PASS']} -> {new_counts['PASS']}",
    ]


def delta_to_text(delta: ReportDelta) -> str:
    """Render the report comparison as terminal text."""

    lines = ["Report comparison", ""] + _delta_header(delta) + [""]
    lines.append(f"REGRESSIONS ({len(delta.regressions)})")
    for old_finding, new_finding in delta.regressions:
        lines.append(
            f"  {new_finding.rule.rule_id:<8} {old_finding.status.value} -> "
            f"{new_finding.status.value}  {new_finding.rule.title}"
        )
        lines.append(f"           evidence: {new_finding.evidence}")
    lines.append("")
    lines.append(f"FIXES ({len(delta.fixes)})")
    for old_finding, new_finding in delta.fixes:
        lines.append(
            f"  {new_finding.rule.rule_id:<8} {old_finding.status.value} -> "
            f"{new_finding.status.value}  {new_finding.rule.title}"
        )
    lines.append("")
    if delta.added:
        lines.append(f"NEW RULES ({len(delta.added)})")
        for finding in delta.added:
            lines.append(f"  {finding.rule.rule_id:<8} {finding.status.value}  {finding.rule.title}")
        lines.append("")
    if delta.removed:
        lines.append(f"REMOVED RULES ({len(delta.removed)})")
        for finding in delta.removed:
            lines.append(f"  {finding.rule.rule_id:<8} {finding.status.value}  {finding.rule.title}")
        lines.append("")
    if not any((delta.regressions, delta.fixes, delta.added, delta.removed)):
        lines.append("No rule-level changes between the two reports.")
    return "\n".join(lines) + "\n"


def delta_to_markdown(delta: ReportDelta) -> str:
    """Render the report comparison as Markdown."""

    lines = ["# Baseline audit comparison", ""]
    for line in _delta_header(delta):
        lines.append(f"- {line}")
    lines.extend(["", "## Regressions", ""])
    if delta.regressions:
        lines.extend(["| Rule | Before | After | Evidence |", "| --- | --- | --- | --- |"])
        for old_finding, new_finding in delta.regressions:
            lines.append(
                f"| `{new_finding.rule.rule_id}` | {old_finding.status.value} | "
                f"**{new_finding.status.value}** | {_md_cell(new_finding.evidence)} |"
            )
    else:
        lines.append("No regressions.")
    lines.extend(["", "## Fixes", ""])
    if delta.fixes:
        lines.extend(["| Rule | Before | After |", "| --- | --- | --- |"])
        for old_finding, new_finding in delta.fixes:
            lines.append(
                f"| `{new_finding.rule.rule_id}` | {old_finding.status.value} | "
                f"{new_finding.status.value} |"
            )
    else:
        lines.append("No fixes.")
    return "\n".join(lines) + "\n"
