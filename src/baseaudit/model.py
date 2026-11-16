"""Data model shared by every baseline check and every report writer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, Mapping, Sequence

#: Canonical category order used in reports and in the CLI.
CATEGORIES: tuple[str, ...] = (
    "ssh",
    "users",
    "permissions",
    "sysctl",
    "services",
    "firewall",
    "updates",
)

CATEGORY_TITLES: Mapping[str, str] = {
    "ssh": "SSH server hardening",
    "users": "Accounts and privileges",
    "permissions": "File permissions",
    "sysctl": "Kernel network hardening",
    "services": "Services and systemd units",
    "firewall": "Host firewall",
    "updates": "Patch management",
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_WEIGHT = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


class Status(str, Enum):
    """Outcome of a single rule evaluation."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"

    @property
    def is_evaluated(self) -> bool:
        """Return ``True`` when the rule produced a compliance decision."""

        return self is not Status.SKIP


class Severity(str, Enum):
    """Business impact of a rule, used for gating and for the score."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank, higher means more severe."""

        return _SEVERITY_RANK[self.value]

    @property
    def weight(self) -> int:
        """Weight used when computing the weighted compliance score."""

        return _SEVERITY_WEIGHT[self.value]

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        """Parse a severity from a case-insensitive name."""

        try:
            return cls(name.strip().lower())
        except ValueError as exc:  # pragma: no cover - guarded by argparse
            raise ValueError(f"unknown severity: {name!r}") from exc


@dataclass(frozen=True)
class Rule:
    """Static description of a single baseline rule."""

    rule_id: str
    title: str
    category: str
    severity: Severity
    remediation: str
    reference: str = ""


@dataclass(frozen=True)
class Finding:
    """Result of evaluating one rule against one target."""

    rule: Rule
    status: Status
    evidence: str
    details: tuple[str, ...] = ()

    @classmethod
    def of(
        cls,
        rule: Rule,
        status: Status,
        evidence: str,
        details: Sequence[str] = (),
    ) -> "Finding":
        """Build a finding with an immutable details tuple."""

        return cls(rule=rule, status=status, evidence=evidence, details=tuple(details))


@dataclass
class AuditReport:
    """Complete result of an audit run."""

    target: str
    platform: str
    generated_at: str
    findings: list[Finding] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        target: str,
        platform: str,
        findings: Iterable[Finding],
        generated_at: datetime | None = None,
    ) -> "AuditReport":
        """Assemble a report, sorting findings in canonical category order."""

        category_index = {name: index for index, name in enumerate(CATEGORIES)}
        ordered = sorted(
            findings,
            key=lambda finding: (
                category_index.get(finding.rule.category, len(CATEGORIES)),
                finding.rule.rule_id,
            ),
        )
        stamp = generated_at or datetime.now(timezone.utc)
        return cls(
            target=target,
            platform=platform,
            generated_at=stamp.isoformat(timespec="seconds"),
            findings=ordered,
        )

    def counts(self) -> dict[str, int]:
        """Return the number of findings per status."""

        result = {status.value: 0 for status in Status}
        for finding in self.findings:
            result[finding.status.value] += 1
        return result

    def evaluated(self) -> int:
        """Return the number of rules that produced a decision."""

        return sum(1 for finding in self.findings if finding.status.is_evaluated)

    def failures(self) -> list[Finding]:
        """Return only the failed findings."""

        return [finding for finding in self.findings if finding.status is Status.FAIL]

    def warnings(self) -> list[Finding]:
        """Return only the findings that need attention but are not failures."""

        return [finding for finding in self.findings if finding.status is Status.WARN]

    def severity_counts(self) -> dict[str, int]:
        """Return failure counts per severity (WARN is reported separately)."""

        result = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            if finding.status in (Status.FAIL, Status.WARN):
                result[finding.rule.severity.value] += 1
        return result

    def category_counts(self) -> dict[str, dict[str, int]]:
        """Return per-category status counts."""

        result: dict[str, dict[str, int]] = {}
        for category in CATEGORIES:
            result[category] = {status.value: 0 for status in Status}
        for finding in self.findings:
            bucket = result.setdefault(
                finding.rule.category, {status.value: 0 for status in Status}
            )
            bucket[finding.status.value] += 1
        return result

    def score(self) -> int:
        """Return a weighted compliance score between 0 and 100.

        Each evaluated rule contributes its severity weight; a passing rule
        earns full credit, a warning earns half credit, a failure earns none.
        ``SKIP`` rules are excluded from the denominator.
        """

        earned = 0
        total = 0
        for finding in self.findings:
            if not finding.status.is_evaluated:
                continue
            weight = finding.rule.severity.weight
            total += weight
            if finding.status is Status.PASS:
                earned += weight
            elif finding.status is Status.WARN:
                earned += weight / 2
        if total == 0:
            return 0
        return int(round(100 * earned / total))

    def status_of(self, rule_id: str) -> Status | None:
        """Return the status of a rule by id, or ``None`` when not present."""

        for finding in self.findings:
            if finding.rule.rule_id == rule_id:
                return finding.status
        return None

    def has_failures_at_or_above(self, severity: Severity) -> bool:
        """Return ``True`` when a failure exists at or above ``severity``."""

        threshold = severity.rank
        return any(
            finding.status is Status.FAIL
            and finding.rule.severity.rank >= threshold
            for finding in self.findings
        )
