"""File permission checks for security sensitive configuration files."""

from __future__ import annotations

from dataclasses import dataclass

from ..model import Finding, Rule, Severity, Status
from ..target import AuditTarget

CATEGORY = "permissions"


@dataclass(frozen=True)
class PermissionRule:
    """A rule bound to a path and to the most permissive allowed mode."""

    rule: Rule
    path: str
    allowed: int


PERM_PASSWD = PermissionRule(
    Rule(
        "PERM-01",
        "/etc/passwd is not writable by group or others",
        CATEGORY,
        Severity.MEDIUM,
        "chmod 644 /etc/passwd && chown root:root /etc/passwd",
        "CIS 6.1.2",
    ),
    "etc/passwd",
    0o644,
)
PERM_SHADOW = PermissionRule(
    Rule(
        "PERM-02",
        "/etc/shadow is restricted to root",
        CATEGORY,
        Severity.HIGH,
        "chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
        "CIS 6.1.3",
    ),
    "etc/shadow",
    0o640,
)
PERM_GROUP = PermissionRule(
    Rule(
        "PERM-03",
        "/etc/group is not writable by group or others",
        CATEGORY,
        Severity.MEDIUM,
        "chmod 644 /etc/group && chown root:root /etc/group",
        "CIS 6.1.4",
    ),
    "etc/group",
    0o644,
)
PERM_GSHADOW = PermissionRule(
    Rule(
        "PERM-04",
        "/etc/gshadow is restricted to root",
        CATEGORY,
        Severity.HIGH,
        "chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow",
        "CIS 6.1.5",
    ),
    "etc/gshadow",
    0o640,
)
PERM_SSHD = PermissionRule(
    Rule(
        "PERM-05",
        "sshd_config is restricted to root",
        CATEGORY,
        Severity.HIGH,
        "chmod 600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config",
        "CIS 5.2.1",
    ),
    "etc/ssh/sshd_config",
    0o644,
)
PERM_SUDOERS = PermissionRule(
    Rule(
        "PERM-06",
        "sudoers is read-only for root",
        CATEGORY,
        Severity.HIGH,
        "chmod 440 /etc/sudoers && chown root:root /etc/sudoers",
        "CIS 5.3.1",
    ),
    "etc/sudoers",
    0o440,
)

SPECS: tuple[PermissionRule, ...] = (
    PERM_PASSWD,
    PERM_SHADOW,
    PERM_GROUP,
    PERM_GSHADOW,
    PERM_SSHD,
    PERM_SUDOERS,
)

RULES = tuple(spec.rule for spec in SPECS)


def run(target: AuditTarget) -> list[Finding]:
    """Evaluate file permission rules against ``target``."""

    findings: list[Finding] = []
    for spec in SPECS:
        if not target.is_posix:
            findings.append(
                Finding.of(
                    spec.rule,
                    Status.SKIP,
                    "POSIX file modes are not available on this platform",
                )
            )
            continue
        info = target.stat(spec.path)
        if info is None:
            findings.append(
                Finding.of(spec.rule, Status.SKIP, f"{spec.path} not present under the audit root")
            )
            continue
        mode = info.st_mode & 0o777
        if mode & ~spec.allowed == 0:
            findings.append(
                Finding.of(
                    spec.rule,
                    Status.PASS,
                    f"/{spec.path} mode {mode:04o} (allowed at most {spec.allowed:04o})",
                )
            )
        else:
            findings.append(
                Finding.of(
                    spec.rule,
                    Status.FAIL,
                    f"/{spec.path} mode {mode:04o} exceeds {spec.allowed:04o}",
                )
            )
    return findings
