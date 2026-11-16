"""Kernel network hardening checks driven by sysctl configuration files."""

from __future__ import annotations

from ..model import Finding, Rule, Severity, Status
from ..parsers import parse_sysctl
from ..target import AuditTarget

CATEGORY = "sysctl"

SYS_01 = Rule(
    "SYS-01",
    "IP forwarding is disabled",
    CATEGORY,
    Severity.MEDIUM,
    "Set net.ipv4.ip_forward = 0 unless the host is a router.",
    "CIS 3.1.1",
)
SYS_02 = Rule(
    "SYS-02",
    "Source routing is disabled",
    CATEGORY,
    Severity.MEDIUM,
    "Set net.ipv4.conf.all.accept_source_route = 0.",
    "CIS 3.2.1",
)
SYS_03 = Rule(
    "SYS-03",
    "ICMP redirects are not accepted",
    CATEGORY,
    Severity.MEDIUM,
    "Set net.ipv4.conf.all.accept_redirects = 0.",
    "CIS 3.2.2",
)
SYS_04 = Rule(
    "SYS-04",
    "ICMP redirects are not sent",
    CATEGORY,
    Severity.MEDIUM,
    "Set net.ipv4.conf.all.send_redirects = 0.",
    "CIS 3.2.3",
)
SYS_05 = Rule(
    "SYS-05",
    "Reverse path filtering is enabled",
    CATEGORY,
    Severity.LOW,
    "Set net.ipv4.conf.all.rp_filter = 1.",
    "CIS 3.2.7",
)
SYS_06 = Rule(
    "SYS-06",
    "TCP SYN cookies are enabled",
    CATEGORY,
    Severity.HIGH,
    "Set net.ipv4.tcp_syncookies = 1.",
    "CIS 3.2.8",
)
SYS_07 = Rule(
    "SYS-07",
    "Broadcast ICMP echo requests are ignored",
    CATEGORY,
    Severity.LOW,
    "Set net.ipv4.icmp_echo_ignore_broadcasts = 1.",
    "CIS 3.2.5",
)
SYS_08 = Rule(
    "SYS-08",
    "Hard link protection is enabled",
    CATEGORY,
    Severity.MEDIUM,
    "Set fs.protected_hardlinks = 1.",
    "CIS 1.6.1",
)
SYS_09 = Rule(
    "SYS-09",
    "Symlink protection is enabled",
    CATEGORY,
    Severity.MEDIUM,
    "Set fs.protected_symlinks = 1.",
    "CIS 1.6.2",
)
SYS_10 = Rule(
    "SYS-10",
    "Address space layout randomisation is enabled",
    CATEGORY,
    Severity.HIGH,
    "Set kernel.randomize_va_space = 2.",
    "CIS 1.5.1",
)

RULES = (SYS_01, SYS_02, SYS_03, SYS_04, SYS_05, SYS_06, SYS_07, SYS_08, SYS_09, SYS_10)

EXPECTATIONS: tuple[tuple[Rule, str, str], ...] = (
    (SYS_01, "net.ipv4.ip_forward", "0"),
    (SYS_02, "net.ipv4.conf.all.accept_source_route", "0"),
    (SYS_03, "net.ipv4.conf.all.accept_redirects", "0"),
    (SYS_04, "net.ipv4.conf.all.send_redirects", "0"),
    (SYS_05, "net.ipv4.conf.all.rp_filter", "1"),
    (SYS_06, "net.ipv4.tcp_syncookies", "1"),
    (SYS_07, "net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    (SYS_08, "fs.protected_hardlinks", "1"),
    (SYS_09, "fs.protected_symlinks", "1"),
    (SYS_10, "kernel.randomize_va_space", "2"),
)


def _read_path(target: AuditTarget, relative: str) -> str | None:
    return target.read_text(relative)


def _load_sysctl(target: AuditTarget) -> dict[str, str] | None:
    """Merge ``/etc/sysctl.d/*.conf`` then ``/etc/sysctl.conf`` (last wins)."""

    merged: dict[str, str] = {}
    sources = target.glob("etc/sysctl.d/*.conf")
    for path in sources:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        merged.update(parse_sysctl(text))
    override = _read_path(target, "etc/sysctl.conf")
    if override is not None:
        merged.update(parse_sysctl(override))
    if not merged and not sources and override is None:
        return None
    return merged


def run(target: AuditTarget) -> list[Finding]:
    """Evaluate the sysctl category against ``target``."""

    values = _load_sysctl(target)
    if values is None:
        return [
            Finding.of(
                rule,
                Status.SKIP,
                "no /etc/sysctl.conf or /etc/sysctl.d/*.conf found under the audit root",
            )
            for rule in RULES
        ]

    findings: list[Finding] = []
    for rule, key, expected in EXPECTATIONS:
        raw = values.get(key)
        if raw is None:
            findings.append(
                Finding.of(
                    rule,
                    Status.WARN,
                    f"{key} is not set in any sysctl configuration file",
                )
            )
            continue
        value = raw.strip().split()[0]
        if value == expected:
            findings.append(Finding.of(rule, Status.PASS, f"{key} = {value}"))
        elif key == "net.ipv4.ip_forward" and value == "1":
            findings.append(
                Finding.of(
                    rule,
                    Status.WARN,
                    f"{key} = 1 (expected 0; legitimate on routers and NAT gateways)",
                )
            )
        else:
            findings.append(
                Finding.of(rule, Status.FAIL, f"{key} = {value} (expected {expected})")
            )
    return findings
