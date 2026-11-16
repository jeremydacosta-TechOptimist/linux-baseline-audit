"""Patch management checks (automatic updates and metadata freshness)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..model import Finding, Rule, Severity, Status
from ..parsers import parse_apt_config, parse_key_value_file
from ..target import AuditTarget

CATEGORY = "updates"

UPD_01 = Rule(
    "UPD-01",
    "Automatic updates are enabled",
    CATEGORY,
    Severity.HIGH,
    "Enable unattended-upgrades (APT) or dnf-automatic so security patches apply automatically.",
    "CIS 1.9",
)
UPD_02 = Rule(
    "UPD-02",
    "Package metadata is fresh",
    CATEGORY,
    Severity.LOW,
    "Run 'apt update' or 'dnf makecache' regularly; stale metadata hides available fixes.",
    "CIS 1.9",
)

RULES = (UPD_01, UPD_02)

_STALENESS_LIMIT_DAYS = 7
_METADATA_CANDIDATES = (
    "var/lib/apt/periodic/update-success-stamp",
    "var/cache/apt/pkgcache.bin",
)


def _read_paths(target: AuditTarget, pattern: str) -> list[Path]:
    return target.glob(pattern)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _apt_settings(target: AuditTarget) -> dict[str, str]:
    merged: dict[str, str] = {}
    for path in _read_paths(target, "etc/apt/apt.conf.d/*"):
        text = _read_text(path)
        if text is not None:
            merged.update(parse_apt_config(text))
    return merged


def _dnf_settings(target: AuditTarget) -> dict[str, str] | None:
    text = target.read_text("etc/dnf/automatic.conf")
    if text is None:
        return None
    return parse_key_value_file(text)


def run(target: AuditTarget, now: datetime | None = None) -> list[Finding]:
    """Evaluate patch management rules against ``target``.

    ``now`` is injectable so tests can control the metadata-age computation.
    """

    moment = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    # UPD-01 — automatic updates.
    apt = _apt_settings(target)
    dnf = _dnf_settings(target)
    if apt:
        update_lists = apt.get("APT::Periodic::Update-Package-Lists")
        unattended = apt.get("APT::Periodic::Unattended-Upgrade")
        if update_lists == "1" and unattended == "1":
            findings.append(
                Finding.of(
                    UPD_01,
                    Status.PASS,
                    "apt periodic update lists and unattended upgrades are enabled",
                )
            )
        else:
            findings.append(
                Finding.of(
                    UPD_01,
                    Status.FAIL,
                    "APT::Periodic::Update-Package-Lists="
                    f"{update_lists or 'unset'}, APT::Periodic::Unattended-Upgrade="
                    f"{unattended or 'unset'}",
                )
            )
    elif dnf is not None:
        apply_updates = dnf.get("apply_updates", "no").strip().lower()
        if apply_updates in ("yes", "true", "1"):
            findings.append(
                Finding.of(UPD_01, Status.PASS, "dnf-automatic apply_updates=yes")
            )
        else:
            findings.append(
                Finding.of(UPD_01, Status.FAIL, f"dnf-automatic apply_updates={apply_updates}")
            )
    else:
        findings.append(
            Finding.of(
                UPD_01,
                Status.SKIP,
                "no APT or DNF automatic-update configuration found under the audit root",
            )
        )

    # UPD-02 — metadata freshness.
    timestamp: float | None = None
    source = ""
    for relative in _METADATA_CANDIDATES:
        info = target.stat(relative)
        if info is not None:
            timestamp = info.st_mtime
            source = relative
            break
    if timestamp is None:
        findings.append(
            Finding.of(
                UPD_02,
                Status.SKIP,
                "no package metadata timestamp found under the audit root",
            )
        )
    else:
        last_update = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        age_days = (moment - last_update).total_seconds() / 86400
        if age_days <= _STALENESS_LIMIT_DAYS:
            findings.append(
                Finding.of(
                    UPD_02,
                    Status.PASS,
                    f"last metadata refresh {age_days:.1f} day(s) ago ({source})",
                )
            )
        else:
            findings.append(
                Finding.of(
                    UPD_02,
                    Status.WARN,
                    f"metadata is {age_days:.1f} day(s) old (limit {_STALENESS_LIMIT_DAYS}) — {source}",
                )
            )

    return findings
