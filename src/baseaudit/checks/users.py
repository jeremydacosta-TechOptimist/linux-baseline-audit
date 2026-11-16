"""Account and privilege checks (passwd, shadow, login.defs, sudoers)."""

from __future__ import annotations

from ..model import Finding, Rule, Severity, Status
from ..parsers import (
    parse_login_defs,
    parse_passwd,
    parse_shadow,
    parse_sudoers,
)
from ..target import AuditTarget

CATEGORY = "users"

USR_01 = Rule(
    "USR-01",
    "Only the root account has UID 0",
    CATEGORY,
    Severity.CRITICAL,
    "Remove or renumber every other account that shares UID 0.",
    "CIS 6.2.5",
)
USR_02 = Rule(
    "USR-02",
    "No account has an empty password",
    CATEGORY,
    Severity.CRITICAL,
    "Lock or set a strong password for every account with an empty shadow field.",
    "CIS 6.2.1",
)
USR_03 = Rule(
    "USR-03",
    "Password aging is enforced in login.defs",
    CATEGORY,
    Severity.MEDIUM,
    "Set PASS_MAX_DAYS<=365, PASS_MIN_DAYS>=1 and PASS_WARN_AGE>=7 in /etc/login.defs.",
    "CIS 5.4.1",
)
USR_04 = Rule(
    "USR-04",
    "UIDs are unique",
    CATEGORY,
    Severity.MEDIUM,
    "Give every account a distinct UID; duplicates break auditing and file ownership.",
    "CIS 6.2.6",
)
USR_05 = Rule(
    "USR-05",
    "System accounts have no interactive shell",
    CATEGORY,
    Severity.LOW,
    "Set the shell of system accounts to /usr/sbin/nologin.",
    "CIS 6.2.7",
)
USR_06 = Rule(
    "USR-06",
    "Sudo rules do not use NOPASSWD",
    CATEGORY,
    Severity.HIGH,
    "Remove NOPASSWD from /etc/sudoers and /etc/sudoers.d/*; require re-authentication.",
    "CIS 5.3.5",
)
USR_07 = Rule(
    "USR-07",
    "Sudo requires a pseudo-terminal",
    CATEGORY,
    Severity.MEDIUM,
    "Add 'Defaults use_pty' to /etc/sudoers.",
    "CIS 5.3.2",
)

RULES = (USR_01, USR_02, USR_03, USR_04, USR_05, USR_06, USR_07)

_INTERACTIVE_SHELLS = frozenset(
    {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ksh", "/bin/csh", "/bin/tcsh"}
)
_PSEUDO_UIDS = frozenset({65534, 65535})


def _as_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def run(target: AuditTarget) -> list[Finding]:
    """Evaluate the users category against ``target``."""

    passwd_text = target.read_text("etc/passwd")
    shadow_text = target.read_text("etc/shadow")
    login_defs_text = target.read_text("etc/login.defs")
    sudoers_text = target.read_text("etc/sudoers")

    accounts = parse_passwd(passwd_text) if passwd_text is not None else []
    shadow = parse_shadow(shadow_text) if shadow_text is not None else []
    login_defs = parse_login_defs(login_defs_text) if login_defs_text is not None else {}

    findings: list[Finding] = []

    # USR-01 — unique root account
    if passwd_text is None:
        findings.append(Finding.of(USR_01, Status.SKIP, "/etc/passwd not found under the audit root"))
    else:
        extra_roots = [
            account["name"]
            for account in accounts
            if account["uid"].strip() == "0" and account["name"] != "root"
        ]
        if extra_roots:
            findings.append(
                Finding.of(
                    USR_01,
                    Status.FAIL,
                    f"{len(extra_roots)} non-root account(s) share UID 0",
                    extra_roots,
                )
            )
        elif any(account["name"] == "root" for account in accounts):
            findings.append(Finding.of(USR_01, Status.PASS, "root is the only UID 0 account"))
        else:
            findings.append(Finding.of(USR_01, Status.WARN, "no root account found in /etc/passwd"))

    # USR-02 — empty passwords
    if shadow_text is None:
        findings.append(
            Finding.of(USR_02, Status.SKIP, "/etc/shadow absent or not readable")
        )
    else:
        empty_passwords = [entry["name"] for entry in shadow if entry["hash"] == ""]
        if empty_passwords:
            findings.append(
                Finding.of(
                    USR_02,
                    Status.FAIL,
                    f"{len(empty_passwords)} account(s) have an empty password hash",
                    empty_passwords,
                )
            )
        else:
            findings.append(
                Finding.of(USR_02, Status.PASS, "no empty password hashes in /etc/shadow")
            )

    # USR-03 — password aging
    if login_defs_text is None:
        findings.append(Finding.of(USR_03, Status.WARN, "/etc/login.defs not found"))
    else:
        max_days = _as_int(login_defs.get("PASS_MAX_DAYS"))
        min_days = _as_int(login_defs.get("PASS_MIN_DAYS"))
        warn_days = _as_int(login_defs.get("PASS_WARN_AGE"))
        if max_days is None or min_days is None or warn_days is None:
            missing = [
                name
                for name, value in (
                    ("PASS_MAX_DAYS", max_days),
                    ("PASS_MIN_DAYS", min_days),
                    ("PASS_WARN_AGE", warn_days),
                )
                if value is None
            ]
            findings.append(
                Finding.of(USR_03, Status.WARN, "missing aging settings", missing)
            )
        elif max_days <= 365 and min_days >= 1 and warn_days >= 7:
            findings.append(
                Finding.of(
                    USR_03,
                    Status.PASS,
                    f"PASS_MAX_DAYS={max_days}, PASS_MIN_DAYS={min_days}, PASS_WARN_AGE={warn_days}",
                )
            )
        else:
            findings.append(
                Finding.of(
                    USR_03,
                    Status.FAIL,
                    f"PASS_MAX_DAYS={max_days}, PASS_MIN_DAYS={min_days}, PASS_WARN_AGE={warn_days}",
                )
            )

    # USR-04 — duplicate UIDs
    if passwd_text is None:
        findings.append(Finding.of(USR_04, Status.SKIP, "/etc/passwd not found under the audit root"))
    else:
        by_uid: dict[str, list[str]] = {}
        for account in accounts:
            uid = _as_int(account["uid"])
            if uid is None or uid in _PSEUDO_UIDS:
                continue
            by_uid.setdefault(account["uid"], []).append(account["name"])
        duplicates = [
            f"UID {uid}: {', '.join(names)}" for uid, names in by_uid.items() if len(names) > 1
        ]
        if duplicates:
            findings.append(
                Finding.of(USR_04, Status.WARN, f"{len(duplicates)} duplicated UID(s)", duplicates)
            )
        else:
            findings.append(Finding.of(USR_04, Status.PASS, "all UIDs are unique"))

    # USR-05 — system accounts must not have an interactive shell
    if passwd_text is None:
        findings.append(Finding.of(USR_05, Status.SKIP, "/etc/passwd not found under the audit root"))
    else:
        uid_min = _as_int(login_defs.get("UID_MIN")) or 1000
        interactive = [
            f"{account['name']} (UID {account['uid']}, shell {account['shell']})"
            for account in accounts
            if account["name"] != "root"
            and (_as_int(account["uid"]) is not None and int(account["uid"]) < uid_min)
            and account["shell"] in _INTERACTIVE_SHELLS
        ]
        if interactive:
            findings.append(
                Finding.of(
                    USR_05,
                    Status.WARN,
                    f"{len(interactive)} system account(s) use an interactive shell",
                    interactive,
                )
            )
        else:
            findings.append(
                Finding.of(USR_05, Status.PASS, "system accounts use nologin/false shells")
            )

    # USR-06 — NOPASSWD rules (main file and drop-ins)
    sudoers_files: list[tuple[str, str]] = []
    if sudoers_text is not None:
        sudoers_files.append(("etc/sudoers", sudoers_text))
    for relative in ("etc/sudoers.d",):
        for path in target.glob(relative + "/*"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            sudoers_files.append((str(path.relative_to(target.root)).replace("\\", "/"), text))
    if not sudoers_files:
        findings.append(Finding.of(USR_06, Status.SKIP, "/etc/sudoers not found under the audit root"))
        findings.append(Finding.of(USR_07, Status.SKIP, "/etc/sudoers not found under the audit root"))
    else:
        nopasswd_lines: list[str] = []
        defaults: set[str] = set()
        for relative, text in sudoers_files:
            parsed = parse_sudoers(text)
            defaults.update(parsed["defaults"])  # type: ignore[arg-type]
            for number, line in parsed["nopasswd"]:  # type: ignore[union-attr]
                nopasswd_lines.append(f"{relative}:{number}: {line}")
        if nopasswd_lines:
            findings.append(
                Finding.of(
                    USR_06,
                    Status.FAIL,
                    f"{len(nopasswd_lines)} NOPASSWD sudo rule(s) found",
                    nopasswd_lines,
                )
            )
        else:
            findings.append(Finding.of(USR_06, Status.PASS, "no NOPASSWD sudo rules"))
        if "use_pty" in defaults:
            findings.append(Finding.of(USR_07, Status.PASS, "Defaults use_pty is set"))
        else:
            findings.append(
                Finding.of(USR_07, Status.WARN, "Defaults use_pty is missing from sudoers")
            )

    return findings
