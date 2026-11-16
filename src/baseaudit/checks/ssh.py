"""SSH server (sshd) configuration hardening checks."""

from __future__ import annotations

import re

from ..model import Finding, Rule, Severity, Status
from ..parsers import parse_ssh_config, ssh_value
from ..target import AuditTarget

CATEGORY = "ssh"

SSH_01 = Rule(
    "SSH-01",
    "SSH root login is disabled",
    CATEGORY,
    Severity.CRITICAL,
    "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload sshd.",
    "CIS 5.2.8",
)
SSH_02 = Rule(
    "SSH-02",
    "Password authentication is disabled",
    CATEGORY,
    Severity.HIGH,
    "Set 'PasswordAuthentication no' and rely on per-user SSH keys.",
    "CIS 5.2.10",
)
SSH_03 = Rule(
    "SSH-03",
    "Empty passwords are refused",
    CATEGORY,
    Severity.CRITICAL,
    "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.",
    "CIS 5.2.9",
)
SSH_04 = Rule(
    "SSH-04",
    "MaxAuthTries is 4 or lower",
    CATEGORY,
    Severity.MEDIUM,
    "Set 'MaxAuthTries 4' to slow down credential guessing.",
    "CIS 5.2.7",
)
SSH_05 = Rule(
    "SSH-05",
    "X11 forwarding is disabled",
    CATEGORY,
    Severity.LOW,
    "Set 'X11Forwarding no'; forward X11 over a tunnel only when needed.",
    "CIS 5.2.6",
)
SSH_06 = Rule(
    "SSH-06",
    "LoginGraceTime is 60 seconds or less",
    CATEGORY,
    Severity.MEDIUM,
    "Set 'LoginGraceTime 60' in /etc/ssh/sshd_config.",
    "CIS 5.2.16",
)
SSH_07 = Rule(
    "SSH-07",
    "A login banner is configured",
    CATEGORY,
    Severity.LOW,
    "Set 'Banner /etc/issue.net' and provide an approved warning banner.",
    "CIS 5.2.18",
)
SSH_08 = Rule(
    "SSH-08",
    "Client keep-alive is enabled",
    CATEGORY,
    Severity.LOW,
    "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3'.",
    "CIS 5.2.20",
)
SSH_09 = Rule(
    "SSH-09",
    "sshd_config is not writable by group or others",
    CATEGORY,
    Severity.HIGH,
    "chmod 600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config",
    "CIS 5.2.1",
)

RULES = (SSH_01, SSH_02, SSH_03, SSH_04, SSH_05, SSH_06, SSH_07, SSH_08, SSH_09)

_DURATION_RE = re.compile(r"^(?P<value>\d+)\s*(?P<unit>[smh]?)$")
_INTERACTIVE_SHELLS = frozenset(
    {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ksh", "/bin/csh", "/bin/tcsh"}
)


def _load_config(target: AuditTarget) -> dict[str, list[str]] | None:
    """Read ``sshd_config`` and merge its ``Include`` drop-ins.

    sshd keeps the *first* value seen for a keyword, so the base file is
    processed first and drop-ins are appended after it.
    """

    text = target.read_text("etc/ssh/sshd_config")
    if text is None:
        return None
    config = parse_ssh_config(text)
    includes = config.pop("include", [])
    for pattern in includes:
        for path in target.glob(pattern.lstrip("/")):
            try:
                drop_in = parse_ssh_config(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            drop_in.pop("include", None)
            for key, values in drop_in.items():
                config.setdefault(key, []).extend(values)
    return config


def _parse_duration(value: str) -> int | None:
    """Parse an sshd duration such as ``60``, ``2m`` or ``1h`` into seconds."""

    match = _DURATION_RE.match(value.strip())
    if not match:
        return None
    amount = int(match.group("value"))
    unit = match.group("unit") or "s"
    return amount * {"s": 1, "m": 60, "h": 3600}[unit]


def _skip_all(evidence: str) -> list[Finding]:
    return [Finding.of(rule, Status.SKIP, evidence) for rule in RULES]


def run(target: AuditTarget) -> list[Finding]:
    """Evaluate the SSH category against ``target``."""

    config = _load_config(target)
    if config is None:
        return _skip_all("sshd_config not found under the audit root")

    findings: list[Finding] = []

    # SSH-01 — root login
    value = ssh_value(config, "permitrootlogin")
    if value is None:
        findings.append(
            Finding.of(
                SSH_01,
                Status.WARN,
                "PermitRootLogin is not configured (OpenSSH default: prohibit-password)",
            )
        )
    elif value.lower() == "no":
        findings.append(Finding.of(SSH_01, Status.PASS, "PermitRootLogin no"))
    elif value.lower() in ("prohibit-password", "without-password", "forced-commands-only"):
        findings.append(
            Finding.of(
                SSH_01,
                Status.WARN,
                f"PermitRootLogin {value} — root may still log in with a key",
            )
        )
    else:
        findings.append(Finding.of(SSH_01, Status.FAIL, f"PermitRootLogin {value}"))

    # SSH-02 — password authentication
    value = ssh_value(config, "passwordauthentication")
    if value is None:
        findings.append(
            Finding.of(
                SSH_02,
                Status.WARN,
                "PasswordAuthentication is not configured (OpenSSH default: yes)",
            )
        )
    elif value.lower() == "no":
        findings.append(Finding.of(SSH_02, Status.PASS, "PasswordAuthentication no"))
    else:
        findings.append(Finding.of(SSH_02, Status.FAIL, f"PasswordAuthentication {value}"))

    # SSH-03 — empty passwords
    value = ssh_value(config, "permitemptypasswords")
    if value is None:
        findings.append(
            Finding.of(SSH_03, Status.PASS, "PermitEmptyPasswords not set (default: no)")
        )
    elif value.lower() == "no":
        findings.append(Finding.of(SSH_03, Status.PASS, "PermitEmptyPasswords no"))
    else:
        findings.append(Finding.of(SSH_03, Status.FAIL, f"PermitEmptyPasswords {value}"))

    # SSH-04 — MaxAuthTries
    value = ssh_value(config, "maxauthtries")
    if value is None:
        findings.append(
            Finding.of(SSH_04, Status.WARN, "MaxAuthTries is not configured (default: 6)")
        )
    else:
        try:
            attempts = int(value)
        except ValueError:
            findings.append(Finding.of(SSH_04, Status.WARN, f"MaxAuthTries {value!r} is not a number"))
        else:
            status = Status.PASS if attempts <= 4 else Status.FAIL
            findings.append(Finding.of(SSH_04, status, f"MaxAuthTries {attempts}"))

    # SSH-05 — X11 forwarding
    value = ssh_value(config, "x11forwarding")
    if value is None:
        findings.append(
            Finding.of(SSH_05, Status.PASS, "X11Forwarding not set (default: no)")
        )
    elif value.lower() == "no":
        findings.append(Finding.of(SSH_05, Status.PASS, "X11Forwarding no"))
    else:
        findings.append(Finding.of(SSH_05, Status.FAIL, f"X11Forwarding {value}"))

    # SSH-06 — LoginGraceTime
    value = ssh_value(config, "logingracetime")
    if value is None:
        findings.append(
            Finding.of(SSH_06, Status.WARN, "LoginGraceTime is not configured (default: 120s)")
        )
    else:
        seconds = _parse_duration(value)
        if seconds is None:
            findings.append(Finding.of(SSH_06, Status.WARN, f"LoginGraceTime {value!r} is not a duration"))
        elif seconds == 0:
            findings.append(Finding.of(SSH_06, Status.WARN, "LoginGraceTime 0 disables the timeout"))
        else:
            status = Status.PASS if seconds <= 60 else Status.FAIL
            findings.append(Finding.of(SSH_06, status, f"LoginGraceTime {seconds}s"))

    # SSH-07 — banner
    value = ssh_value(config, "banner")
    if value is None or value.lower() == "none":
        findings.append(Finding.of(SSH_07, Status.FAIL, "No login banner configured"))
    else:
        findings.append(Finding.of(SSH_07, Status.PASS, f"Banner {value}"))

    # SSH-08 — client keep-alive
    value = ssh_value(config, "clientaliveinterval")
    if value is None:
        findings.append(
            Finding.of(SSH_08, Status.WARN, "ClientAliveInterval is not configured")
        )
    else:
        seconds = _parse_duration(value)
        if seconds is None or seconds == 0:
            findings.append(Finding.of(SSH_08, Status.WARN, f"ClientAliveInterval {value}"))
        else:
            findings.append(Finding.of(SSH_08, Status.PASS, f"ClientAliveInterval {seconds}s"))

    # SSH-09 — configuration file permissions
    if not target.is_posix:
        findings.append(
            Finding.of(
                SSH_09,
                Status.SKIP,
                "POSIX file modes are not available on this platform",
            )
        )
    else:
        info = target.stat("etc/ssh/sshd_config")
        if info is None:
            findings.append(Finding.of(SSH_09, Status.SKIP, "sshd_config is not a regular file"))
        else:
            mode = info.st_mode & 0o777
            status = Status.PASS if mode & 0o022 == 0 else Status.FAIL
            findings.append(Finding.of(SSH_09, status, f"mode {mode:04o}"))

    return findings
