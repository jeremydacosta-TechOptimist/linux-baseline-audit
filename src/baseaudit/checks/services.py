"""Service exposure checks based on the on-disk systemd unit state."""

from __future__ import annotations

from ..model import Finding, Rule, Severity, Status
from ..target import AuditTarget

CATEGORY = "services"

SVC_01 = Rule(
    "SVC-01",
    "SSH service is enabled",
    CATEGORY,
    Severity.HIGH,
    "systemctl enable --now sshd (or ssh) so remote administration stays available.",
    "CIS 5.1.1",
)
SVC_02 = Rule(
    "SVC-02",
    "Insecure remote services are disabled",
    CATEGORY,
    Severity.CRITICAL,
    "Disable telnet, rsh, rlogin, tftp, vsftpd and xinetd units.",
    "CIS 2.1.7",
)
SVC_03 = Rule(
    "SVC-03",
    "Discovery and printing services are not enabled",
    CATEGORY,
    Severity.LOW,
    "Disable avahi-daemon and cups on servers that do not need them.",
    "CIS 2.2.4",
)
SVC_04 = Rule(
    "SVC-04",
    "RPC bind services are not enabled",
    CATEGORY,
    Severity.MEDIUM,
    "Disable rpcbind unless the host exports NFS.",
    "CIS 2.2.9",
)

RULES = (SVC_01, SVC_02, SVC_03, SVC_04)

_INSECURE_UNITS = frozenset(
    {
        "telnet.service",
        "telnet.socket",
        "rsh.service",
        "rsh.socket",
        "rlogin.service",
        "rlogin.socket",
        "rexec.service",
        "rexec.socket",
        "tftp.service",
        "tftp.socket",
        "vsftpd.service",
        "xinetd.service",
    }
)
_DISCOVERY_UNITS = frozenset(
    {"avahi-daemon.service", "avahi-daemon.socket", "cups.service", "cups.socket"}
)
_RPCBIND_UNITS = frozenset({"rpcbind.service", "rpcbind.socket"})


def enabled_units(target: AuditTarget) -> set[str]:
    """Return unit names linked into any ``*.wants`` directory."""

    units: set[str] = set()
    for path in target.glob("etc/systemd/system/*.wants/*"):
        units.add(path.name)
    return units


def has_systemd_tree(target: AuditTarget) -> bool:
    """Return ``True`` when the target contains systemd unit directories."""

    return target.is_dir("etc/systemd/system")


def run(target: AuditTarget) -> list[Finding]:
    """Evaluate the service exposure category against ``target``."""

    if not has_systemd_tree(target):
        return [
            Finding.of(
                rule,
                Status.SKIP,
                "no /etc/systemd/system directory found under the audit root",
            )
            for rule in RULES
        ]

    units = enabled_units(target)
    findings: list[Finding] = []

    # SVC-01 — SSH must stay enabled.
    if units & {"ssh.service", "sshd.service"}:
        findings.append(Finding.of(SVC_01, Status.PASS, "ssh/sshd unit is enabled"))
    else:
        findings.append(Finding.of(SVC_01, Status.FAIL, "no enabled ssh or sshd unit found"))

    # SVC-02 — insecure remote services.
    insecure = sorted(units & _INSECURE_UNITS)
    if insecure:
        findings.append(
            Finding.of(
                SVC_02,
                Status.FAIL,
                f"{len(insecure)} insecure service(s) enabled",
                insecure,
            )
        )
    else:
        findings.append(Finding.of(SVC_02, Status.PASS, "no insecure remote service enabled"))

    # SVC-03 — discovery and printing.
    discovery = sorted(units & _DISCOVERY_UNITS)
    if discovery:
        findings.append(
            Finding.of(
                SVC_03,
                Status.WARN,
                f"{len(discovery)} discovery/printing unit(s) enabled",
                discovery,
            )
        )
    else:
        findings.append(Finding.of(SVC_03, Status.PASS, "avahi and cups are not enabled"))

    # SVC-04 — rpcbind.
    rpcbind = sorted(units & _RPCBIND_UNITS)
    if rpcbind:
        findings.append(
            Finding.of(SVC_04, Status.WARN, f"{len(rpcbind)} rpcbind unit(s) enabled", rpcbind)
        )
    else:
        findings.append(Finding.of(SVC_04, Status.PASS, "rpcbind is not enabled"))

    return findings
