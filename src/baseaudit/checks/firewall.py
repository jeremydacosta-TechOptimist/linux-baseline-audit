"""Host firewall checks (ufw, nftables, iptables persistence)."""

from __future__ import annotations

from ..model import Finding, Rule, Severity, Status
from ..parsers import parse_ufw
from ..target import AuditTarget
from .services import enabled_units

CATEGORY = "firewall"

FW_01 = Rule(
    "FW-01",
    "Host firewall is active",
    CATEGORY,
    Severity.HIGH,
    "Enable the host firewall (ufw enable, nftables or iptables-persistent) with a default deny policy.",
    "CIS 3.5.1",
)
FW_02 = Rule(
    "FW-02",
    "Default inbound policy is deny",
    CATEGORY,
    Severity.HIGH,
    'Set DEFAULT_INPUT_POLICY="DROP" in /etc/default/ufw or "policy drop" in nftables.',
    "CIS 3.5.2",
)
FW_03 = Rule(
    "FW-03",
    "Firewall configuration is enabled at boot",
    CATEGORY,
    Severity.MEDIUM,
    "systemctl enable ufw.service (or nftables.service / netfilter-persistent.service).",
    "CIS 3.5.1",
)

RULES = (FW_01, FW_02, FW_03)

_BOOT_UNITS = frozenset(
    {"ufw.service", "nftables.service", "iptables.service", "netfilter-persistent.service"}
)


class _FirewallState:
    """Detection result for the firewall technologies present in the target."""

    def __init__(self, target: AuditTarget) -> None:
        self.ufw = parse_ufw(
            target.read_text("etc/ufw/ufw.conf"),
            target.read_text("etc/default/ufw"),
        )
        self.nftables = target.read_text("etc/nftables.conf")
        self.iptables = target.read_text("etc/iptables/rules.v4") or target.read_text(
            "etc/sysconfig/iptables"
        )
        self.ufw_files_present = (
            self.ufw.enabled is not None or self.ufw.default_input_policy is not None
        )

    @property
    def present(self) -> bool:
        return (
            self.ufw_files_present
            or self.nftables is not None
            or self.iptables is not None
        )

    @property
    def active(self) -> bool:
        if self.ufw.enabled:
            return True
        text = self.nftables
        if text is not None and "table" in text and "chain" in text:
            return True
        rules = (self.iptables or "").strip()
        return bool(rules)


def run(target: AuditTarget) -> list[Finding]:
    """Evaluate the firewall category against ``target``."""

    state = _FirewallState(target)
    findings: list[Finding] = []

    # FW-01 — active firewall.
    if state.ufw.enabled:
        findings.append(Finding.of(FW_01, Status.PASS, "ufw reports ENABLED=yes"))
    elif state.active:
        technology = (
            "nftables"
            if state.nftables is not None and "table" in (state.nftables or "")
            else "iptables"
        )
        findings.append(Finding.of(FW_01, Status.PASS, f"{technology} ruleset is present"))
    elif state.ufw.enabled is False:
        findings.append(
            Finding.of(FW_01, Status.FAIL, "ufw is configured but disabled (ENABLED=no)")
        )
    elif state.nftables is not None:
        findings.append(
            Finding.of(FW_01, Status.FAIL, "nftables configuration present but no table/chain rules")
        )
    elif state.iptables is not None:
        findings.append(Finding.of(FW_01, Status.FAIL, "iptables rules file present but empty"))
    else:
        findings.append(
            Finding.of(
                FW_01,
                Status.SKIP,
                "no ufw, nftables or iptables configuration found under the audit root",
            )
        )

    # FW-02 — default inbound policy.
    if state.ufw.default_input_policy is not None:
        policy = state.ufw.default_input_policy
        status = Status.PASS if policy in ("DROP", "REJECT") else Status.FAIL
        findings.append(Finding.of(FW_02, status, f"DEFAULT_INPUT_POLICY={policy}"))
    elif state.nftables is not None:
        if "policy drop" in state.nftables:
            findings.append(Finding.of(FW_02, Status.PASS, "nftables chains use policy drop"))
        else:
            findings.append(
                Finding.of(FW_02, Status.WARN, "nftables ruleset has no explicit 'policy drop'")
            )
    elif state.iptables is not None:
        findings.append(
            Finding.of(FW_02, Status.SKIP, "cannot infer the policy from an iptables rules file")
        )
    else:
        findings.append(Finding.of(FW_02, Status.SKIP, "no firewall configuration to inspect"))

    # FW-03 — persistence across reboots.
    if not state.present:
        findings.append(Finding.of(FW_03, Status.SKIP, "no firewall configuration to inspect"))
    else:
        units = enabled_units(target)
        boot = sorted(units & _BOOT_UNITS)
        if boot:
            findings.append(Finding.of(FW_03, Status.PASS, f"enabled at boot via {', '.join(boot)}"))
        else:
            findings.append(
                Finding.of(FW_03, Status.WARN, "no firewall management unit is enabled")
            )

    return findings
