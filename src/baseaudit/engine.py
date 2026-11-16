"""Audit orchestration: pick the check modules, run them, build the report."""

from __future__ import annotations

from typing import Sequence

from .checks import firewall, permissions, services, ssh, sysctl, updates, users
from .model import CATEGORIES, AuditReport
from .target import AuditTarget

#: Check modules in canonical category order.
CHECK_MODULES = (ssh, users, permissions, sysctl, services, firewall, updates)


def available_categories() -> tuple[str, ...]:
    """Return the categories the engine can evaluate."""

    return tuple(module.CATEGORY for module in CHECK_MODULES)


def iter_rules():  # type: ignore[no-untyped-def]
    """Yield every :class:`~baseaudit.model.Rule` in canonical order."""

    for module in CHECK_MODULES:
        yield from module.RULES


def run_audit(
    target: AuditTarget,
    categories: Sequence[str] | None = None,
) -> AuditReport:
    """Run every selected check and return the aggregated report."""

    selected = set(categories) if categories else set(CATEGORIES)
    findings = []
    for module in CHECK_MODULES:
        if module.CATEGORY not in selected:
            continue
        findings.extend(module.run(target))
    return AuditReport.create(
        target=str(target.root),
        platform=target.platform,
        findings=findings,
    )
