"""Rule implementations, one module per audit category.

Each module exposes:

* ``CATEGORY`` — the category name used by the report and the CLI filters;
* ``RULES`` — the static rule catalogue;
* ``run(target)`` — evaluate every rule against an :class:`~baseaudit.target.AuditTarget`.
"""
