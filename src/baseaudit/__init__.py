"""baseaudit — CIS-aligned Linux server baseline auditor.

The package is intentionally dependency free: every parser and check works
with the Python standard library only, so the auditor can be dropped on a
locked-down server or run from a workstation against an extracted snapshot.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
