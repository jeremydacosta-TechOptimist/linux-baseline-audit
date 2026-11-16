"""Abstraction over the directory tree that is being audited.

Every check receives an :class:`AuditTarget`; it never touches absolute paths
directly. That keeps the checks testable (a temporary fixture tree replaces
``/``) and makes the tool safe to run against a mounted snapshot.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path


class AuditTarget:
    """Read-only view of a filesystem tree rooted at ``root``."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()
        self.platform = platform.system()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AuditTarget):
            return NotImplemented
        return self.root == other.root

    def __hash__(self) -> int:
        return hash(self.root)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"AuditTarget({self.root!s})"

    @property
    def is_posix(self) -> bool:
        """Return ``True`` when POSIX metadata (modes, uids) is meaningful."""

        return os.name == "posix"

    def resolve(self, relative: str) -> Path:
        """Return the absolute path for a target-relative path."""

        cleaned = relative.lstrip("/\\")
        return self.root / cleaned

    def exists(self, relative: str) -> bool:
        """Return ``True`` when a target-relative path exists."""

        return self.resolve(relative).exists()

    def is_dir(self, relative: str) -> bool:
        """Return ``True`` when a target-relative path is a directory."""

        return self.resolve(relative).is_dir()

    def read_text(self, relative: str, max_bytes: int = 2_000_000) -> str | None:
        """Read a target-relative text file.

        Returns ``None`` when the file is missing, unreadable or larger than
        ``max_bytes``. Decoding is tolerant: configuration files occasionally
        contain non UTF-8 bytes and that must not crash an audit.
        """

        path = self.resolve(relative)
        try:
            if not path.is_file():
                return None
            if path.stat().st_size > max_bytes:
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def glob(self, pattern: str) -> list[Path]:
        """Return files matching a target-relative glob pattern, sorted."""

        try:
            return sorted(
                path for path in self.root.glob(pattern.lstrip("/\\")) if path.is_file()
            )
        except (OSError, ValueError):
            return []

    def stat(self, relative: str) -> os.stat_result | None:
        """Return ``os.stat`` for a target-relative path, or ``None``."""

        try:
            return self.resolve(relative).stat()
        except OSError:
            return None
