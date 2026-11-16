"""Small, dependency-free parsers for the configuration files the auditor reads.

The parsers deliberately avoid ``configparser``: real ``sshd_config``,
``sysctl``, APT and sudoers files are not INI files and a permissive
line-oriented parser is both simpler and more faithful.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_KV_RE = re.compile(r"^\s*(?P<key>[^=\s]+)\s*=\s*(?P<value>.*?)\s*$")
_APT_RE = re.compile(r'^\s*(?P<key>APT::[A-Za-z0-9:._-]+)\s+"?(?P<value>[^";]*)"?\s*;\s*$')


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def strip_comment(line: str, marker: str = "#") -> str:
    """Drop a trailing comment, keeping the value before the marker."""

    index = line.find(marker)
    if index == -1:
        return line
    return line[:index]


def parse_ssh_config(text: str) -> dict[str, list[str]]:
    """Parse ``sshd_config`` style text into ``{keyword: [values]}``.

    Keywords are lower-cased. SSH uses the *first* obtained value for most
    keywords, so callers should read the first element of each list.
    """

    result: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result.setdefault(key, []).append(value)
    return result


def ssh_value(config: dict[str, list[str]], key: str) -> str | None:
    """Return the first value for an sshd_config keyword, or ``None``."""

    values = config.get(key.lower())
    return values[0] if values else None


def parse_sysctl(text: str) -> dict[str, str]:
    """Parse ``sysctl.conf`` style text into ``{key: value}``."""

    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("-"):
            # "sysctl -w key=value" style lines are tolerated, the flag is dropped.
            line = line.lstrip("-").strip()
        match = _KV_RE.match(line)
        if not match:
            continue
        key = match.group("key").strip()
        value = match.group("value").split("#")[0].strip()
        if key and value:
            result[key] = value
    return result


def parse_passwd(text: str) -> list[dict[str, str]]:
    """Parse ``/etc/passwd`` into a list of dictionaries."""

    entries: list[dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 7:
            continue
        entries.append(
            {
                "name": fields[0],
                "password": fields[1],
                "uid": fields[2],
                "gid": fields[3],
                "gecos": fields[4],
                "home": fields[5],
                "shell": fields[6],
            }
        )
    return entries


def parse_shadow(text: str) -> list[dict[str, str]]:
    """Parse ``/etc/shadow`` into a list of dictionaries (hash included)."""

    entries: list[dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        entries.append(
            {
                "name": fields[0],
                "hash": fields[1],
                "last_change": fields[2] if len(fields) > 2 else "",
                "min_days": fields[3] if len(fields) > 3 else "",
                "max_days": fields[4] if len(fields) > 4 else "",
                "warn_days": fields[5] if len(fields) > 5 else "",
            }
        )
    return entries


def parse_login_defs(text: str) -> dict[str, str]:
    """Parse ``/etc/login.defs`` into ``{KEY: value}``."""

    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = strip_comment(raw_line).strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        result[parts[0].upper()] = parts[1].strip()
    return result


def parse_apt_config(text: str) -> dict[str, str]:
    """Parse an APT configuration fragment into ``{Option::Name: value}``."""

    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        match = _APT_RE.match(raw_line)
        if match:
            result[match.group("key")] = match.group("value").strip()
    return result


def parse_key_value_file(text: str) -> dict[str, str]:
    """Parse flat ``key = value`` or ``KEY=value`` files (dnf, ufw, ...)."""

    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = strip_comment(raw_line.strip())
        if not line or line.startswith("[") or line.startswith(";"):
            continue
        match = _KV_RE.match(line)
        if match:
            result[match.group("key").strip().lower()] = match.group("value").strip()
    return result


def parse_sudoers(text: str) -> dict[str, object]:
    """Parse a sudoers file just enough for hardening checks.

    Returns a dictionary with:
    * ``defaults``: lower-cased ``Defaults`` options without their values;
    * ``nopasswd``: tuples ``(line_number, line)`` for NOPASSWD rules;
    * ``rules``: non-comment, non-Defaults lines.
    """

    defaults: set[str] = set()
    nopasswd: list[tuple[int, str]] = []
    rules: list[str] = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("defaults"):
            for part in line[len("defaults") :].replace(",", " ").split():
                key = part.split("=")[0].strip().lower()
                if key:
                    defaults.add(key)
            continue
        rules.append(line)
        if "nopasswd" in line.lower():
            nopasswd.append((number, line))
    return {"defaults": defaults, "nopasswd": nopasswd, "rules": rules}


@dataclass(frozen=True)
class UfwSettings:
    """Subset of the ufw configuration the auditor cares about."""

    enabled: bool | None
    default_input_policy: str | None


def parse_ufw(conf_text: str | None, defaults_text: str | None) -> UfwSettings:
    """Combine ``/etc/ufw/ufw.conf`` and ``/etc/default/ufw`` values."""

    enabled: bool | None = None
    policy: str | None = None
    if conf_text is not None:
        values = parse_key_value_file(conf_text)
        raw = values.get("enabled")
        if raw is not None:
            enabled = raw.strip().strip('"').strip("'").lower() == "yes"
    if defaults_text is not None:
        values = parse_key_value_file(defaults_text)
        raw = values.get("default_input_policy")
        if raw is not None:
            policy = raw.strip().strip('"').strip("'").upper()
    return UfwSettings(enabled=enabled, default_input_policy=policy)
