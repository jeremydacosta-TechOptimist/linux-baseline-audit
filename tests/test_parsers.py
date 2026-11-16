"""Tests for the configuration file parsers."""

from __future__ import annotations

import unittest

from baseaudit.parsers import (
    parse_apt_config,
    parse_key_value_file,
    parse_login_defs,
    parse_passwd,
    parse_shadow,
    parse_ssh_config,
    parse_sudoers,
    parse_sysctl,
    parse_ufw,
    ssh_value,
    strip_comment,
)


class StripCommentTests(unittest.TestCase):
    def test_strips_trailing_comment(self) -> None:
        self.assertEqual(strip_comment("value # note"), "value ")

    def test_keeps_line_without_comment(self) -> None:
        self.assertEqual(strip_comment("value"), "value")


class SshConfigTests(unittest.TestCase):
    def test_parses_keywords_and_lists_duplicates(self) -> None:
        config = parse_ssh_config(
            "# a comment\nPort 22\nPermitRootLogin no\nPort 2222\n\n"
        )
        self.assertEqual(config["port"], ["22", "2222"])
        self.assertEqual(ssh_value(config, "permitrootlogin"), "no")

    def test_first_value_wins(self) -> None:
        config = parse_ssh_config("PermitRootLogin no\nPermitRootLogin yes\n")
        self.assertEqual(ssh_value(config, "permitrootlogin"), "no")

    def test_quoted_values_are_unwrapped(self) -> None:
        config = parse_ssh_config('Banner "/etc/issue.net"\n')
        self.assertEqual(ssh_value(config, "banner"), "/etc/issue.net")

    def test_comment_and_blank_lines_are_ignored(self) -> None:
        config = parse_ssh_config("#X11Forwarding yes\n   \n")
        self.assertEqual(config, {})

    def test_include_keyword_is_preserved(self) -> None:
        config = parse_ssh_config("Include /etc/ssh/sshd_config.d/*.conf\n")
        self.assertEqual(config["include"], ["/etc/ssh/sshd_config.d/*.conf"])


class SysctlTests(unittest.TestCase):
    def test_parses_key_value_pairs(self) -> None:
        values = parse_sysctl(
            "# hardening\n"
            "net.ipv4.ip_forward = 0\n"
            "net.ipv4.tcp_syncookies=1  # inline note\n"
            "fs.protected_hardlinks = 1\n"
        )
        self.assertEqual(values["net.ipv4.ip_forward"], "0")
        self.assertEqual(values["net.ipv4.tcp_syncookies"], "1")
        self.assertEqual(values["fs.protected_hardlinks"], "1")

    def test_ignores_malformed_lines(self) -> None:
        values = parse_sysctl("not a valid line\n= 1\nkey=\n")
        self.assertEqual(values, {})


class AccountParserTests(unittest.TestCase):
    def test_parses_passwd_entries(self) -> None:
        entries = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n"
            "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
            "bad line\n"
        )
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["name"], "root")
        self.assertEqual(entries[0]["uid"], "0")
        self.assertEqual(entries[1]["shell"], "/usr/sbin/nologin")

    def test_parses_shadow_and_keeps_empty_hash(self) -> None:
        entries = parse_shadow("root:$6$hash:19000:0:90:14:::\nempty::19500:0:90:14:::\n")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["max_days"], "90")
        self.assertEqual(entries[1]["hash"], "")

    def test_parses_login_defs(self) -> None:
        values = parse_login_defs(
            "# comment\nPASS_MAX_DAYS\t90\nPASS_MIN_DAYS   1\nUID_MIN 1000\nbroken\n"
        )
        self.assertEqual(values["PASS_MAX_DAYS"], "90")
        self.assertEqual(values["UID_MIN"], "1000")


class AptAndKeyValueTests(unittest.TestCase):
    def test_parses_apt_configuration_fragments(self) -> None:
        values = parse_apt_config(
            '// comment\nAPT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "0";\n'
        )
        self.assertEqual(values["APT::Periodic::Update-Package-Lists"], "1")
        self.assertEqual(values["APT::Periodic::Unattended-Upgrade"], "0")

    def test_parses_ufw_style_key_value(self) -> None:
        values = parse_key_value_file("ENABLED=yes\n# comment\n")
        self.assertEqual(values["enabled"], "yes")

    def test_parses_dnf_section_file(self) -> None:
        values = parse_key_value_file(
            "[commands]\napply_updates = yes\nupgrade_type = security\n"
        )
        self.assertEqual(values["apply_updates"], "yes")
        self.assertEqual(values["upgrade_type"], "security")


class SudoersTests(unittest.TestCase):
    def test_collects_defaults_and_nopasswd_rules(self) -> None:
        parsed = parse_sudoers(
            "Defaults use_pty\n"
            "Defaults env_keep += \"LANG LC_*\"\n"
            "%sudo ALL=(ALL:ALL) ALL\n"
            "labadmin ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx\n"
            "# comment\n"
        )
        self.assertIn("use_pty", parsed["defaults"])
        self.assertEqual(len(parsed["rules"]), 2)
        self.assertEqual(parsed["nopasswd"][0][0], 4)

    def test_no_nopasswd(self) -> None:
        parsed = parse_sudoers("Defaults use_pty\n%sudo ALL=(ALL:ALL) ALL\n")
        self.assertEqual(parsed["nopasswd"], [])


class UfwParserTests(unittest.TestCase):
    def test_combines_configuration_files(self) -> None:
        settings = parse_ufw(
            "ENABLED=yes\nLOGLEVEL=low\n",
            'DEFAULT_INPUT_POLICY="DROP"\n',
        )
        self.assertTrue(settings.enabled)
        self.assertEqual(settings.default_input_policy, "DROP")

    def test_handles_missing_files(self) -> None:
        settings = parse_ufw(None, None)
        self.assertIsNone(settings.enabled)
        self.assertIsNone(settings.default_input_policy)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
