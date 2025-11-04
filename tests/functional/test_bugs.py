# -*- coding: utf-8 -*-
#
# Copyright 2025 Jamie Strandboge
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import unittest

from tests.functional.testutil import UFWTestEnvironment


class TestBugsApps(unittest.TestCase):
    """
    Test bug fixes related to application profiles.

    Equivalent to: tests/bugs/apps
    """

    @unittest.skip("Requires root privileges")
    def test_samba_ipv4_tuple(self) -> None:
        """
        Test Bug: Samba IPv4 tuple text wrong when IPv6 is enabled.

        This test is skipped as it requires root privileges to add rules.
        """
        pass

    @unittest.skip("Requires root privileges")
    def test_samba_rule_ordering(self) -> None:
        """
        Test Bug: Inserted Samba rules out of order when IPv6 is enabled.

        This test is skipped as it requires root privileges to add rules.
        """
        pass


class TestBugsMisc(unittest.TestCase):
    """
    Test miscellaneous bug fixes.

    Equivalent to: tests/bugs/misc
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_bug_319226_hidden_files(self) -> None:
        """
        Test Bug #319226: Hidden files in applications.d should be ignored.

        Verifies that hidden files and directories (starting with .) in the
        applications.d directory are properly ignored.
        """
        if self.env.testconfig is None:
            self.fail("Test environment not set up")

        apps_dir = os.path.join(self.env.testconfig, "applications.d")

        os.makedirs(os.path.join(apps_dir, ".svn"), exist_ok=True)

        hgignore_path = os.path.join(apps_dir, ".hgignore")
        with open(hgignore_path, "w", encoding="utf-8") as f:
            f.write("")

        test_profile = os.path.join(apps_dir, ".testme")
        with open(test_profile, "w", encoding="utf-8") as f:
            f.write("[Bug319226]\n")
            f.write("title=test 319226\n")
            f.write("description=test description\n")
            f.write("ports=23/tcp\n")

        rc, stdout, _ = self.env.run_cmd(
            ["app", "list"], expected_rc=0, capture_output=True
        )

        self.assertNotIn("Bug319226", stdout)
        self.assertNotIn(".testme", stdout)

    @unittest.skip("Modifies ufw binary - too invasive for standard tests")
    def test_bug_337705_import_error(self) -> None:
        """
        Test Bug #337705: Better error handling for import failures.

        This test is skipped as it requires modifying the ufw binary.
        """
        pass

    @unittest.skip("Requires root privileges")
    def test_bug_430053_readonly_files(self) -> None:
        """
        Test Bug #430053: Handling of read-only configuration files.

        This test is skipped as it requires specific file permissions
        and root privilege checks.
        """
        pass

    @unittest.skip("Requires root privileges")
    def test_bug_480789_logging_levels(self) -> None:
        """
        Test Bug #480789: INVALID rules with different logging levels.

        This test is skipped as it requires adding actual rules.
        """
        pass

    @unittest.skip("Requires root privileges")
    def test_bug_512131_ufw_limit_block(self) -> None:
        """
        Test Bug #512131: UFW LIMIT BLOCK chain handling.

        This test is skipped as it requires modifying actual rules.
        """
        pass

    def test_bug_568877_interface_names(self) -> None:
        """
        Test Bug #568877: Allow interface names like 'iaslab'.

        Verifies that interface names with various characters are accepted.
        """
        self.env.run_cmd(["--dry-run", "allow", "in", "on", "iaslab"], expected_rc=0)


class TestBugsRules(unittest.TestCase):
    """
    Test bug fixes related to rule processing.

    Equivalent to: tests/bugs/rules
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_bug_237446_small_cidr(self) -> None:
        """
        Test Bug #237446: Allow small CIDR ranges like /4.

        Verifies that CIDR notation with small prefix lengths is accepted.
        """
        self.env.run_cmd(["--dry-run", "allow", "to", "111.12.34.2/4"], expected_rc=0)

    def test_proto_ipv6_when_enabled(self) -> None:
        """
        Test that 'proto ipv6' is allowed when IPv6 is enabled.

        Verifies that specifying IPv6 as a protocol is accepted when
        IPv6 support is enabled in UFW configuration.
        """
        if self.env.testconfig is None:
            self.fail("Test environment not set up")

        default_ufw = os.path.join(self.env.testconfig, "..", "default", "ufw")

        with open(default_ufw, "r", encoding="utf-8") as f:
            content = f.read()

        content = content.replace("IPV6=no", "IPV6=yes")

        with open(default_ufw, "w", encoding="utf-8") as f:
            f.write(content)

        self.env.run_cmd(
            ["--dry-run", "allow", "to", "any", "proto", "ipv6"], expected_rc=0
        )


if __name__ == "__main__":
    unittest.main()
