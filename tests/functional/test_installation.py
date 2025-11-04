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


class TestInstallation(unittest.TestCase):
    """
    Installation tests - verify basic UFW installation and help output.
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_check_help(self) -> None:
        """
        Test UFW help command output.

        Equivalent to: tests/installation/check_help
        """
        self.env.reset()
        self.env.run_cmd(["help"], expected_rc=0)

        result = self.env.get_result()

        self.assertIn("0: help", result)
        self.assertIn("Usage: ufw COMMAND", result)
        self.assertIn("Commands:", result)
        self.assertIn("enable", result)
        self.assertIn("disable", result)
        self.assertIn("default ARG", result)
        self.assertIn("logging LEVEL", result)
        self.assertIn("allow ARGS", result)
        self.assertIn("deny ARGS", result)
        self.assertIn("reject ARGS", result)
        self.assertIn("limit ARGS", result)
        self.assertIn("delete RULE|NUM", result)
        self.assertIn("insert NUM RULE", result)
        self.assertIn("Application profile commands:", result)
        self.assertIn("app list", result)
        self.assertIn("app info PROFILE", result)

    @unittest.skip("Requires root privileges")
    def test_check_root(self) -> None:
        """
        Test UFW status command (requires root).

        Equivalent to: tests/installation/check_root
        This test is skipped as it requires root privileges.
        """
        pass


if __name__ == "__main__":
    unittest.main()
