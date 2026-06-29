# -*- coding: utf-8 -*-
#
# Copyright 2026 Jamie Strandboge
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
#
# Independent smoke tests of the installed ufw binary, run as a real
# subprocess. These deliberately overlap the in-process suite only in coverage
# (representative command types); they share no test-scenario code with it.

import unittest

import tests.functional.support
from tests.functional.support import SubprocessTestCase


class SubprocessSmokeTests(SubprocessTestCase):
    def test_help(self):
        out = self.assert_ok("help")
        self.assertIn("Usage: ufw COMMAND", out)

    def test_version(self):
        # The installed binary substitutes #VERSION# (Makefile), so -- unlike the
        # in-process suite, where it is only a placeholder -- this asserts a real
        # version string. This is the sole home for version-output coverage.
        for arg in ("version", "--version"):
            out = self.assert_ok(arg)
            self.assertRegex(out, r"^ufw \d")
            self.assertNotIn("#VERSION#", out)
            self.assertIn("Copyright", out)

    def test_dry_run_status(self):
        self.assert_ok("--dry-run", "status")

    def test_basic_rule_roundtrip(self):
        self.assert_ok("allow", "22/tcp")
        self.assertIn("22", self.read(self.user_rules))
        self.assert_ok("delete", "allow", "22/tcp")

    def test_dry_run_rule(self):
        self.assert_ok("--dry-run", "allow", "53")

    def test_app_info_and_rule(self):
        out = self.assert_ok("app", "info", "Apache")
        self.assertIn("Apache", out)
        self.assert_ok("allow", "Apache")
        self.assert_ok("delete", "allow", "Apache")

    def test_bad_arg_fails(self):
        self.assert_fail("allow", "53a")

    def test_ipv6_rule(self):
        self.enable_ipv6()
        self.assert_ok("--dry-run", "allow", "to", "2001:db8::1")


def test_main():
    tests.functional.support.run_unittest(SubprocessSmokeTests)


if __name__ == "__main__":
    unittest.main()
