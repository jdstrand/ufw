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
# Functional tests converted from tests/installation/

import unittest

import tests.functional.support
from tests.functional.support import FunctionalTestCase


class InstallationTests(FunctionalTestCase):
    class_name = "installation"

    def test_check_help(self):
        """tests/installation/check_help: ufw help"""
        out = self.assert_ok("help")
        self.assertIn("Usage: ufw COMMAND", out)
        self.assertIn("enable", out)
        self.assertIn("app list", out)

    def test_check_root(self):
        """tests/installation/check_root: ufw --dry-run status"""
        out = self.assert_ok("--dry-run", "status")
        self.assertIn("Checking iptables", out)


def test_main():
    tests.functional.support.run_unittest(InstallationTests)


if __name__ == "__main__":
    unittest.main()
