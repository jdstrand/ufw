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
# Functional tests converted from tests/bugs/

import os
import re
import unittest
import unittest.mock

import tests.functional.support
from tests.functional.support import FunctionalTestCase


class BugsTests(FunctionalTestCase):
    class_name = "bugs"

    def test_apps(self):
        """tests/bugs/apps"""
        # Bug: Samba IPv4 tuple text was wrong when IPV6 is enabled.
        self.enable_ipv6()
        self.assert_ok("allow", "in", "on", "eth1", "to", "any", "app", "Samba")
        v4 = self.read(self.user_rules)
        v6 = self.read(self.user6_rules)
        # the IPv4 tuples must carry the correct (v4) addresses + app/iface text
        self.assertIn("0.0.0.0/0 Samba - in_eth1", v4)
        self.assertIn(
            "-A ufw-user-input -i eth1 -p tcp -m multiport --dports 139,445", v4
        )
        # and the IPv6 tuples are written to user6.rules
        self.assertIn("::/0 Samba - in_eth1", v6)
        self.assertIn("-A ufw6-user-input -i eth1 -p tcp", v6)
        self.assert_ok(
            "delete", "allow", "in", "on", "eth1", "to", "any", "app", "Samba"
        )
        self.set_default("IPV6", "no")

        # Bug: inserted Samba rules out of order when IPV6 is enabled. (Exact
        # ordering verification is deferred to phase 2; here we verify the
        # commands succeed and the inserted rules round-trip cleanly.)
        self.enable_ipv6()
        self.assert_ok("allow", "in", "on", "eth0")
        self.assert_ok("allow", "to", "192.168.0.2")
        self.assert_ok("allow", "to", "192.168.0.3")
        self.assert_ok("allow", "in", "on", "eth1")
        self.assert_ok("allow", "in", "on", "eth2")

        self.assert_ok("insert", "8", "deny", "to", "any", "app", "Bind9")
        self.assertIn("Bind9", self.read(self.user_rules))
        self.assert_ok("delete", "deny", "to", "any", "app", "Bind9")
        self.assert_ok("insert", "8", "deny", "to", "any", "app", "Samba")
        self.assertIn("dapp_Samba", self.read(self.user_rules))

        # this insert should look the same as the above
        self.assert_ok("delete", "deny", "to", "any", "app", "Samba")
        self.assert_ok("insert", "5", "deny", "to", "any", "app", "Bind9")
        self.assertIn("Bind9", self.read(self.user_rules))

        self.assert_ok("delete", "deny", "to", "any", "app", "Bind9")
        self.assert_ok("insert", "5", "deny", "to", "any", "app", "Samba")
        self.assertIn("dapp_Samba", self.read(self.user_rules))

        self.assert_ok("delete", "allow", "in", "on", "eth0")
        self.assert_ok("delete", "allow", "to", "192.168.0.2")
        self.assert_ok("delete", "allow", "to", "192.168.0.3")
        self.assert_ok("delete", "allow", "in", "on", "eth1")
        self.assert_ok("delete", "allow", "in", "on", "eth2")
        self.assert_ok("delete", "deny", "to", "any", "app", "Samba")
        # everything removed again
        self.assertEqual(self.tuple_count(self.user_rules), 0)
        self.set_default("IPV6", "no")

        # Bug #407810: an app whose name differs from its profile filename
        bug = self.app_profile_path("bug407810")
        self.copy_file(self.app_profile_path("samba"), bug)
        self.write_file(bug, self.read(bug).replace("Samba", "bug407810"))
        self.assert_ok("app", "info", "bug407810")
        self.assert_ok("allow", "bug407810")
        self.assertIn("dapp_bug407810", self.read(self.user_rules))
        self.remove(bug)
        self.assert_ok("delete", "allow", "bug407810")
        self.assertNotIn("bug407810", self.read(self.user_rules))

    def test_misc(self):
        """tests/bugs/misc"""
        # Bug #319226: VCS/hidden files in applications.d are ignored
        self.makedirs(os.path.join(self.appsd, ".svn"))
        self.touch(os.path.join(self.appsd, ".hgignore"))
        self.write_file(
            os.path.join(self.appsd, ".testme"),
            "[Bug319226]\ntitle=test 319226\ndescription=test description\n"
            "ports=23/tcp\n",
        )
        out = self.assert_ok("app", "list")
        self.assertNotIn("Bug319226", out)

        # Bug #337705: a failed module import must exit 1 (not crash). In the old
        # shell test this broke 'import ufw.frontend' in the installed script; in
        # process we simulate the import failure during command handling.
        with unittest.mock.patch(
            "ufw.frontend.parse_command",
            side_effect=ModuleNotFoundError("No module named 'ufw.nonexistent'"),
        ):
            self.assert_fail("help")

        # Bug #430053: file permissions are honored (overridden only as root)
        expected = 0 if os.getuid() == 0 else 1
        self.set_default("IPV6", "no")
        self.chmod(self.user_rules, 0o444)
        self.assert_rc(expected, "allow", "12345")
        self.chmod(self.user_rules, 0o644)

        self.set_default("IPV6", "yes")
        self.chmod(self.user6_rules, 0o444)
        self.assert_rc(expected, "allow", "12345")
        self.chmod(self.user6_rules, 0o644)
        self.set_default("IPV6", "no")

        self.chmod(self.default_ufw, 0o444)
        self.assert_rc(expected, "default", "deny")
        self.chmod(self.default_ufw, 0o644)

        self.chmod(self.ufw_conf, 0o444)
        self.assert_rc(expected, "logging", "medium")
        self.chmod(self.ufw_conf, 0o644)

        # Bug #480789: 'INVALID -j RETURN' present in logging-deny only for low/on
        self.set_default("IPV6", "yes")
        for i in ("low", "on", "medium", "high", "full"):
            self.assert_ok("--dry-run", "logging", i)
            should = i in ("low", "on")
            self.assert_ok("allow", "13")
            for path in (self.user_rules, self.user6_rules):
                present = bool(
                    re.search(r"logging-deny .* INVALID -j RETURN", self.read(path))
                )
                self.assertEqual(present, should, "level=%s file=%s" % (i, path))
            self.assert_ok("delete", "allow", "13")
        self.set_default("IPV6", "yes")

        # Bug #512131: 'UFW LIMIT BLOCK' present unless logging is off
        for i in ("off", "low", "on", "medium", "high", "full", "off"):
            self.assert_ok("logging", i)
            found = bool(re.search(r"UFW LIMIT BLOCK", self.read(self.user_rules)))
            self.assertEqual(found, i != "off", "level=%s" % i)

        # Bug #568877: unusual interface name
        self.assert_ok("--dry-run", "allow", "in", "on", "iaslab")

        # Bug #946332: bare --dry-run is an error
        self.assert_fail("--dry-run")

        # Bug #787955: an invalid default policy makes status fail
        self.set_default("DEFAULT_INPUT_POLICY", "ACCEPT_NO_TRACK")
        self.assert_fail("--dry-run", "status")
        self.set_default("DEFAULT_INPUT_POLICY", "ACCEPT")

    def test_rules(self):
        """tests/bugs/rules"""
        # Bug #237446
        self.assert_ok("--dry-run", "allow", "to", "111.12.34.2/4")

        # IPv6 Bugs
        self.enable_ipv6()
        # proto ipv6 when IPV6=yes
        self.assert_ok("--dry-run", "allow", "to", "any", "proto", "ipv6")
        self.set_default("IPV6", "no")


def test_main():
    tests.functional.support.run_unittest(BugsTests)


if __name__ == "__main__":
    unittest.main()
