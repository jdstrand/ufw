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
# Truncated rules-file handling: ufw must warn about a cut-short user.rules
# on every command and refuse to rewrite it (which would make the rule loss
# permanent).

import tests.functional.support
from tests.functional.support import FunctionalTestCase


class CorruptionTests(FunctionalTestCase):
    """Truncated user.rules/user6.rules: warn, refuse rewrites, recover."""

    class_name = None

    def _truncate(self, path):
        """Drop the COMMIT trailer and everything after it."""
        content = self.read(path)
        self.write_file(path, content[: content.index("COMMIT")])

    def test_truncated_rules_file_warns_and_refuses_changes(self):
        """truncated user.rules is never silently rewritten"""
        self.assert_ok("allow", "80", "comment", "nginx")
        self._truncate(self.user_rules)

        # every command warns, but read-only ones still work
        r = self.ufw("status")
        self.assertEqual(r.rc, 0, r.out)
        self.assertIn("looks truncated", r.out)
        self.assertIn(self.user_rules, r.out)

        # rule changes are refused and the file is left exactly as found
        before = self.read(self.user_rules)
        out = self.assert_fail("allow", "443")
        self.assertIn("Refusing to rewrite truncated", out)
        self.assertEqual(self.read(self.user_rules), before)

        # deletes are refused the same way (fail2ban's unban path)
        out = self.assert_fail("delete", "allow", "80")
        self.assertIn("Refusing to rewrite truncated", out)
        self.assertEqual(self.read(self.user_rules), before)

        # recovery: reset installs pristine files and changes work again
        self.assert_ok("--force", "reset")
        out = self.assert_ok("allow", "443")
        self.assertNotIn("looks truncated", out)
        self.assertIn("443", self.read(self.user_rules))

    def test_empty_rules_file_warns_and_refuses_changes(self):
        """a zero-byte user.rules (the classic crash artifact)"""
        self.write_file(self.user_rules, "")

        r = self.ufw("status")
        self.assertEqual(r.rc, 0, r.out)
        self.assertIn("looks truncated", r.out)

        out = self.assert_fail("allow", "443")
        self.assertIn("Refusing to rewrite truncated", out)
        self.assertEqual(self.read(self.user_rules), "")

    def test_truncated_v6_file_flagged_independently(self):
        """only the damaged family's file is refused"""
        self.enable_ipv6()
        self.assert_ok("allow", "80")
        self._truncate(self.user6_rules)

        r = self.ufw("status")
        self.assertEqual(r.rc, 0, r.out)
        self.assertIn("looks truncated", r.out)
        self.assertIn(self.user6_rules, r.out)
        self.assertNotIn(self.user_rules + " ", r.out)

        # a both-families rule add: the v4 write goes through, the v6 write
        # is refused, and the damaged file is not touched
        before6 = self.read(self.user6_rules)
        out = self.assert_fail("allow", "443")
        self.assertIn("Refusing to rewrite truncated", out)
        self.assertIn(self.user6_rules, out)
        self.assertIn("443", self.read(self.user_rules))
        self.assertEqual(self.read(self.user6_rules), before6)

    def test_truncated_v6_file_guarded_while_ipv6_disabled(self):
        """user6.rules is guarded even under IPV6=no ('logging on' and app
        updates rewrite it regardless of the setting)"""
        self.assert_ok("allow", "80")
        self._truncate(self.user6_rules)

        # warned about even though the file is never parsed
        r = self.ufw("status")
        self.assertEqual(r.rc, 0, r.out)
        self.assertIn("looks truncated", r.out)
        self.assertIn(self.user6_rules, r.out)

        # v4-only rule changes don't touch user6.rules and still work
        self.assert_ok("allow", "443")

        # 'logging on' rewrites both families' files: the damaged v6 file
        # is refused, not silently regenerated without its rules
        before6 = self.read(self.user6_rules)
        out = self.assert_fail("logging", "on")
        self.assertIn("Refusing to rewrite truncated", out)
        self.assertIn(self.user6_rules, out)
        self.assertEqual(self.read(self.user6_rules), before6)


def test_main():
    tests.functional.support.run_unittest(CorruptionTests)
