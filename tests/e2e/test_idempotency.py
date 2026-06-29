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
# End-to-end idempotency check against the REAL iptables backend: re-rendering
# the saved rules from scratch (disable -> enable) must reproduce the exact same
# kernel state the incremental adds left behind. Distilled from the
# disable/enable + iptables-save diff in the old root/logging and root/live_apps.

import tests.functional.support
from tests.functional.support import E2ETestCase


class IdempotencyE2E(E2ETestCase):
    """A from-scratch re-apply (disable then enable, which renders user.rules to
    the kernel in one shot) must match the state built up by individual `ufw`
    adds. A mismatch means rule rendering or iptables-restore is not stable."""

    # A spread that exercises the rendering paths most likely to drift: a
    # multi-field tcp rule, a limit (recent module), a reject, a logged rule,
    # and a v6 rule -- across v4 and v6.
    RULES = (
        ("allow", "23/tcp"),
        (
            "deny",
            "proto",
            "tcp",
            "from",
            "10.0.0.0/8",
            "to",
            "192.168.0.1",
            "port",
            "25",
        ),
        ("limit", "13/tcp"),
        ("reject", "115/udp"),
        ("allow", "log", "80/tcp"),
        ("deny", "proto", "tcp", "from", "2001:db8::/32", "to", "any", "port", "25"),
    )

    def test_reapply_is_stable(self):
        self.enable_ipv6()
        self.assert_ok("logging", "medium")
        self.assert_ok("--force", "enable")
        for rule in self.RULES:
            self.assert_ok(*rule)

        before4 = self.iptables_rules()
        before6 = self.iptables_rules(v6=True)

        # Tear the rules out of the kernel and render them all back at once.
        self.assert_ok("disable")
        self.assert_ok("--force", "enable")

        after4 = self.iptables_rules()
        after6 = self.iptables_rules(v6=True)

        self.assertEqual(before4, after4, "v4 kernel rules changed after reapply")
        self.assertEqual(before6, after6, "v6 kernel rules changed after reapply")


def test_main():
    tests.functional.support.run_e2e(IdempotencyE2E)
