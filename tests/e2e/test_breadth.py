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
# Apply the rule families that GoodE2E's good/rules sequence does NOT exercise
# against the REAL iptables backend -- route rules (the FORWARD path),
# application rules (profile -> ports), and v6-address rules -- so that real
# iptables/ip6tables-restore acceptance is verified for them too, not just their
# generation (which the functest pins). Distilled from tests/root/live_route,
# tests/root/live_apps, and tests/root/valid6. Also covers the iptables-querying
# `show` reports (raw, builtins) that the functest cannot (no live backend).

import tests.functional.support
from tests.functional.support import E2ETestCase


class BreadthE2E(E2ETestCase):
    def setUp(self):
        super().setUp()
        self.enable_ipv6()  # so v6-address rules apply via ip6tables-restore too
        self.assert_ok("--force", "enable")

    def test_route_rules_apply(self):
        # Route rules render into ufw-user-forward; real iptables must accept.
        self.assert_ok(
            "route",
            "allow",
            "proto",
            "tcp",
            "from",
            "10.0.0.0/8",
            "to",
            "any",
            "port",
            "80",
        )
        self.assert_ok("route", "deny", "in", "on", "eth0", "out", "on", "eth1")
        self.assert_ok("route", "limit", "53")
        fwd = self.raw_iptables("-S", "ufw-user-forward").out
        self.assertIn(
            "10.0.0.0/8", fwd, "route rule not in ufw-user-forward:\n%s" % fwd
        )
        self.assertIn("eth0", fwd)
        self.assertIn("eth1", fwd)

    def test_app_rules_apply(self):
        # Application rules expand a profile to its ports; real iptables must
        # accept the (multiport) result.
        self.assert_ok("allow", "Samba")  # 137,138/udp | 139,445/tcp
        self.assert_ok("allow", "Apache")  # 80/tcp
        inp = self.raw_iptables("-S", "ufw-user-input").out
        self.assertIn("445", inp, "Samba ports not in ufw-user-input:\n%s" % inp)
        self.assertIn("80", inp)

    def test_v6_address_rules_apply(self):
        # v6-address rules go through ip6tables-restore (GoodE2E only mirrors
        # port rules to v6; it never applies a v6 literal address).
        self.assert_ok("allow", "from", "2001:db8::/32")
        self.assert_ok(
            "deny",
            "proto",
            "tcp",
            "from",
            "2001:db8::/32",
            "to",
            "2001:db8:3:4:5:6:7:8",
            "port",
            "25",
        )
        inp6 = self.raw_iptables("-S", "ufw6-user-input", v6=True).out
        self.assertIn(
            "2001:db8::/32", inp6, "v6 address rule not in ufw6-user-input:\n%s" % inp6
        )

    def test_show_raw_and_builtins(self):
        # The iptables-querying reports need the real backend; just assert they
        # run and reflect the live ufw chains.
        self.assert_ok("allow", "22/tcp")
        self.assertIn("ufw", self.assert_ok("show", "raw"))
        self.assert_ok("show", "builtins")


def test_main():
    tests.functional.support.run_e2e(BreadthE2E)
