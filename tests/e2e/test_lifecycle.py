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
# End-to-end lifecycle checks against the REAL iptables backend: things the
# functest (fake backend) structurally cannot verify. Here: the ufw CLI and the
# ufw-init script (the boot path) must drive the kernel to identical state.

import tests.functional.support
from tests.functional.support import E2ETestCase


class InitEquivalenceE2E(E2ETestCase):
    """`ufw enable` and `ufw-init start` must produce identical kernel rules,
    and `ufw disable` and `ufw-init stop` likewise -- otherwise a host would
    firewall differently at boot than when toggled by hand. Distilled from the
    old root/live 'Compare enable and ufw-init' check (v4 + v6)."""

    def test_enable_equals_init_start(self):
        self.enable_ipv6()
        self.assert_ok("allow", "23/tcp")
        self.assert_ok("logging", "medium")

        # CLI path: capture kernel state after enable, then after disable.
        self.assert_ok("--force", "enable")
        ipt_enable = self.iptables_rules()
        ip6t_enable = self.iptables_rules(v6=True)

        self.assert_ok("disable")
        ipt_disable = self.iptables_rules()
        ip6t_disable = self.iptables_rules(v6=True)

        # Init path: ufw-init start honors ENABLED in ufw.conf (disable set it to
        # no), so flip it back, then compare start vs enable and stop vs disable.
        self.set_default("ENABLED", "yes", conf=True)
        self.assert_init_ok("start")
        ipt_start = self.iptables_rules()
        ip6t_start = self.iptables_rules(v6=True)

        self.assert_init_ok("stop")
        ipt_stop = self.iptables_rules()
        ip6t_stop = self.iptables_rules(v6=True)

        self.assertEqual(
            ipt_enable, ipt_start, "v4: 'ufw enable' and 'ufw-init start' differ"
        )
        self.assertEqual(
            ip6t_enable, ip6t_start, "v6: 'ufw enable' and 'ufw-init start' differ"
        )
        self.assertEqual(
            ipt_disable, ipt_stop, "v4: 'ufw disable' and 'ufw-init stop' differ"
        )
        self.assertEqual(
            ip6t_disable, ip6t_stop, "v6: 'ufw disable' and 'ufw-init stop' differ"
        )


def test_main():
    tests.functional.support.run_e2e(InitEquivalenceE2E)
