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
# functest (fake backend) structurally cannot verify -- the ufw CLI and the
# ufw-init script (the boot path) driving the kernel, the init script under
# churn (serial xtables-lock churn), and reset tearing the firewall down.

import glob
import os

import tests.functional.support
from tests.functional.support import E2ETestCase, flushes_whole_firewall


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


@flushes_whole_firewall("ufw-init flush-all in the churn loop flushes everything")
class InitChurnE2E(E2ETestCase):
    """`ufw-init start` must succeed on every iteration of rapid serial
    start/flush-all churn -- repeated xtables-lock acquisition and teardown.
    A faithful port of the root/live stress loop (25 iterations), which was
    equally sequential: each command's process exits (releasing the lock)
    before the next starts, so this exercises lock-acquisition health under
    churn, NOT concurrent lock contention."""

    ITERATIONS = 25

    def test_init_start_under_churn(self):
        self.assert_ok("allow", "13/tcp")
        self.assert_ok("--force", "enable")
        self.assert_init_ok("stop")
        for _ in range(self.ITERATIONS):
            self.assert_init_ok("start")  # must not hit the xtables lock
            self.assert_init_ok("flush-all")  # tear down for the next start


class ForceReloadE2E(E2ETestCase):
    """`ufw-init force-reload` must re-apply the firewall in place: same kernel
    state as the enable that preceded it (rc 0, no drift) with v4+v6 up, and --
    the historical LP: #251355 condition from root/bugs -- it must also succeed
    with IPV6=no, preserving the v6 lockdown state."""

    def test_force_reload_is_stable(self):
        self.enable_ipv6()
        self.assert_ok("allow", "23/tcp")
        self.assert_ok("--force", "enable")
        before4 = self.iptables_rules()
        before6 = self.iptables_rules(v6=True)

        self.assert_init_ok("force-reload")

        self.assert_ufw_chains_present()  # firewall still up after the reload
        self.assertEqual(self.iptables_rules(), before4, "v4 drift after force-reload")
        self.assertEqual(
            self.iptables_rules(v6=True), before6, "v6 drift after force-reload"
        )

    def test_force_reload_ipv6_disabled(self):
        """LP: #251355: with IPV6=no (the sandbox default), force-reload must
        succeed -- the historical bug tripped exactly on the disabled-v6
        reload path -- and reproduce ufw's deliberate v6 lockdown. With v6
        disabled but available in the kernel, start sets ip6tables to default
        DROP with accept-on-loopback and creates no ufw6 chains (the old
        root/bugs golden pinned exactly that ip6tables state)."""
        self.assert_ok("allow", "23/tcp")
        self.assert_ok("--force", "enable")

        after_enable6 = self.iptables_rules(v6=True)
        self.assertIn(":INPUT DROP", after_enable6)
        self.assertIn("-A INPUT -i lo -j ACCEPT", after_enable6)
        self.assertFalse(
            [ln for ln in after_enable6 if "ufw6" in ln],
            "IPV6=no: enable created ufw6 chains",
        )

        self.assert_init_ok("force-reload")

        # v4 chains applied (v6=False asserts nothing about ufw6; the
        # lockdown-equality check below is what proves no ufw6 chains
        # appeared, since after_enable6 was shown ufw6-free above)
        self.assert_ufw_chains_present(v6=False)
        self.assertEqual(
            self.iptables_rules(v6=True),
            after_enable6,
            "IPV6=no: force-reload changed the v6 lockdown (LP: #251355)",
        )


class ResetE2E(E2ETestCase):
    """`ufw reset` must back up every on-disk rule file, tear the firewall out
    of the kernel, and clear the user rules. Distilled from root/live "Reset
    test"."""

    def test_reset_backs_up_and_tears_down(self):
        self.assert_ok("--force", "enable")
        self.assert_ok("allow", "12345")
        self.assert_ufw_chains_present(v6=False)  # IPV6=no by default

        confdir = os.path.join(self.etc, "ufw")
        before = glob.glob(os.path.join(confdir, "*.rules"))

        self.assert_ok("--force", "reset")

        # every *.rules file is backed up to *.rules.<timestamp> ...
        backups = glob.glob(os.path.join(confdir, "*.rules.2*"))
        self.assertEqual(
            len(backups),
            len(before),
            "reset should back up each *.rules file (%r -> %r)" % (before, backups),
        )
        # ... the firewall is torn out of the kernel ...
        self.assertIsNone(
            self.chain_references("ufw-user-input"),
            "ufw-user-input chain still present after reset",
        )
        # ... and the rule is gone from disk.
        self.assertNotIn("12345", self.read(self.user_rules))


def test_main():
    tests.functional.support.run_e2e(
        InitEquivalenceE2E, InitChurnE2E, ForceReloadE2E, ResetE2E
    )
