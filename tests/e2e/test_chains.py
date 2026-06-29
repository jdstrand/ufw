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
# End-to-end chain-skeleton checks against the REAL iptables backend: the full
# set of ufw chains must be wired into the kernel, and that wiring must be
# invariant across every loglevel (loglevel changes what is logged, not the
# chain structure). Distilled from root/live "Verify toplevel/secondary chains".

import tests.functional.support
from tests.functional.support import E2ETestCase


class ChainMatrixE2E(E2ETestCase):
    LOGLEVELS = ("off", "on", "low", "medium", "high", "full")

    # Every builtin jumps to these six ufw sub-chains (suffixed by the lowercased
    # builtin name), at every loglevel.
    BUILTINS = ("INPUT", "OUTPUT", "FORWARD")
    PER_BUILTIN = (
        "before-logging",
        "before",
        "after",
        "after-logging",
        "reject",
        "track",
    )

    # Secondary chains that must be referenced (the live path) ...
    REFERENCED = (
        "logging-deny",
        "not-local",
        "user-forward",
        "user-input",
        "user-output",
        "skip-to-policy-input",
    )
    # ... and those that exist but are not jumped to in the default config.
    ZERO_REF = (
        "logging-allow",
        "user-limit",
        "user-limit-accept",
        "user-logging-forward",
        "user-logging-input",
        "user-logging-output",
        "skip-to-policy-output",
        "skip-to-policy-forward",
    )

    def test_chain_skeleton_every_loglevel(self):
        for level in self.LOGLEVELS:
            self.assert_ok("logging", level)
            self.assert_ok("disable")
            self._flush_all()  # clean slate, then build the skeleton fresh
            self.assert_ok("--force", "enable")

            # Toplevel: each builtin references all six of its ufw sub-chains.
            for builtin in self.BUILTINS:
                jumps = self.builtin_jumps(builtin)
                for c in self.PER_BUILTIN:
                    name = "ufw-%s-%s" % (c, builtin.lower())
                    self.assertIn(
                        name,
                        jumps,
                        "loglevel %s: %s not referenced from %s (got %r)"
                        % (level, name, builtin, jumps),
                    )

            # Secondary: live chains have references, dormant ones have none.
            for c in self.REFERENCED:
                n = self.chain_references("ufw-%s" % c)
                self.assertTrue(
                    n, "loglevel %s: ufw-%s has %r references, want >0" % (level, c, n)
                )
            for c in self.ZERO_REF:
                n = self.chain_references("ufw-%s" % c)
                self.assertEqual(
                    n,
                    0,
                    "loglevel %s: ufw-%s has %r references, want 0" % (level, c, n),
                )


def test_main():
    tests.functional.support.run_e2e(ChainMatrixE2E)
