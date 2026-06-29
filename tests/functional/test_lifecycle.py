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
# On-disk rule lifecycle.
#
# Exercises the *persisted* rule state machine end to end -- the first add
# builds the chain structure, adds accumulate in order, a delete removes exactly
# its rule and leaves the order intact, a re-add appends, and removing every rule
# returns to no user rules. This is the on-disk behaviour the transcript's
# per-command deltas glide over (the setUp warm-up hides the first-add
# structure-init) and that the render oracle doesn't cover (BoilerplateTests pins
# the dry-run render, not the add/delete cycle).

import tests.functional.support
from tests.functional.support import FunctionalTestCase


class LifecycleTests(FunctionalTestCase):
    """The persisted add / delete / re-add / remove-all lifecycle."""

    class_name = None

    # A logging chain that the pristine user.rules lacks but the first add builds
    # -- the signal that adding a rule initializes the firewall structure.
    LOGGING_CHAIN = ":ufw-before-logging-input - [0:0]"

    def setUp(self):
        super().setUp()
        # Undo the setUp warm-up so the first add is observed building the chain
        # structure (the warm-up pre-builds it to keep transcript deltas clean).
        self._restore_pristine_config()
        self._reset_recording()

    def tuples(self, path):
        """The ``### tuple ###`` lines (one per user rule) in a rules file."""
        return [
            line
            for line in self.read(path).splitlines()
            if line.startswith("### tuple ###")
        ]

    def test_rule_lifecycle(self):
        ur = self.user_rules

        # 0) pristine: no user rules, logging structure not yet built
        self.assertEqual(0, self.tuple_count(ur))
        self.assertNotIn(self.LOGGING_CHAIN, self.read(ur))

        # 1) the first add builds the logging-chain structure *and* the rule
        self.assert_ok("allow", "22")
        self.assertIn(self.LOGGING_CHAIN, self.read(ur))
        self.assertEqual(
            ["### tuple ### allow any 22 0.0.0.0/0 any 0.0.0.0/0 in"],
            self.tuples(ur),
        )

        # 2) further adds accumulate, in order
        self.assert_ok("allow", "80/tcp")
        self.assert_ok("deny", "25")
        self.assertEqual(
            [
                "### tuple ### allow any 22 0.0.0.0/0 any 0.0.0.0/0 in",
                "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in",
                "### tuple ### deny any 25 0.0.0.0/0 any 0.0.0.0/0 in",
            ],
            self.tuples(ur),
        )

        # 3) deleting the middle rule removes exactly it; order preserved
        self.assert_ok("delete", "allow", "80/tcp")
        self.assertEqual(
            [
                "### tuple ### allow any 22 0.0.0.0/0 any 0.0.0.0/0 in",
                "### tuple ### deny any 25 0.0.0.0/0 any 0.0.0.0/0 in",
            ],
            self.tuples(ur),
        )

        # 4) re-adding the rule deleted in 3) appends at the end -- duplicate
        #    detection is against the *current* rules, so a deleted rule is
        #    re-addable, and it does not resume its old middle slot
        self.assert_ok("allow", "80/tcp")
        self.assertEqual(
            [
                "### tuple ### allow any 22 0.0.0.0/0 any 0.0.0.0/0 in",
                "### tuple ### deny any 25 0.0.0.0/0 any 0.0.0.0/0 in",
                "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in",
            ],
            self.tuples(ur),
        )

        # 5) removing every rule returns to no user rules (the structure stays)
        self.assert_ok("delete", "allow", "22")
        self.assert_ok("delete", "deny", "25")
        self.assert_ok("delete", "allow", "80/tcp")
        self.assertEqual(0, self.tuple_count(ur))
        self.assertIn(self.LOGGING_CHAIN, self.read(ur))

    def test_ipv6_rule_lifecycle(self):
        # With IPV6=yes a single rule lands in BOTH families; the delete clears
        # both. (v6 structure-init is likewise hidden by the warm-up.)
        self.enable_ipv6()

        self.assert_ok("allow", "22")
        self.assertEqual(
            ["### tuple ### allow any 22 0.0.0.0/0 any 0.0.0.0/0 in"],
            self.tuples(self.user_rules),
        )
        self.assertEqual(
            ["### tuple ### allow any 22 ::/0 any ::/0 in"],
            self.tuples(self.user6_rules),
        )

        self.assert_ok("delete", "allow", "22")
        self.assertEqual(0, self.tuple_count(self.user_rules))
        self.assertEqual(0, self.tuple_count(self.user6_rules))

    def test_delete_by_number(self):
        """Deleting by rule number removes the right rule (tests/root/live).

        Adds ports 1..4 (so rule N == port N), then deletes by number from the
        highest down so the lower indices stay stable, checking each port's rule
        is present beforehand and gone afterward."""
        ur = self.user_rules
        for i in (1, 2, 3, 4):
            self.assert_ok("allow", str(i))
        self.assertEqual(4, self.tuple_count(ur))

        for i in (4, 3, 2, 1):
            self.assertIn("### tuple ### allow any %d " % i, self.read(ur))
            self.assert_ok("--force", "delete", str(i))
            self.assertNotIn("### tuple ### allow any %d " % i, self.read(ur))
        self.assertEqual(0, self.tuple_count(ur))

    def test_show_rule_reports(self):
        """The file-based 'show' reports run (rc 0) without a live firewall
        (tests/root/live "Show" checked rc only, via 'null'). The iptables-
        querying reports (raw, builtins) need the real backend and are covered
        by the e2e suite."""
        self.assert_ok("allow", "22/tcp")
        for sub in ("before-rules", "user-rules", "after-rules", "logging-rules"):
            self.assert_ok("show", sub)


def test_main():
    tests.functional.support.run_unittest(LifecycleTests)
