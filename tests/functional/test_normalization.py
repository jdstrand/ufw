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
# Rule normalization: equivalent input forms (service name vs port, CIDR vs
# dotted netmask, bare host vs /32) must normalize to the same stored rule, so a
# rule added by one form is deletable by an equivalent form. A delete that
# returns rc 0 *is* the proof the forms normalized to the same rule (ufw returns
# non-zero when it cannot find the rule). Distilled from tests/root/normalization.

import tests.functional.support
from tests.functional.support import FunctionalTestCase


class NormalizationTests(FunctionalTestCase):
    class_name = None

    def _add_then_delete(self, add_args, del_args):
        """Add a rule via add_args, delete it via del_args; both must succeed and
        the rule store must return to empty (the forms were equivalent)."""
        self.assert_ok(*(["allow"] + add_args))
        self.assert_ok(*(["delete", "allow"] + del_args))
        self.assertEqual(
            0,
            self.tuple_count(self.user_rules),
            "add %r / delete %r did not cancel out" % (add_args, del_args),
        )

    def test_equivalent_ports(self):
        # service name <-> port/proto <-> long form all denote the same rule.
        forms = [
            ["http"],
            ["80/tcp"],
            ["to", "any", "port", "80", "proto", "tcp"],
        ]
        for add in forms:
            for delete in forms:
                self._add_then_delete(add, delete)

    def test_equivalent_host_netmasks(self):
        # bare host == /32 == /255.255.255.255
        forms = [
            ["from", "192.168.0.1"],
            ["from", "192.168.0.1/32"],
            ["from", "192.168.0.1/255.255.255.255"],
        ]
        for add in forms:
            for delete in forms:
                self._add_then_delete(add, delete)

    def test_equivalent_network_netmasks(self):
        # CIDR prefix == equivalent dotted mask, both directions, at every
        # width /32../1 (tests/root/normalization walked the full range; a
        # conversion bug at one width -- an off-by-one in a single octet --
        # is invisible at the others).
        for width in range(32, 0, -1):
            bits = (0xFFFFFFFF << (32 - width)) & 0xFFFFFFFF
            mask = ".".join(str((bits >> s) & 0xFF) for s in (24, 16, 8, 0))
            cidr = ["from", "192.168.0.0/%d" % width]
            dotted = ["from", "192.168.0.0/%s" % mask]
            self._add_then_delete(cidr, dotted)
            self._add_then_delete(dotted, cidr)


def test_main():
    tests.functional.support.run_unittest(NormalizationTests)
