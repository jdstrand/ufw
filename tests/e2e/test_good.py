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
# Run the good/rules command sequence (RuleCommands) against the REAL iptables
# backend. ufw is enabled, so every assert_ok is an apply-acceptance check:
# it means real iptables/ip6tables-restore accepted the rule ufw generated.
# (On-disk generation checks are no-ops here -- verify_on_disk=False -- since
# applying changes the persisted state; generation is pinned by the functest.)

import tests.functional.support
from tests.functional.commands import RuleCommands
from tests.functional.support import E2ETestCase


class GoodE2E(RuleCommands, E2ETestCase):
    def setUp(self):
        super().setUp()
        self.enable_ipv6()  # exercise v4 AND v6 apply
        self.assert_ok("--force", "enable")


def test_main():
    tests.functional.support.run_e2e(GoodE2E)
