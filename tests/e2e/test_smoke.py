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
# Phase-0 smoke test: prove the e2e harness drives the real iptables backend
# (subprocess + real iptables) through the apply / teardown lifecycle.

import tests.functional.support
from tests.functional.support import E2ETestCase


class SmokeE2E(E2ETestCase):
    def test_apply_lifecycle(self):
        # setUp flush-all'd to a clean kernel and asserted no ufw chains remain.
        self.enable_ipv6()  # exercise both iptables- and ip6tables-restore
        # enable + a basic rule must apply for real (restore accepts it).
        self.assert_ok("--force", "enable")
        self.assert_ok("allow", "22/tcp")
        self.assert_ufw_chains_present()
        self.assertIn("22/tcp", self.ufw("status").out)
        # tearDown runs flush-all; the next test's setUp re-asserts a clean kernel.

    def test_dry_run_is_stripped(self):
        # The e2e driver strips --dry-run, so a "--dry-run" rule still applies.
        self.assert_ok("--force", "enable")
        self.assert_ok("--dry-run", "allow", "2222/tcp")
        self.assertIn("2222", self.ufw("status").out)


def test_main():
    tests.functional.support.run_e2e(SmokeE2E)
