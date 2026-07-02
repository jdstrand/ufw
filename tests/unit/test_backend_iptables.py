#
# Copyright 2012-2024 Canonical Ltd.
# Copyright 2025 Jamie Strandboge
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

import unittest
import unittest.mock
import tests.unit.support
import ufw.backend_iptables
import ufw.common
import ufw.frontend
import ufw.util
import ufw.applications
import os
import re
import shutil
import time

from io import StringIO
from typing import Optional


class BackendIptablesTestBase(unittest.TestCase):
    ui: ufw.frontend.UFWFrontend
    backend: ufw.backend_iptables.UFWBackendIptables
    msg_output: Optional[StringIO]
    saved_msg_output: object
    prevpath: str

    def setUp(self):
        ufw.common.do_checks = False

        for d in [ufw.common.state_dir, ufw.common.config_dir]:
            if not os.path.isdir(d + ".bak"):
                shutil.copytree(d, d + ".bak")

        # don't duplicate all the code for set_rule() from frontend.py so
        # the frontend's set_rule() to exercise our set_rule()
        self.ui = ufw.frontend.UFWFrontend(dryrun=True)

        # for convenience
        self.backend = self.ui.backend  # type: ignore[assignment]

        self.saved_msg_output = ufw.util.msg_output
        self.msg_output = None

        self.prevpath = os.environ["PATH"]
        os.environ["PATH"] = "%s:%s" % (ufw.common.iptables_dir, os.environ["PATH"])

        # update ufw-init-functions to use our fake iptables* commands
        f = os.path.join(ufw.common.state_dir, "ufw-init-functions")
        contents = ""
        fd = open(f, "r")
        for line in fd.readlines():
            if re.search("^PATH=", line):
                line = "#" + line
                line += 'PATH="%s:%s"\n' % (ufw.common.iptables_dir, line.split('"')[1])
            contents += line
        fd.close()

        fd_new = open(f + ".new", "w")
        fd_new.write(contents)
        fd_new.close()

        os.rename(f + ".new", f)

    def tearDown(self):
        self.ui.backend = None  # type: ignore[assignment]
        self.ui = None  # type: ignore[assignment]
        self.backend = None  # type: ignore[assignment]
        os.environ["PATH"] = self.prevpath

        for d in [ufw.common.state_dir, ufw.common.config_dir]:
            if os.path.isdir(d):
                tests.unit.support.recursive_rm(d)
                shutil.copytree(d + ".bak", d)

        if self.msg_output:
            ufw.util.msg_output = self.saved_msg_output
            self.msg_output.close()
            self.msg_output = None

        sysctl = os.path.join(ufw.common.iptables_dir, "sysctl")
        if os.path.exists(sysctl):
            os.unlink(sysctl)

    def _update_sysctl(self, forward=False):
        sysctl = os.path.join(ufw.common.iptables_dir, "sysctl")
        if forward:
            shutil.copy(
                os.path.join(ufw.common.iptables_dir, "sysctl-forward-yes"), sysctl
            )
        else:
            shutil.copy(
                os.path.join(ufw.common.iptables_dir, "sysctl-forward-no"), sysctl
            )

    def _test__do_checks(self):
        """Test _do_checks()"""
        print("  setting self.backend.do_checks to 'True'")
        self.backend.do_checks = True
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend._do_checks
        )
        print("  setting self.backend.do_checks to 'False'")
        self.backend.do_checks = False
        self.backend._do_checks()


class BackendIptablesTestCase(BackendIptablesTestBase):
    def test_get_default_application_policy(self):
        """Test get_default_application_policy()"""
        s = self.backend.get_default_application_policy()
        self.assertTrue(s.endswith("skip"))

    def test_set_default_application_policy(self):
        """Test set_default_application_policy()"""
        self.backend.dryrun = False
        for policy in ["allow", "deny", "reject", "skip"]:
            s = self.backend.set_default_application_policy(policy)
            self.assertTrue(policy in s, "Could not find '%s' in:\n%s" % (policy, s))

    def test_get_app_rules_from_template(self):
        """Test get_app_rules_from_template()"""
        pr = ufw.frontend.parse_command(["rule", "allow", "CIFS"])
        rules = self.backend.get_app_rules_from_template(pr.data["rule"])
        self.assertEqual(len(rules), 2)
        for r in rules:
            self.assertEqual(r.dapp, "CIFS")

        pr = ufw.frontend.parse_command(["rule", "deny", "from", "any", "app", "CIFS"])
        rules = self.backend.get_app_rules_from_template(pr.data["rule"])
        self.assertEqual(len(rules), 2)
        for r in rules:
            self.assertEqual(r.sapp, "CIFS")

        pr = ufw.frontend.parse_command(
            ["rule", "reject", "to", "any", "app", "CIFS", "from", "any", "app", "CIFS"]
        )
        rules = self.backend.get_app_rules_from_template(pr.data["rule"])
        self.assertEqual(len(rules), 2)
        for r in rules:
            self.assertEqual(r.dapp, "CIFS")
            self.assertEqual(r.sapp, "CIFS")

        pr = ufw.frontend.parse_command(
            [
                "rule",
                "reject",
                "to",
                "any",
                "app",
                "WWW",
                "from",
                "any",
                "app",
                "WWW Secure",
            ]
        )
        rules = self.backend.get_app_rules_from_template(pr.data["rule"])
        self.assertEqual(len(rules), 1)
        for r in rules:
            self.assertEqual(r.dapp, "WWW")
            self.assertEqual(r.sapp, "WWW Secure")

        pr = ufw.frontend.parse_command(
            ["rule", "allow", "from", "any", "app", "IPP", "to", "any", "app", "WWW"]
        )
        rules = self.backend.get_app_rules_from_template(pr.data["rule"])
        self.assertEqual(len(rules), 1)
        for r in rules:
            self.assertEqual(r.sapp, "IPP")

        pr = ufw.frontend.parse_command(["rule", "allow", "12345"])
        tests.unit.support.check_for_exception(
            self,
            ufw.common.UFWError,
            self.backend.get_app_rules_from_template,
            pr.data["rule"],
        )

    def test_update_app_rule(self):
        """Test upate_app_rule()"""
        self.saved_msg_output = ufw.util.msg_output
        self.msg_output = StringIO()
        ufw.util.msg_output = self.msg_output

        (s, res) = self.backend.update_app_rule("WWW")
        self.assertFalse(res)
        self.assertEqual(s, "")

        pr = ufw.frontend.parse_command([] + ["rule", "allow", "CIFS"])
        self.backend.rules.append(pr.data["rule"])
        (s, res) = self.backend.update_app_rule("WWW")
        self.assertFalse(res)
        self.assertEqual(s, "")
        (s, res) = self.backend.update_app_rule("CIFS")
        self.assertTrue(res)
        self.assertTrue("CIFS" in s)

        pr = ufw.frontend.parse_command(
            [] + ["rule", "allow", "to", "5678:fff::/64", "app", "WWW Secure"]
        )
        pr.data["rule"].set_v6(True)
        self.backend.rules6.append(pr.data["rule"])
        (s, res) = self.backend.update_app_rule("WWW")
        self.assertFalse(res)
        self.assertEqual(s, "")
        (s, res) = self.backend.update_app_rule("WWW Secure")
        self.assertTrue(res)
        self.assertTrue("WWW Secure" in s)

        pr = ufw.frontend.parse_command(
            []
            + [
                "rule",
                "allow",
                "from",
                "1234:fff::/64",
                "app",
                "WWW Secure",
                "to",
                "2345:fff::/64",
                "app",
                "WWW Full",
            ]
        )
        pr.data["rule"].set_v6(True)
        self.backend.rules6.append(pr.data["rule"])
        (s, res) = self.backend.update_app_rule("WWW")
        self.assertFalse(res)
        self.assertEqual(s, "")
        (s, res) = self.backend.update_app_rule("WWW Full")
        self.assertTrue(res)
        self.assertTrue("WWW Full" in s)

        pr = ufw.frontend.parse_command([] + ["rule", "allow", "NFS"])
        self.backend.rules.append(pr.data["rule"])
        pr.data["rule"].set_v6(True)
        self.backend.rules6.append(pr.data["rule"])
        (s, res) = self.backend.update_app_rule("WWW")
        self.assertFalse(res)
        self.assertEqual(s, "")
        (s, res) = self.backend.update_app_rule("NFS")
        self.assertTrue(res)
        self.assertTrue("NFS" in s)

    def test_find_application_name(self):
        """Test find_application_name()"""
        res = self.backend.find_application_name("WWW")
        self.assertEqual(res, "WWW")

        res = self.backend.find_application_name("WwW")
        self.assertEqual(res, "WWW")

        f = os.path.join(self.backend.files["apps"], "testapp")
        contents = """
[WWw]
title=Duplicate Web Server
description=Duplicate Web server
ports=80/tcp
"""
        fd = open(f, "w")
        fd.write(contents)
        fd.close()
        self.backend.profiles = ufw.applications.get_profiles(
            self.backend.files["apps"]
        )
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend.find_application_name, "wWw"
        )

        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend.find_application_name, "nonexistent"
        )

    def test_find_other_position(self):
        """Test find_other_position()"""
        pr = ufw.frontend.parse_command(
            []
            + [
                "rule",
                "allow",
                "from",
                "1234:fff::/64",
                "app",
                "WWW Secure",
                "to",
                "2345:fff::/64",
                "app",
                "WWW Full",
            ]
        )
        pr.data["rule"].set_v6(True)
        self.backend.rules6.append(pr.data["rule"])

        pr = ufw.frontend.parse_command(["rule", "allow", "WWW"])
        self.backend.rules.append(pr.data["rule"])
        pr.data["rule"].set_v6(True)
        self.backend.rules6.append(pr.data["rule"])

        res = self.backend.find_other_position(2, v6=True)
        self.assertEqual(res, 0)

        res = self.backend.find_other_position(1, v6=False)
        self.assertEqual(res, 2)

        tests.unit.support.check_for_exception(
            self, ValueError, self.backend.find_other_position, 3, True
        )

        tests.unit.support.check_for_exception(
            self, ValueError, self.backend.find_other_position, 3, False
        )

        tests.unit.support.check_for_exception(
            self, ValueError, self.backend.find_other_position, 0, False
        )

        pr = ufw.frontend.parse_command(
            [] + ["rule", "allow", "to", "2345:fff::/64", "app", "CIFS"]
        )
        pr.data["rule"].set_v6(True)
        self.backend.rules6.append(pr.data["rule"])

        pr = ufw.frontend.parse_command(["rule", "allow", "CIFS"])
        self.backend.rules.append(pr.data["rule"])
        pr.data["rule"].set_v6(True)
        self.backend.rules6.append(pr.data["rule"])

        res = self.backend.find_other_position(3, v6=True)
        self.assertEqual(res, 0)

    def test_get_loglevel(self):
        """Test get_loglevel()"""
        for level in ["off", "low", "medium", "high"]:
            self.backend.set_loglevel(level)
            (_, s) = self.backend.get_loglevel()
            self.assertTrue(level in s, "Could not find '%s' in:\n%s" % (level, s))

        self.backend.defaults["loglevel"] = "nonexistent"
        (_, s) = self.backend.get_loglevel()
        self.assertTrue("unknown" in s, "Could not find 'unknown' in:\n%s" % s)

    def test_set_loglevel(self):
        """Test set_loglevel()"""
        for ll in ["off", "on", "low", "medium", "high"]:
            self.backend.set_loglevel(ll)
            (_, s) = self.backend.get_loglevel()
            if ll == "on":
                ll = "low"
            self.assertTrue(ll in s, "Could not find '%s' in:\n%s" % (ll, s))

        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend.set_loglevel, "nonexistent"
        )

    def test_get_rules_count(self):
        """Test get_rules_count()"""
        res = self.backend.get_rules_count(v6=False)
        self.assertEqual(res, 0)

        pr = ufw.frontend.parse_command(
            []
            + [
                "rule",
                "allow",
                "from",
                "1234:fff::/64",
                "app",
                "WWW Secure",
                "to",
                "2345:fff::/64",
                "app",
                "WWW Full",
            ]
        )
        pr.data["rule"].set_v6(True)
        self.backend.rules6.append(pr.data["rule"])

        pr = ufw.frontend.parse_command(["rule", "allow", "WWW"])
        self.backend.rules.append(pr.data["rule"])
        pr.data["rule"].set_v6(True)
        self.backend.rules6.append(pr.data["rule"])

        res = self.backend.get_rules_count(v6=False)
        self.assertEqual(res, 1)

        res = self.backend.get_rules_count(v6=True)
        self.assertEqual(res, 2)

    def test_get_rule_by_number(self):
        """Test get_rule_by_number()"""
        pr1 = ufw.frontend.parse_command(["rule", "allow", "WWW"])
        self.backend.rules.append(pr1.data["rule"])

        pr2 = ufw.frontend.parse_command(["rule", "allow", "WWW"])
        pr2.data["rule"].set_v6(True)
        self.backend.rules6.append(pr2.data["rule"])

        pr3 = ufw.frontend.parse_command(
            []
            + [
                "rule",
                "allow",
                "from",
                "1234:fff::/64",
                "app",
                "WWW Secure",
                "to",
                "2345:fff::/64",
                "app",
                "WWW Full",
            ]
        )
        pr3.data["rule"].set_v6(True)
        self.backend.rules6.append(pr3.data["rule"])

        res = self.backend.get_rule_by_number(1)
        assert res is not None
        self.assertEqual(ufw.common.UFWRule.match(res, pr1.data["rule"]), 0)
        self.assertEqual(ufw.common.UFWRule.match(res, pr2.data["rule"]), 1)
        self.assertEqual(ufw.common.UFWRule.match(res, pr3.data["rule"]), 1)

        res = self.backend.get_rule_by_number(2)
        assert res is not None
        self.assertEqual(ufw.common.UFWRule.match(res, pr2.data["rule"]), 0)
        self.assertEqual(ufw.common.UFWRule.match(res, pr1.data["rule"]), 1)
        self.assertEqual(ufw.common.UFWRule.match(res, pr3.data["rule"]), 1)

        res = self.backend.get_rule_by_number(3)
        assert res is not None
        self.assertEqual(ufw.common.UFWRule.match(res, pr3.data["rule"]), 0)
        self.assertEqual(ufw.common.UFWRule.match(res, pr1.data["rule"]), 1)
        self.assertEqual(ufw.common.UFWRule.match(res, pr2.data["rule"]), 1)

        res = self.backend.get_rule_by_number(4)
        self.assertEqual(res, None)

        pr4 = ufw.frontend.parse_command([] + ["rule", "allow", "CIFS"])
        self.backend.rules.append(pr4.data["rule"])
        pr4.data["rule"].set_v6(True)
        self.backend.rules6.append(pr4.data["rule"])
        res = self.backend.get_rule_by_number(6)
        self.assertEqual(res, None)
        res = self.backend.get_rule_by_number(4)
        assert res is not None
        self.assertEqual(ufw.common.UFWRule.match(res, pr4.data["rule"]), 1)

    def test_get_matching(self):
        """Test get_matching()"""
        pr1 = ufw.frontend.parse_command(["rule", "allow", "WWW"])
        self.backend.rules.append(pr1.data["rule"])

        pr2 = ufw.frontend.parse_command(["rule", "deny", "WWW"])
        self.backend.rules.append(pr2.data["rule"])

        test_rule = pr1.data["rule"].dup_rule()
        res = self.backend.get_matching(test_rule)
        self.assertEqual(len(res), 2)

    def test_set_bad_default_application_policy(self):
        """Test bad set_default_application_policy()"""
        self.backend.dryrun = False
        for policy in ["alow", "deny 78&"]:
            tests.unit.support.check_for_exception(
                self,
                ufw.common.UFWError,
                self.backend.set_default_application_policy,
                policy,
            )

    def test_set_default_policy(self):
        """Test set_default_policy()"""
        # dryrun
        for direction in ["incoming", "outgoing", "routed"]:
            for policy in ["allow", "deny", "reject"]:
                res = self.backend.set_default_policy(policy, direction)
                self.assertTrue(
                    policy in res, "Could not find '%s' in:\n%s" % (policy, res)
                )
                self.assertTrue(
                    direction in res, "Could not find '%s' in:\n%s" % (direction, res)
                )

        # no dryrun
        self.backend.dryrun = False
        for direction in ["incoming", "outgoing"]:
            for policy in ["allow", "deny", "reject"]:
                res = self.backend.set_default_policy(policy, direction)
                self.assertTrue(
                    policy in res, "Could not find '%s' in:\n%s" % (policy, res)
                )
                self.assertTrue(
                    direction in res, "Could not find '%s' in:\n%s" % (direction, res)
                )
                if direction == "incoming":
                    res = self.backend._get_default_policy("input")
                else:
                    res = self.backend._get_default_policy("output")
                self.assertEqual(res, policy)

        #  no dryrun for routed
        self.backend.dryrun = False
        for forward_enabled in [False, True]:
            self._update_sysctl(forward_enabled)
            direction = "routed"
            for policy in ["allow", "deny", "reject"]:
                res = self.backend.set_default_policy(policy, direction)
                self.assertTrue(
                    policy in res, "Could not find '%s' in:\n%s" % (policy, res)
                )
                self.assertTrue(
                    direction in res, "Could not find '%s' in:\n%s" % (direction, res)
                )
                res = self.backend._get_default_policy("forward", check_forward=True)
                if not forward_enabled:
                    policy = "disabled"
                self.assertEqual(res, policy)

    def test_set_default(self):
        """Test set_default()"""
        self.backend.set_default(
            self.backend.files["defaults"], "NEW_INPUT_POLICY", "accept"
        )
        self.assertEqual(self.backend.defaults["new_input_policy"], "accept")

    def test_set_bad_default(self):
        """Test bad set_default_policy()"""
        tests.unit.support.check_for_exception(
            self,
            ufw.common.UFWError,
            self.backend.set_default,
            self.backend.files["defaults"],
            "DEFAULT INPUT_POLICY",
            "accept",
        )

        tests.unit.support.check_for_exception(
            self,
            ufw.common.UFWError,
            self.backend.set_default,
            self.backend.files["defaults"] + ".nonexistent",
            "DEFAULT_INPUT_POLICY",
            "accept",
        )

    def test_get_running_raw(self):
        """Test get_running_raw()"""
        # dryrun
        for t in ["raw", "builtins", "before", "user", "after", "logging"]:
            res = self.backend.get_running_raw(t)
            for s in ["iptables", "ip6tables"]:
                self.assertTrue(
                    "Checking raw %s" % s in res,
                    "Could not find '%s' in:\n%s" % (s, res),
                )

        # no dryrun
        self.backend.dryrun = False
        for t in ["raw", "builtins", "before", "user", "after", "logging"]:
            res = self.backend.get_running_raw(t)
            self.assertTrue(t in res, "Could not find '%s' in:\n%s" % (t, res))

    def test_get_status(self):
        """Test get_status()"""
        # get_status() reads the forwarding policy via sysctl; install the fake
        # sysctl so this works without a real sysctl on the host.
        self._update_sysctl()
        # build up some rules
        cmds_sim = tests.unit.support.get_sample_rule_commands_simple()
        cmds_ext = tests.unit.support.get_sample_rule_commands_extended()

        for cmds in [cmds_sim, cmds_ext]:
            self.backend.rules = []
            self.backend.rules6 = []
            for cmd in cmds:
                pr = ufw.frontend.parse_command(cmd + [])
                action = cmd[1]
                self.assertEqual(action, pr.action, "%s != %s" % (action, pr.action))
                if "rule" in pr.data:
                    if pr.data["rule"].v6:
                        self.backend.rules6.append(pr.data["rule"])
                    else:
                        self.backend.rules.append(pr.data["rule"])

            # dryrun
            self.backend.dryrun = True
            for v in [False, True]:
                for c in [False, True]:
                    res = self.backend.get_status(verbose=v, show_count=c)
                    for s in ["iptables", "ip6tables"]:
                        self.assertTrue(
                            "Checking %s" % s in res,
                            "Could not find '%s' in:\n%s" % (s, res),
                        )

            # no dryrun
            self.backend.dryrun = False
            for v in [False, True]:
                for c in [False, True]:
                    res = self.backend.get_status(verbose=v, show_count=c)
                    terms = ["Status: active", "To"]
                    if v:
                        terms += ["Logging: on", "Default: deny", "New profiles: skip"]
                    if c:
                        terms += "[ 1] "
                    for search in terms:
                        self.assertTrue(
                            search in res, "Could not find '%s' in:\n%s" % (search, res)
                        )

    def test_lp1838764(self):
        """Test get_status() - LP: #1838764"""
        # get_status() reads the forwarding policy via sysctl; install the fake
        # sysctl so this works without a real sysctl on the host.
        self._update_sysctl()
        # build up some rules
        cmds = [
            [
                "rule",
                "allow",
                "from",
                "192.168.1.0/24",
                "to",
                "192.168.1.0/24",
                "app",
                "SSH",
            ],
            [
                "rule",
                "allow",
                "out",
                "from",
                "192.168.1.0/24",
                "to",
                "192.168.1.0/24",
                "app",
                "SSH",
            ],
            [
                "rule",
                "allow",
                "from",
                "192.168.1.0/24",
                "to",
                "192.168.1.0/24",
                "port",
                "22",
            ],
            [
                "rule",
                "allow",
                "out",
                "from",
                "192.168.1.0/24",
                "to",
                "192.168.1.0/24",
                "port",
                "22",
            ],
            [
                "rule",
                "allow",
                "from",
                "192.168.1.0/24",
                "to",
                "192.168.1.0/24",
                "port",
                "22",
                "proto",
                "tcp",
            ],
            [
                "rule",
                "allow",
                "out",
                "from",
                "192.168.1.0/24",
                "to",
                "192.168.1.0/24",
                "port",
                "22",
                "proto",
                "tcp",
            ],
        ]

        pat_exp = re.compile(
            r"192\.168\.1\.0/24\s+SSH\s+ALLOW\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+22\s+ALLOW\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+22/tcp\s+ALLOW\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+SSH\s+ALLOW OUT\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+22\s+ALLOW OUT\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+22/tcp\s+ALLOW OUT\s+192\.168\.1\.0/24\s+"
        )
        pat_verbose = re.compile(
            r"192\.168\.1\.0/24\s+SSH \(SSH\)\s+ALLOW IN\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+22\s+ALLOW IN\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+22/tcp\s+ALLOW IN\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+SSH \(SSH\)\s+ALLOW OUT\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+22\s+ALLOW OUT\s+192\.168\.1\.0/24\s+192\.168\.1\.0/24\s+22/tcp\s+ALLOW OUT\s+192\.168\.1\.0/24\s+"
        )

        self.backend.rules = []
        self.backend.rules6 = []
        for cmd in cmds:
            pr = ufw.frontend.parse_command(cmd + [])
            action = cmd[1]
            self.assertEqual(action, pr.action, "%s != %s" % (action, pr.action))
            if "rule" in pr.data:
                if pr.data["rule"].v6:
                    self.backend.rules6.append(pr.data["rule"])
                else:
                    self.backend.rules.append(pr.data["rule"])

        self.backend.dryrun = False
        for v in [False, True]:
            res = self.backend.get_status(verbose=v, show_count=False)
            pat = pat_exp
            if v:
                pat = pat_verbose
            self.assertTrue(pat.search(res), "Could not find '%s' in:\n%s" % (pat, res))

    def test_stop_firewall(self):
        """Test stop_firewall()"""
        self.backend.stop_firewall()
        self.backend.dryrun = False
        self.backend.stop_firewall()
        # TODO: verify output

    def test_start_firewall(self):
        """Test start_firewall()"""
        self.backend.start_firewall()
        self.backend.dryrun = False
        self.backend.start_firewall()
        # TODO: verify output

    def test__need_reload(self):
        """Test _need_reload()"""
        for v6 in [False, True]:
            res = self.backend._need_reload(v6)
            self.backend.dryrun = False
            res = self.backend._need_reload(v6)
            self.assertFalse(res)
            # TODO: verify output

    def test__reload_user_rules(self):
        """Test _reload_user_rules()"""
        self.backend.defaults["enabled"] = "no"
        self.backend._reload_user_rules()
        self.backend.dryrun = False
        self.backend.defaults["enabled"] = "yes"
        self.backend._reload_user_rules()
        # TODO: verify output

    def test_use_ipv6(self):
        """Test use_ipv6()"""
        self.backend.defaults["ipv6"] = "yes"
        self.assertTrue(self.backend.use_ipv6())
        self.backend.defaults["ipv6"] = "no"
        self.assertFalse(self.backend.use_ipv6())

    def test__get_defaults(self):
        """Test _get_defaults()"""
        self.backend._get_defaults()
        for k in [
            "default_output_policy",
            "default_input_policy",
            "default_forward_policy",
            "loglevel",
            "manage_builtins",
            "enabled",
            "ipv6",
            "default_application_policy",
        ]:
            self.assertTrue(k in self.backend.defaults, "Could not find '%s'" % k)

        # Installation defaults are tested elsewhere

        f = self.backend.files["defaults"]
        contents = ""
        fd = open(f, "r")
        for line in fd.readlines():
            if re.search("^DEFAULT_INPUT_POLICY=", line):
                line = "#" + line
            contents += line
        fd.close()

        fd_new = open(f + ".new", "w")
        fd_new.write(contents)
        fd_new.close()
        os.rename(f + ".new", f)

        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend._get_defaults
        )

        f = self.backend.files["defaults"]
        contents = ""
        fd = open(f, "r")
        for line in fd.readlines():
            if re.search("^#DEFAULT_INPUT_POLICY=", line):
                line = "DEFAULT_INPUT_POLICY=bad" + line
            contents += line
        fd.close()

        fd_new = open(f + ".new", "w")
        fd_new.write(contents)
        fd_new.close()
        os.rename(f + ".new", f)

        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend._get_defaults
        )

    def test_set_rule(self):
        """Test set_rule()"""
        self.ui.backend.dryrun = False  # keeps the verbosity down
        # TODO: optimize this. We don't need to hit the disk for all of these.
        #       maybe set enabled to 'yes' once for each branch
        self.ui.backend.defaults["enabled"] = "yes"
        cmds_sim = tests.unit.support.get_sample_rule_commands_simple()
        for cmd in cmds_sim:
            pr = ufw.frontend.parse_command(cmd + [])
            action = cmd[1]
            self.assertEqual(action, pr.action, "%s != %s" % (action, pr.action))
            if "rule" in pr.data:
                self.ui.do_action(pr.action, pr.data["rule"], pr.data["iptype"], True)
            # TODO: verify output

    def test_update_logging(self):
        """Test update_logging()"""
        self.backend.defaults["enabled"] = "no"
        self.backend.dryrun = False
        for level in ["off", "low", "medium", "high", "full"]:
            self.backend.defaults["enabled"] = "no"
            self.backend.update_logging(level)
            self.backend.defaults["enabled"] = "yes"
            self.backend.update_logging(level)
            # TODO: verify output

    def test_reset(self):
        """Test reset()"""
        res = self.backend.reset()
        print(res)

        # we only have 1 second resolution on the backup, so sleep is needed
        time.sleep(1)

        self.backend.dryrun = False
        res = self.backend.reset()
        print(res)
        # TODO: verify output


class StatusAndPolicyTestCase(BackendIptablesTestBase):
    """get_status()/get_running_raw() corners and set_default_policy()
    error paths"""

    def _rule_from_cmd(self, cmd_args, v6=False):
        pr = ufw.frontend.parse_command(["ufw"] + cmd_args)
        r = pr.data["rule"].dup_rule()
        r.set_v6(v6)
        return r

    def test_get_default_application_policy_values(self):
        """Test get_default_application_policy() - all policies"""
        for policy, word in [
            ("accept", "allow"),
            ("drop", "deny"),
            ("reject", "reject"),
            ("skip", "skip"),
        ]:
            self.backend.defaults["default_application_policy"] = policy
            res = self.backend.get_default_application_policy()
            self.assertEqual(res, "New profiles: %s" % word)

    def test_set_default_policy_bad(self):
        """Test set_default_policy() - bad policy and direction"""
        self.backend.dryrun = False
        tests.unit.support.check_for_exception(
            self,
            ufw.common.UFWError,
            self.backend.set_default_policy,
            "bogus",
            "incoming",
        )
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend.set_default_policy, "allow", "bogus"
        )

    def test_set_default_policy_failures(self):
        """Test set_default_policy() - failures are re-raised"""
        self.backend.dryrun = False
        for policy in ["allow", "reject", "deny"]:
            with unittest.mock.patch.object(
                self.backend, "set_default", side_effect=Exception("boom")
            ):
                self.assertRaises(
                    Exception, self.backend.set_default_policy, policy, "incoming"
                )

        # set_default() uses open_files()/close_files() too, so scope the
        # failures to the after_rules edit that follows it
        after = [self.backend.files["after_rules"], self.backend.files["after6_rules"]]
        real_open = ufw.util.open_files

        def fake_open(fn):
            if fn in after:
                raise Exception("boom")
            return real_open(fn)

        with unittest.mock.patch("ufw.util.open_files", side_effect=fake_open):
            self.assertRaises(
                Exception, self.backend.set_default_policy, "allow", "incoming"
            )

        real_close = ufw.util.close_files
        calls = {"n": 0}

        def fake_close(fns, update=True):
            calls["n"] += 1
            if calls["n"] > 1:  # first call is set_default()'s
                raise Exception("boom")
            return real_close(fns, update)

        with unittest.mock.patch("ufw.util.close_files", side_effect=fake_close):
            self.assertRaises(
                Exception, self.backend.set_default_policy, "allow", "incoming"
            )

    def test_set_default_policy_swaps_log_lines(self):
        """Test set_default_policy() - catch-all log rules are swapped"""
        self.backend.dryrun = False
        f = self.backend.files["after_rules"]
        with open(f, "a") as fd:
            fd.write('-A ufw-after-input -j LOG --log-prefix "[UFW BLOCK] "\n')
        res = self.backend.set_default_policy("allow", "incoming")
        self.assertTrue("Default incoming policy changed to 'allow'" in res)
        with open(f) as fd:
            contents = fd.read()
        self.assertTrue("[UFW ALLOW] " in contents)
        self.assertFalse("[UFW BLOCK] " in contents)

    def test_get_running_raw_user_limit6(self):
        """Test get_running_raw() - user chains with v6 rate limiting"""
        self.backend.dryrun = False
        self.backend.initcaps()
        assert self.backend.caps is not None
        self.backend.caps["limit"]["6"] = True
        res = self.backend.get_running_raw("user")
        self.assertTrue("user" in res)

    def test_get_running_raw_failures(self):
        """Test get_running_raw() - iptables failures (v4 and v6)"""
        self.backend.dryrun = False
        with unittest.mock.patch.object(
            ufw.backend_iptables, "cmd", return_value=(1, "bad")
        ):
            tests.unit.support.check_for_exception(
                self, ufw.common.UFWError, self.backend.get_running_raw, "raw"
            )

        # v4 tables succeed, first v6 table fails
        with unittest.mock.patch.object(
            ufw.backend_iptables,
            "cmd",
            side_effect=[(0, "")] * 4 + [(1, "bad")],
        ):
            tests.unit.support.check_for_exception(
                self, ufw.common.UFWError, self.backend.get_running_raw, "raw"
            )

    def test_get_status_not_running(self):
        """Test get_status() - inactive and iptables failures"""
        self.backend.dryrun = False
        with unittest.mock.patch.object(
            ufw.backend_iptables, "cmd", return_value=(1, "")
        ):
            res = self.backend.get_status()
        self.assertEqual(res, "Status: inactive")

        with unittest.mock.patch.object(
            ufw.backend_iptables, "cmd", return_value=(2, "boom")
        ):
            tests.unit.support.check_for_exception(
                self, ufw.common.UFWError, self.backend.get_status
            )

        # v4 check succeeds, ip6tables check fails
        self.backend.defaults["ipv6"] = "yes"
        with unittest.mock.patch.object(
            ufw.backend_iptables, "cmd", side_effect=[(0, ""), (1, "")]
        ):
            tests.unit.support.check_for_exception(
                self, ufw.common.UFWError, self.backend.get_status
            )

    def test_get_status_v6(self):
        """Test get_status() - v6 rule formatting"""
        self._update_sysctl()
        self.backend.dryrun = False
        self.backend.defaults["ipv6"] = "yes"

        self.backend.rules = []
        self.backend.rules6 = [
            self._rule_from_cmd(["allow", "to", "any", "app", "WWW"], v6=True),
            self._rule_from_cmd(["allow", "from", "any", "app", "CIFS"], v6=True),
            self._rule_from_cmd(["allow", "proto", "tcp", "from", "any"], v6=True),
            self._rule_from_cmd(["allow", "22"], v6=True),
        ]

        res = self.backend.get_status()
        for search in ["WWW (v6)", "CIFS (v6)", "Anywhere/tcp (v6)", "22 (v6)"]:
            self.assertTrue(
                search in res, "Could not find '%s' in:\n%s" % (search, res)
            )

        res = self.backend.get_status(verbose=True)
        for search in ["(WWW (v6))", "(CIFS (v6))"]:
            self.assertTrue(
                search in res, "Could not find '%s' in:\n%s" % (search, res)
            )

    def test_get_status_route_interfaces(self):
        """Test get_status() - route rules report interfaces by flow"""
        self._update_sysctl()
        self.backend.dryrun = False

        route = self._rule_from_cmd(
            ["route", "allow", "in", "on", "eth0", "out", "on", "eth1"]
        )
        self.backend.rules = [
            self._rule_from_cmd(["allow", "22"]),
            self._rule_from_cmd(["allow", "out", "53"]),
            route,
        ]
        self.backend.rules6 = []

        res = self.backend.get_status()
        self.assertTrue("FWD" in res, "Could not find 'FWD' in:\n%s" % res)
        self.assertTrue("Anywhere on eth1" in res, "Could not find eth1 in:\n%s" % res)
        self.assertTrue("Anywhere on eth0" in res, "Could not find eth0 in:\n%s" % res)


class RaisedErrorsTestCase(BackendIptablesTestBase):
    """Failures updating the rules files or the running firewall raise"""

    def test_set_rule_write_failure(self):
        """Test set_rule() - failure writing the rules file raises"""
        self.backend.dryrun = False
        pr = ufw.frontend.parse_command(["ufw", "allow", "22"])
        with unittest.mock.patch.object(
            self.backend, "_write_rules", side_effect=OSError("boom")
        ):
            try:
                self.backend.set_rule(pr.data["rule"])
                self.fail("UFWError not thrown")
            except ufw.common.UFWError as e:
                self.assertEqual(e.value, "Couldn't update rules file")

    def test_update_logging_write_failure(self):
        """Test update_logging() - failure writing the rules file raises"""
        self.backend.dryrun = False
        with unittest.mock.patch.object(
            self.backend, "_write_rules", side_effect=OSError("boom")
        ):
            try:
                self.backend.update_logging("low")
                self.fail("UFWError not thrown")
            except ufw.common.UFWError as e:
                self.assertEqual(e.value, "Couldn't update rules file for logging")

    def test_set_rule_live_apply_failure(self):
        """Test set_rule() - failure updating the running firewall raises"""
        import io
        import sys

        self.backend.dryrun = False
        self.backend.defaults["enabled"] = "yes"

        def fake_cmd(args):
            if "-L" in args:
                return (0, "")
            return (1, "boom")

        pr = ufw.frontend.parse_command(["ufw", "allow", "22"])
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            with unittest.mock.patch.object(
                self.backend, "_need_reload", return_value=False
            ):
                with unittest.mock.patch.object(
                    ufw.backend_iptables, "cmd", side_effect=fake_cmd
                ):
                    try:
                        self.backend.set_rule(pr.data["rule"])
                        self.fail("UFWError not thrown")
                    except ufw.common.UFWError as e:
                        self.assertEqual(e.value, "Could not update running firewall")
        finally:
            sys.stderr = old_stderr


class RulesFileIOTestCase(BackendIptablesTestBase):
    """_read_rules()/_write_rules() error paths over crafted rules files"""

    def _append_rules_file(self, lines):
        f = self.backend.files["rules"]
        with open(f, "a") as fd:
            fd.write("\n".join(lines) + "\n")

    def test__read_rules_unreadable(self):
        """Test _read_rules() - unreadable rules file"""
        f = self.backend.files["rules"]
        os.chmod(f, 0)
        try:
            tests.unit.support.check_for_exception(
                self,
                ufw.common.UFWError,
                ufw.backend_iptables.UFWBackendIptables,
                True,
            )
        finally:
            os.chmod(f, 0o640)

    def test__read_rules_malformed_tuples(self):
        """Test _read_rules() - malformed tuples are skipped with a warning"""
        import io
        import sys

        self._append_rules_file(
            [
                "### tuple ### allow tcp",
                "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 xx_foo",
                "### tuple ### allow tcp 99999 0.0.0.0/0 any 0.0.0.0/0 in",
                "### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 "
                + "in_eth0!out_eth1",
            ]
        )

        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            backend = ufw.backend_iptables.UFWBackendIptables(True)
            err = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr

        # only the route rule is valid
        self.assertEqual(len(backend.rules), 1)
        rule = backend.rules[0]
        self.assertTrue(rule.forward)
        self.assertEqual(rule.interface_in, "eth0")
        self.assertEqual(rule.interface_out, "eth1")

        for search in [
            "Skipping malformed tuple (bad length): allow tcp",
            "Skipping malformed tuple (iface)",
            "Skipping malformed tuple: allow tcp 99999",
        ]:
            self.assertTrue(
                search in err, "Could not find '%s' in:\n%s" % (search, err)
            )

    def test__write_rules_failures(self):
        """Test _write_rules() - open/logging/close failures raise"""
        self.backend.dryrun = False

        with unittest.mock.patch("ufw.util.open_files", side_effect=OSError("boom")):
            self.assertRaises(OSError, self.backend._write_rules, False)

        self.backend.defaults["loglevel"] = "bogus"
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend._write_rules, False
        )
        self.backend.defaults["loglevel"] = "low"

        with unittest.mock.patch("ufw.util.close_files", side_effect=OSError("boom")):
            self.assertRaises(OSError, self.backend._write_rules, False)

    def test__get_lists_from_formatted(self):
        """Test _get_lists_from_formatted() - log prefix kept as one arg"""
        res = self.backend._get_lists_from_formatted(
            "-A ufw-user-input -p tcp --dport 22 -j ACCEPT_log", "ufw", "input"
        )
        found = False
        for args in res:
            if "--log-prefix" in args:
                found = True
                idx = args.index("--log-prefix")
                self.assertEqual(args[idx + 1], "[UFW ALLOW] ")
        self.assertTrue(found, "Could not find '--log-prefix' in %s" % res)


class LifecycleTestCase(BackendIptablesTestBase):
    """start/stop/reload/logging failure branches (pinned ufw-init and
    iptables results)"""

    def test_stop_start_firewall_failure_with_rootdir(self):
        """Test stop/start_firewall() - rootdir args and init failure"""
        self.backend.dryrun = False
        # exercise the --rootdir/--datadir argument building; 'false'
        # ignores them and fails like a broken ufw-init would
        self.backend.rootdir = "/nonexistent/root"
        self.backend.datadir = "/nonexistent/data"
        self.backend.files["init"] = "false"
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend.stop_firewall
        )
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend.start_firewall
        )

    def test_start_firewall_loglevel(self):
        """Test start_firewall() - missing/invalid loglevel handling"""
        self.backend.dryrun = False
        self.backend.files["init"] = "true"

        # missing loglevel is added
        del self.backend.defaults["loglevel"]
        self.backend.start_firewall()
        self.assertEqual(self.backend.defaults["loglevel"], "low")

        del self.backend.defaults["loglevel"]
        with unittest.mock.patch.object(
            self.backend, "set_loglevel", side_effect=Exception("boom")
        ):
            try:
                self.backend.start_firewall()
                self.fail("UFWError not thrown")
            except ufw.common.UFWError as e:
                self.assertEqual(e.value, "Could not set LOGLEVEL")

        self.backend.defaults["loglevel"] = "low"
        with unittest.mock.patch.object(
            self.backend, "update_logging", side_effect=Exception("boom")
        ):
            try:
                self.backend.start_firewall()
                self.fail("UFWError not thrown")
            except ufw.common.UFWError as e:
                self.assertEqual(e.value, "Could not load logging rules")

    def test__need_reload(self):
        """Test _need_reload() - limit capabilities and missing chains"""
        self.backend.dryrun = False
        self.backend.caps = {"limit": {"4": False, "6": False}}
        self.assertFalse(self.backend._need_reload(False))
        self.assertFalse(self.backend._need_reload(True))

        with unittest.mock.patch.object(
            ufw.backend_iptables, "cmd", return_value=(1, "")
        ):
            self.assertTrue(self.backend._need_reload(False))

    def test__reload_user_rules_failures(self):
        """Test _reload_user_rules() - restore failures (v4 and v6)"""
        self.backend.dryrun = False
        self.backend.defaults["enabled"] = "yes"
        with unittest.mock.patch.object(
            ufw.backend_iptables, "cmd_pipe", return_value=(1, "")
        ):
            tests.unit.support.check_for_exception(
                self, ufw.common.UFWError, self.backend._reload_user_rules
            )

        self.backend.defaults["ipv6"] = "yes"
        with unittest.mock.patch.object(
            ufw.backend_iptables, "cmd_pipe", side_effect=[(0, ""), (1, "")]
        ):
            tests.unit.support.check_for_exception(
                self, ufw.common.UFWError, self.backend._reload_user_rules
            )

    def test__chain_cmd(self):
        """Test _chain_cmd() - failures honor fail_ok"""
        with unittest.mock.patch.object(
            ufw.backend_iptables, "cmd", return_value=(1, "")
        ):
            tests.unit.support.check_for_exception(
                self,
                ufw.common.UFWError,
                self.backend._chain_cmd,
                "ufw6-user-input",
                ["-L", "ufw6-user-input", "-n"],
            )
            # fail_ok swallows the failure
            self.backend._chain_cmd(
                "ufw-user-input", ["-L", "ufw-user-input", "-n"], fail_ok=True
            )

    def test_update_logging_failures(self):
        """Test update_logging() - level and running-firewall failures"""
        self.backend.dryrun = False
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.backend.update_logging, "bogus"
        )

        with unittest.mock.patch.object(
            self.backend, "_write_rules", side_effect=ufw.common.UFWError("boom")
        ):
            try:
                self.backend.update_logging("low")
                self.fail("UFWError not thrown")
            except ufw.common.UFWError as e:
                self.assertEqual(e.value, "boom")

        self.backend.defaults["enabled"] = "yes"
        err_msg = "Could not update running firewall"

        # chain consistency check fails
        with unittest.mock.patch.object(
            self.backend, "_chain_cmd", side_effect=ufw.common.UFWError("boom")
        ):
            try:
                self.backend.update_logging("low")
                self.fail("UFWError not thrown")
            except ufw.common.UFWError as e:
                self.assertEqual(e.value, err_msg)

        # flushing the logging chains fails
        def fail_flush(c, args, fail_ok=False):
            if args[0] == "-F":
                raise ufw.common.UFWError("boom")

        with unittest.mock.patch.object(
            self.backend, "_chain_cmd", side_effect=fail_flush
        ):
            try:
                self.backend.update_logging("low")
                self.fail("UFWError not thrown")
            except ufw.common.UFWError as e:
                self.assertEqual(e.value, err_msg)

        # adding the logging rules fails
        def fail_add(c, args, fail_ok=False):
            if args[0] == "-I":
                raise ufw.common.UFWError("boom")

        with unittest.mock.patch.object(
            self.backend, "_chain_cmd", side_effect=fail_add
        ):
            try:
                self.backend.update_logging("off")
                self.fail("UFWError not thrown")
            except ufw.common.UFWError as e:
                self.assertEqual(e.value, err_msg)


def test_main():  # used by runner.py
    tests.unit.support.run_unittest(
        BackendIptablesTestCase,
        StatusAndPolicyTestCase,
        RaisedErrorsTestCase,
        RulesFileIOTestCase,
        LifecycleTestCase,
    )


if __name__ == "__main__":  # used when standalone
    unittest.main()
