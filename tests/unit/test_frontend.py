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
import os

from io import StringIO
from typing import Optional

import tests.unit.support
import ufw.common
import ufw.frontend
import ufw.util


class FrontendTestBase(unittest.TestCase):
    """Shared sandbox setup: a dry-run UFWFrontend with msg() captured"""

    ui: ufw.frontend.UFWFrontend
    msg_output: Optional[StringIO]
    saved_msg_output: object

    def setUp(self):
        ufw.common.do_checks = False
        iptables_dir = ""
        for d in [
            "/sbin",
            "/bin",
            "/usr/sbin",
            "/usr/bin",
            "/usr/local/sbin",
            "/usr/local/bin",
        ]:
            if os.path.exists(os.path.join(d, "iptables")):
                iptables_dir = d
                break
        # Fall back to the harness's fake iptables (set by initvars()) when the
        # host has no real iptables, so these dry-run tests don't require one
        # (the fallback guarantees a non-empty dir, so there is nothing left
        # to assert here).
        if iptables_dir == "":
            iptables_dir = ufw.common.iptables_dir
        ufw.common.iptables_dir = iptables_dir

        # This needs to be before we set ufw.util.msg_output since
        # ufw.util.warn() is called in backend.py:init()
        self.ui = ufw.frontend.UFWFrontend(dryrun=True)

        # Capture stdout from msg() and write_to_file() so we can examine it
        self.saved_msg_output = ufw.util.msg_output
        self.msg_output = StringIO()
        ufw.util.msg_output = self.msg_output

    def tearDown(self):
        # Restore stdout
        if self.msg_output:
            ufw.util.msg_output = self.saved_msg_output
            self.msg_output.close()
            self.msg_output = None

        self.ui = None  # type: ignore[assignment]

    def _init_ui(self, dryrun=True):
        """Construct a UFWFrontend outside msg() capture (backend init may
        warn), then restore capture"""
        ufw.util.msg_output = self.saved_msg_output
        ui = ufw.frontend.UFWFrontend(dryrun=dryrun)
        ufw.util.msg_output = self.msg_output
        return ui


class FrontendTestCase(FrontendTestBase):
    def test_parse_command(self):
        """Test parse_command()"""
        # test_parser.py will handle command combinations exhaustively, let's
        # just use a representative set here
        cmds = [
            "enable",
            "disable",
            "reload",
            "default allow",
            "default deny",
            "default reject",
            "default allow incoming",
            "default deny outgoing",
            "logging on",
            "logging off",
            "logging medium",
            "reset",
            "status",
            "status numbered",
            "status verbose",
            "show raw",
            "show builtins",
            "show before-rules",
            "show user-rules",
            "show after-rules",
            "show logging-rules",
            "show listening",
            "show added",
            "delete 1",
            "delete reject 22",
            "insert 1 limit 22/tcp",
            "allow 53/udp",
            "deny http",
            "allow to any port 23 proto tcp",
            "deny from 192.168.0.1 to 192.168.0.2",
            "reject in on eth0",
            "allow to fe80::/16",
            "deny from any port 53 proto udp",
            "limit in on eth0 to 192.168.0.1 port 22 from 10.0.0.0/24 port 1024:65535 proto tcp",
            "reject telnet comment unsafe",
            "--version",
            "--dry-run allow 22/tcp",
            "--dry-run app list",
            "app list",
            "app info Apache",
            "app default skip",
            "app update Apache",
        ]
        for c in cmds:
            # print(c)
            ufw.frontend.parse_command(["ufw"] + c.split())

    def test_parse_command_bad(self):
        """Test parse_command_bad"""
        data = [
            ("llow 12345", ValueError),
            ("allo 12345", ValueError),
            ("allow", ValueError),
        ]
        # for ufw.util.error() on python3
        ufw.util.msg_output = self.saved_msg_output
        for c, expected in data:
            tests.unit.support.check_for_exception(
                self, expected, ufw.frontend.parse_command, ["ufw"] + c.split()
            )

    def test___init__(self):
        """Test __init__()"""
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, ufw.frontend.UFWFrontend, True, "nonexistent"
        )

    def test_get_command_help(self):
        """Test get_command_help()"""
        s = ufw.frontend.get_command_help()
        terms = [
            "enable",
            "disable",
            "default ARG",
            "logging LEVEL",
            "allow ARGS",
            "deny ARGS",
            "reject ARGS",
            "limit ARGS",
            "delete RULE|NUM",
            "insert NUM RULE",
            "reload",
            "reset",
            "status",
            "status numbered",
            "status verbose",
            "show ARG",
            "version",
            "app list",
            "app info PROFILE",
            "app update PROFILE",
            "app default ARG",
        ]
        for search in terms:
            self.assertTrue(search in s, "Could not find '%s' in:\n%s" % (search, s))

    def test_continue_under_ssh(self):
        """Test continue_under_ssh()"""
        self.ui.continue_under_ssh()

    def test_do_action(self):
        """Test do_action()"""
        cmds = [
            "enable",
            "disable",
            "enable",
            "reload",
            "default allow",
            "default deny",
            "default reject",
            "default allow incoming",
            "default deny outgoing",
            "logging on",
            "logging off",
            "logging medium",
            "reset",
            "status",
            "status numbered",
            "status verbose",
            "allow 43",
            "reject 22",
            "delete 1",
            "delete reject 22",
            "insert 1 limit 22/tcp",
            "allow 53/udp",
            "deny http",
            "allow to any port 23 proto tcp",
            "deny from 192.168.0.1 to 192.168.0.2",
            "reject in on eth0",
            "allow to fe80::/16",
            "deny from any port 53 proto udp",
            "limit in on eth0 to 192.168.0.1 port 22 from 10.0.0.0/24 port 1024:65535 proto tcp",
            "allow CIFS",
            "delete allow CIFS",
            "allow CIFS",
            "delete allow CifS",
            "allow to 192.168.0.1 app WWW",
            "delete allow to 192.168.0.1 app WWW",
            "allow to fe80::/16 app WWW",
            "delete allow to fe80::/16 app WWW",
            "allow from fe80::/16 app WWW",
            "delete allow from fe80::/16 app WWW",
            "allow from fe80::/16 app CIFS",
            "delete allow from fe80::/16 app CifS",
            "show listening",
            "show added",
            "show raw",
        ]
        for dryrun in [True, False]:
            ufw.util.msg_output = self.saved_msg_output
            ui = ufw.frontend.UFWFrontend(dryrun=dryrun)
            ufw.util.msg_output = self.msg_output
            for c in cmds:
                if not dryrun and c not in [
                    "allow",
                    "deny",
                    "limit",
                    "reject",
                    "delete",
                    "insert",
                ]:
                    continue
                try:
                    pr = ufw.frontend.parse_command(["ufw"] + c.split())
                    if "rule" in pr.data:
                        res = ui.do_action(
                            pr.action, pr.data["rule"], pr.data["iptype"], force=True
                        )
                    else:
                        res = ui.do_action(pr.action, "", "", force=True)
                except Exception:
                    print("%s failed:" % c)
                    raise

                if c == "show listening":
                    # "show listening" only returns LISTEN sockets, which may not
                    # exist in all test environments. Empty output is valid.
                    continue  # nothing more to test with 'show listening'

                self.assertTrue(res != "", "Output is empty for '%s'" % c)
                cmd = c.split()[0]
                assert self.msg_output is not None
                out = self.msg_output.getvalue()
                if cmd in ["allow", "deny", "limit", "reject", "delete", "insert"]:
                    for search in ["*filter", "COMMIT"]:
                        self.assertTrue(
                            search in out, "Could not find '%s' in:\n%s" % (search, out)
                        )
                else:
                    search = "running ufw-init"
                    self.assertTrue(
                        search in out, "Could not find '%s' in:\n%s" % (search, out)
                    )

        print("TODO: verify output of rules in do_action()")

    def test_do_action_remove_bad_appname(self):
        """Test do_action() remove bad appname"""
        c = "delete allow to any app &^%$"
        pr = ufw.frontend.parse_command(["ufw"] + c.split())
        tests.unit.support.check_for_exception(
            self,
            ufw.common.UFWError,
            self.ui.do_action,
            pr.action,
            pr.data["rule"],
            pr.data["iptype"],
            True,
        )

    def test_do_application_action(self):
        """Test do_application_action()"""
        cmds = [
            "app list",
            "app info WWW",
            "app default skip",
            "app default deny",
            "app update WWW",
            "app update all",
            "app update --add-new CIFS",
        ]
        for c in cmds:
            try:
                pr = ufw.frontend.parse_command(["ufw"] + c.split())
                if "type" in pr.data and pr.data["type"] == "app":
                    res = self.ui.do_application_action(pr.action, pr.data["name"])
                else:
                    res = self.ui.do_action(pr.action, "", "", force=True)
            except Exception:
                print("%s failed:" % c)
                raise
            # print(res)
            if c.startswith("app update"):
                self.assertTrue(res == "", "Output is not empty for '%s'" % c)
            elif c.startswith("app list"):
                for search in ["Available applications", "AIM", "WWW"]:
                    self.assertTrue(
                        search in res, "Could not find '%s' in:\n%s" % (search, res)
                    )
            elif c.startswith("app info"):
                for search in ["Title: Web Server", "80/tcp"]:
                    self.assertTrue(
                        search in res, "Could not find '%s' in:\n%s" % (search, res)
                    )
            elif c.startswith("app default"):
                p = c.split()[-1]
                search = "Default application policy changed to '%s'" % p
                self.assertTrue(
                    search in res, "Could not find '%s' in:\n%s" % (search, res)
                )
            else:
                self.assertTrue(res != "", "Output is empty for '%s'" % c)

        pr = ufw.frontend.parse_command(["ufw", "app", "update", "--add-new", "all"])
        tests.unit.support.check_for_exception(
            self,
            ufw.common.UFWError,
            self.ui.do_application_action,
            pr.action,
            pr.data["name"],
        )

    def test_get_show_raw(self):
        """Test get_show_raw()"""
        res = self.ui.get_show_raw()
        search = "> Checking"
        self.assertTrue(search in res, "Could not find '%s' in:\n%s" % (search, res))

    def test_get_show_listening(self):
        """Test get_show_listening()"""
        res = self.ui.get_show_listening()
        for search in ["tcp", "udp"]:
            # self.assertTrue(search in res, \
            #                 "Could not find '%s' in:\n%s" % (search, res))
            if search not in res:
                print(
                    "(TODO: fake-netstat) Could not find '%s' in:\n%s" % (search, res)
                )

    def test_get_show_added(self):
        """Test get_show_added()"""
        res = self.ui.get_show_added()
        search = "(None)"
        self.assertTrue(search in res, "Could not find '%s' in:\n%s" % (search, res))

        c = "allow 12345"
        pr = ufw.frontend.parse_command(["ufw"] + c.split())
        self.ui.do_action(pr.action, pr.data["rule"], pr.data["iptype"], force=True)
        res = self.ui.get_show_added()
        search = c
        self.assertTrue(search in res, "Could not find '%s' in:\n%s" % (search, res))

    def test_application_add(self):
        """Test application_add()"""
        for i in ["accept", "drop", "reject"]:
            self.ui.backend.defaults["default_application_policy"] = i
            res = self.ui.application_add("WWW")
            for search in ["Rules updated", "Rules updated (v6)"]:
                self.assertTrue(
                    search in res, "Could not find '%s' in:\n%s" % (search, res)
                )
        self.ui.backend.defaults["default_application_policy"] = "bad"
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.ui.application_add, "WWW"
        )
        self.ui.backend.defaults["default_application_policy"] = "skip"


class SetRuleErrorPathsTestCase(FrontendTestBase):
    """set_rule()/parse_command() error handling and the multi-rule backout"""

    def test_parse_command_reraises_ufwerror(self):
        """Test parse_command() re-raises UFWError after error()"""
        # error() normally exits; neuter it so the re-raise is reachable
        with unittest.mock.patch.object(ufw.frontend, "error"):
            tests.unit.support.check_for_exception(
                self,
                ufw.common.UFWError,
                ufw.frontend.parse_command,
                ["ufw", "allow", "80:70000/tcp"],
            )

    def test_set_rule_app_remove_both(self):
        """Test set_rule() - remove app rule with ip_version 'both'"""
        ui = self._init_ui(dryrun=False)

        pr = ufw.frontend.parse_command(["ufw", "allow", "WWW"])
        ui.do_action(pr.action, pr.data["rule"], pr.data["iptype"], force=True)

        pr = ufw.frontend.parse_command(["ufw", "delete", "allow", "WWW"])
        res = ui.set_rule(pr.data["rule"], "both")
        self.assertTrue(res != "", "Output is empty")

    def test_set_rule_app_remove_both_v6_twin(self):
        """Test set_rule() - remove 'both' where v6 matches v4 modulo v6"""
        # rules from the system only differ by v6 when crafted (template
        # rules always differ in dst: 0.0.0.0/0 vs ::/0), so pin the lookup
        x = ufw.common.UFWRule("allow", "tcp", "80")
        x.dapp = "WWW"
        y = x.dup_rule()
        # flip only the flag (set_v6() would normalize dst/src to ::/0 and
        # the twins would no longer match modulo v6)
        y.v6 = True
        with unittest.mock.patch.object(
            self.ui.backend,
            "get_app_rules_from_system",
            side_effect=[[x], [y]],
        ):
            # only the v6-twin matching is under test; stub the backend
            # application of the resulting rules
            with unittest.mock.patch.object(
                self.ui.backend, "set_rule", return_value="ok"
            ):
                pr = ufw.frontend.parse_command(["ufw", "delete", "allow", "WWW"])
                res = self.ui.set_rule(pr.data["rule"], "both")
        self.assertTrue(res != "", "Output is empty")

    def test_set_rule_app_remove_nonexistent(self):
        """Test set_rule() - remove nonexistent app rule (v4 and v6)"""
        ui = self._init_ui(dryrun=False)

        pr = ufw.frontend.parse_command(["ufw", "delete", "allow", "WWW"])
        res = ui.set_rule(pr.data["rule"], "v4")
        self.assertEqual(res, "Could not delete non-existent rule")

        pr = ufw.frontend.parse_command(["ufw", "delete", "allow", "WWW"])
        res = ui.set_rule(pr.data["rule"], "v6")
        self.assertEqual(res, "Could not delete non-existent rule (v6)")

    def test_set_rule_invalid_ip_version_app_remove(self):
        """Test set_rule() - invalid ip_version with app rule removal"""
        pr = ufw.frontend.parse_command(["ufw", "delete", "allow", "WWW"])
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.ui.set_rule, pr.data["rule"], "bogus"
        )

    def test_set_rule_invalid_ip_version(self):
        """Test set_rule() - invalid ip_version (IPv6 enabled and disabled)"""
        # a single failing rule ends in error(); neuter it to return
        pr = ufw.frontend.parse_command(["ufw", "allow", "12345"])
        with unittest.mock.patch.object(ufw.frontend, "error") as m:
            self.ui.set_rule(pr.data["rule"], "bogus")
        m.assert_called_once_with("Invalid IP version 'bogus'")

        pr = ufw.frontend.parse_command(["ufw", "allow", "12345"])
        with unittest.mock.patch.object(
            self.ui.backend, "use_ipv6", return_value=False
        ):
            with unittest.mock.patch.object(ufw.frontend, "error") as m:
                self.ui.set_rule(pr.data["rule"], "bogus")
        m.assert_called_once_with("Invalid IP version 'bogus'")

    def test_set_rule_backout(self):
        """Test set_rule() - failing multi-rule application is backed out"""
        # CIFS expands to two rules; the first is accepted and the second
        # fails, forcing the backout of the first
        pr = ufw.frontend.parse_command(["ufw", "allow", "CIFS"])
        with unittest.mock.patch.object(
            self.ui.backend,
            "set_rule",
            side_effect=["", ufw.common.UFWError("boom")],
        ):
            try:
                self.ui.set_rule(pr.data["rule"], "v4")
                self.fail("UFWError not thrown")
            except ufw.common.UFWError as e:
                self.assertTrue("Error applying application rules" in e.value)
                self.assertTrue("successfully unapplied" in e.value)

    def test_set_rule_backout_undo_error(self):
        """Test set_rule() - failed backout of a failing application"""
        import io
        import sys

        pr = ufw.frontend.parse_command(["ufw", "allow", "CIFS"])
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        try:
            with unittest.mock.patch.object(
                self.ui.backend,
                "set_rule",
                side_effect=["", ufw.common.UFWError("boom")],
            ):
                # make the backout's removal lookups fail too
                with unittest.mock.patch.object(
                    self.ui.backend,
                    "get_app_rules_from_system",
                    side_effect=ufw.common.UFWError("nope"),
                ):
                    try:
                        self.ui.set_rule(pr.data["rule"], "v4")
                        self.fail("UFWError not thrown")
                    except ufw.common.UFWError as e:
                        self.assertTrue("Some rules could not be unapplied" in e.value)
            err = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr
        self.assertTrue("Could not back out rule" in err)


class DeleteRuleAndActionsTestCase(FrontendTestBase):
    """delete_rule() lookup/prompt paths and do_action() error edges"""

    def _rule(self, v6=False, forward=False):
        r = ufw.common.UFWRule("allow", "tcp", "22")
        r.v6 = v6
        r.forward = forward
        return r

    def test_delete_rule_bad_number(self):
        """Test delete_rule() - unparseable and out-of-range numbers"""
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.ui.delete_rule, "x", True
        )
        for n in ["0", "999"]:
            tests.unit.support.check_for_exception(
                self, ufw.common.UFWError, self.ui.delete_rule, n, True
            )

    def test_delete_rule_not_found(self):
        """Test delete_rule() - number in range but rule not found"""
        with unittest.mock.patch.object(
            self.ui.backend, "get_rules", return_value=[self._rule()]
        ):
            with unittest.mock.patch.object(
                self.ui.backend, "get_rule_by_number", return_value=None
            ):
                tests.unit.support.check_for_exception(
                    self, ufw.common.UFWError, self.ui.delete_rule, "1", True
                )

    def test_delete_rule_v6(self):
        """Test delete_rule() - v6 rule selects ip_version 'v6'"""
        rule = self._rule(v6=True)
        with unittest.mock.patch.object(
            self.ui.backend, "get_rules", return_value=[rule]
        ):
            with unittest.mock.patch.object(
                self.ui.backend, "get_rule_by_number", return_value=rule
            ):
                with unittest.mock.patch.object(
                    self.ui, "set_rule", return_value="deleted"
                ) as m:
                    res = self.ui.delete_rule("1", True)
        self.assertEqual(res, "deleted")
        m.assert_called_once_with(rule, "v6")

    def _delete_with_prompt(self, rule, answer):
        import io

        with unittest.mock.patch.object(
            self.ui.backend, "get_rules", return_value=[rule]
        ):
            with unittest.mock.patch.object(
                self.ui.backend, "get_rule_by_number", return_value=rule
            ):
                with unittest.mock.patch.object(
                    self.ui, "set_rule", return_value="deleted"
                ):
                    with unittest.mock.patch("sys.stdin", io.StringIO("%s\n" % answer)):
                        return self.ui.delete_rule("1", False)

    def test_delete_rule_prompt(self):
        """Test delete_rule() - interactive prompt"""
        res = self._delete_with_prompt(self._rule(), "n")
        self.assertEqual(res, "Aborted")

        res = self._delete_with_prompt(self._rule(), "y")
        self.assertEqual(res, "deleted")

        # route rules are displayed with the 'route' prefix
        res = self._delete_with_prompt(self._rule(forward=True), "y")
        self.assertEqual(res, "deleted")
        assert self.msg_output is not None
        self.assertTrue("route allow 22/tcp" in self.msg_output.getvalue())

    def test_do_action_bad_default_policy(self):
        """Test do_action() - malformed default- action"""
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.ui.do_action, "default-bogus", "", "", True
        )

    def test_do_action_remove_bad_appname_sapp(self):
        """Test do_action() remove bad appname (sapp)"""
        c = "delete allow from any app &^%$"
        pr = ufw.frontend.parse_command(["ufw"] + c.split())
        tests.unit.support.check_for_exception(
            self,
            ufw.common.UFWError,
            self.ui.do_action,
            pr.action,
            pr.data["rule"],
            pr.data["iptype"],
            True,
        )

    def test_do_action_unsupported(self):
        """Test do_action() - unsupported action"""
        tests.unit.support.check_for_exception(
            self, ufw.common.UFWError, self.ui.do_action, "bogus", "", "", True
        )


class ApplicationAndShowTestCase(FrontendTestBase):
    """Application-command internals, show helpers and reset()"""

    def test_get_show_listening_no_ipv6(self):
        """Test get_show_listening() - IPv6 disabled"""
        with unittest.mock.patch.object(
            self.ui.backend, "use_ipv6", return_value=False
        ):
            res = self.ui.get_show_listening()
        self.assertTrue(isinstance(res, str))

    def test_get_show_added_route(self):
        """Test get_show_added() - route rules carry the route prefix"""
        r = ufw.common.UFWRule("allow", "tcp", "22")
        r.forward = True
        with unittest.mock.patch.object(self.ui.backend, "get_rules", return_value=[r]):
            res = self.ui.get_show_added()
        self.assertTrue(
            "route allow 22/tcp" in res, "Could not find route rule in:\n%s" % res
        )

    def test_get_application_info_invalid_profile(self):
        """Test get_application_info() - profile fails verification"""
        with unittest.mock.patch("ufw.applications.verify_profile", return_value=False):
            tests.unit.support.check_for_exception(
                self, ufw.common.UFWError, self.ui.get_application_info, "WWW"
            )

    def test_application_update_found(self):
        """Test application_update() - updated profiles accumulate output"""
        with unittest.mock.patch.object(
            self.ui.backend, "update_app_rule", return_value=("Rules updated", True)
        ):
            res = self.ui.application_update("all")
        self.assertTrue("Rules updated\n" in res)

        with unittest.mock.patch.object(
            self.ui.backend, "update_app_rule", return_value=("Rules updated", True)
        ):
            res = self.ui.application_update("WWW")
        self.assertEqual(res, "Rules updated\n")

    def test_application_update_reload(self):
        """Test application_update() - firewall reload after update"""
        with unittest.mock.patch.object(
            self.ui.backend, "update_app_rule", return_value=("", True)
        ):
            with unittest.mock.patch.object(
                self.ui.backend, "is_enabled", return_value=True
            ):
                with unittest.mock.patch.object(
                    self.ui.backend, "_reload_user_rules"
                ) as m:
                    res = self.ui.application_update("WWW")
        self.assertEqual(res, "Firewall reloaded")
        m.assert_called_once_with()

    def test_application_update_reload_error(self):
        """Test application_update() - reload failure is re-raised"""
        with unittest.mock.patch.object(
            self.ui.backend, "update_app_rule", return_value=("", True)
        ):
            with unittest.mock.patch.object(
                self.ui.backend, "is_enabled", return_value=True
            ):
                with unittest.mock.patch.object(
                    self.ui.backend,
                    "_reload_user_rules",
                    side_effect=RuntimeError("boom"),
                ):
                    self.assertRaises(RuntimeError, self.ui.application_update, "WWW")

    def test_application_update_skip_reload_under_ssh(self):
        """Test application_update() - reload skipped under ssh"""
        self.ui.backend.do_checks = True
        try:
            with unittest.mock.patch("ufw.util.under_ssh", return_value=True):
                with unittest.mock.patch.object(
                    self.ui.backend,
                    "update_app_rule",
                    return_value=("", True),
                ):
                    with unittest.mock.patch.object(
                        self.ui.backend, "is_enabled", return_value=True
                    ):
                        res = self.ui.application_update("WWW")
        finally:
            self.ui.backend.do_checks = False
        self.assertEqual(res, "Skipped reloading firewall")

    def test_application_add_no_rule_data(self):
        """Test application_add() - parsed command without rule data"""
        pr = unittest.mock.MagicMock()
        pr.action = "allow"
        pr.data = {}
        self.ui.backend.defaults["default_application_policy"] = "accept"
        try:
            with unittest.mock.patch.object(
                ufw.frontend, "parse_command", return_value=pr
            ):
                with unittest.mock.patch.object(
                    self.ui, "do_action", return_value="ok"
                ) as m:
                    res = self.ui.application_add("WWW")
        finally:
            self.ui.backend.defaults["default_application_policy"] = "skip"
        self.assertEqual(res, "ok")
        m.assert_called_once_with("allow", "", "")

    def test_do_application_action_update_with_new(self):
        """Test do_application_action() - update-with-new joins output"""
        with unittest.mock.patch.object(
            self.ui, "application_update", return_value="updated"
        ):
            with unittest.mock.patch.object(
                self.ui, "application_add", return_value="added"
            ):
                res = self.ui.do_application_action("update-with-new", "WWW")
        self.assertEqual(res, "updated\nadded")

    def test_do_application_action_unsupported(self):
        """Test do_application_action() - unsupported action"""
        tests.unit.support.check_for_exception(
            self,
            ufw.common.UFWError,
            self.ui.do_application_action,
            "bogus",
            "WWW",
        )

    def test_reset_prompt_under_ssh(self):
        """Test reset() - ssh-aware prompt is selected"""
        self.ui.backend.do_checks = True
        try:
            with unittest.mock.patch("ufw.util.under_ssh", return_value=True):
                with unittest.mock.patch.object(
                    self.ui.backend, "reset", return_value="reset"
                ):
                    res = self.ui.reset(force=True)
        finally:
            self.ui.backend.do_checks = False
        self.assertEqual(res, "reset")


def test_main():  # used by runner.py
    tests.unit.support.run_unittest(
        FrontendTestCase,
        SetRuleErrorPathsTestCase,
        DeleteRuleAndActionsTestCase,
        ApplicationAndShowTestCase,
    )


if __name__ == "__main__":  # used when standalone
    unittest.main()
