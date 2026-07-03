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
# Functional tests converted from tests/good/

import glob
import os
import re
import unittest
from unittest import mock

import tests.functional.support
from tests.functional.commands import RuleCommands
from tests.functional.support import FunctionalTestCase


class GoodTests(RuleCommands, FunctionalTestCase):
    class_name = "good"

    def test_apps(self):
        """tests/good/apps"""
        # args
        self.assert_ok("app", "list")
        self.assert_ok("app", "info", "Apache")
        self.assert_ok("app", "info", "Apache Secure")
        self.assert_ok("app", "info", "Apache Full")
        self.assert_ok("app", "info", "Bind9")
        self.assert_ok("app", "info", "Samba")
        self.assert_ok("app", "info", "Custom Web App")
        self.assert_ok("app", "info", "Custom Web App2")
        self.assert_ok("app", "info", "all")
        self.assert_ok("app", "info", "0verkill")

        # simple rules
        for target in ("allow", "deny", "limit"):
            for app in (
                "Apache",
                "Apache Secure",
                "Apache Full",
                "Bind9",
                "Samba",
                "OpenNTPD",
                "Multi TCP",
                "Multi UDP",
                "Custom Web App2",
            ):
                self.assert_ok("--dry-run", target, app)

        # extended rules
        for target in ("allow", "deny", "limit"):
            for i in ("to", "from"):
                for loc in ("192.168.0.0/16", "any"):
                    for app in (
                        "Apache",
                        "Apache Secure",
                        "Apache Full",
                        "Bind9",
                        "Samba",
                        "OpenNTPD",
                        "Multi TCP",
                        "Multi UDP",
                    ):
                        self.assert_ok("--dry-run", target, i, loc, "app", app)
            for i in ("192.168.0", "any"):
                for j in ("from", "to"):
                    k = "from" if j == "to" else "to"
                    m = "%s.1" % i if i != "any" else "any"
                    n = "%s.2" % i if i != "any" else "any"
                    self.assert_ok(
                        "--dry-run", target, j, m, "app", "Apache", k, n, "port", "8080"
                    )
                    self.assert_ok(
                        "--dry-run",
                        target,
                        j,
                        m,
                        "app",
                        "OpenNTPD",
                        k,
                        n,
                        "port",
                        "10123",
                    )
                    self.assert_ok(
                        "--dry-run", target, j, m, "app", "Samba", k, n, "app", "Bind9"
                    )
                    self.assert_ok(
                        "--dry-run", target, j, m, "app", "Samba", k, n, "port", "13"
                    )
                    self.assert_ok(
                        "--dry-run",
                        target,
                        j,
                        m,
                        "app",
                        "Apache",
                        k,
                        n,
                        "app",
                        "Apache Full",
                    )
                loc = i if i == "any" else "%s.1" % i
                self.assert_ok(
                    "--dry-run",
                    target,
                    "to",
                    loc,
                    "app",
                    "Samba",
                    "from",
                    loc,
                    "app",
                    "Samba",
                )

        # case insensitive
        self.add_profile(
            "runtest",
            "[runtest]\ntitle=runtest title\ndescription=runtest description\n"
            "ports=23/tcp\n",
        )
        self.assert_ok("--dry-run", "allow", "runtest")
        self.assert_ok("--dry-run", "allow", "RunTest")
        self.remove(self.app_profile_path("runtest"))

        # update
        self.assert_ok("app", "default", "allow")
        self.assert_ok("--dry-run", "app", "update", "--add-new", "Apache")
        self.assert_ok("app", "default", "deny")
        self.assert_ok("--dry-run", "app", "update", "--add-new", "Samba")
        self.assert_ok("app", "default", "skip")
        self.assert_ok("--dry-run", "app", "update", "--add-new", "Bind9")
        self.assert_ok("app", "default", "reject")
        self.assert_ok("--dry-run", "app", "update", "--add-new", "Samba")

        # exact vs multi
        self.add_profile(
            "Runtest2",
            "[Runtest2]\ntitle=runtest title\ndescription=runtest description\n"
            "ports=23/tcp\n",
        )
        self.add_profile(
            "RunTest2",
            "[RunTest2]\ntitle=runtest title\ndescription=runtest description\n"
            "ports=24/tcp\n",
        )
        self.assert_ok("--dry-run", "allow", "RunTest2")
        self.remove(self.app_profile_path("Runtest2"))
        self.remove(self.app_profile_path("RunTest2"))

        # insert
        self.assert_ok("allow", "Apache")
        self.assert_ok("allow", "Bind9")
        self.assert_ok("insert", "1", "allow", "Samba")
        self.assert_ok("insert", "2", "reject", "Dovecot POP3")
        self.assertIn("dapp_Samba", self.read(self.user_rules))
        self.assert_ok("delete", "allow", "Apache")
        self.assert_ok("delete", "allow", "Bind9")
        self.assert_ok("delete", "allow", "Samba")
        self.assert_ok("delete", "reject", "Dovecot POP3")
        self.assertEqual(self.tuple_count(self.user_rules), 0)

        self.assert_ok("allow", "Samba")
        self.assert_ok("allow", "13")
        self.assert_ok(
            "insert",
            "2",
            "allow",
            "log-all",
            "from",
            "any",
            "to",
            "any",
            "app",
            "Samba",
        )
        self.assert_ok(
            "insert",
            "2",
            "allow",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "app",
            "Samba",
        )
        self.assert_ok(
            "insert", "2", "allow", "from", "192.168.0.1", "to", "any", "app", "Samba"
        )
        self.assert_ok(
            "insert",
            "2",
            "allow",
            "from",
            "192.168.0.1",
            "app",
            "Samba",
            "to",
            "10.0.0.1",
        )
        self.assert_ok(
            "insert", "2", "allow", "from", "any", "app", "Samba", "to", "10.0.0.1"
        )
        self.assert_ok("delete", "allow", "Samba")
        self.assert_ok("delete", "allow", "13")
        self.assert_ok(
            "delete", "allow", "log-all", "from", "any", "to", "any", "app", "Samba"
        )
        self.assert_ok(
            "delete", "allow", "from", "192.168.0.1", "to", "10.0.0.1", "app", "Samba"
        )
        self.assert_ok(
            "delete", "allow", "from", "192.168.0.1", "to", "any", "app", "Samba"
        )
        self.assert_ok(
            "delete", "allow", "from", "192.168.0.1", "app", "Samba", "to", "10.0.0.1"
        )
        self.assert_ok(
            "delete", "allow", "from", "any", "app", "Samba", "to", "10.0.0.1"
        )
        self.assertEqual(self.tuple_count(self.user_rules), 0)

        # interfaces
        for i in ("in", "out"):
            for j in ("allow", "deny", "limit", "reject"):
                self.assert_ok(j, i, "on", "eth0", "to", "192.168.0.1", "app", "Samba")
                self.assert_ok(j, i, "on", "eth0", "from", "10.0.0.1", "app", "Samba")
                self.assert_ok(
                    j, i, "on", "eth0", "from", "10.0.0.1", "to", "any", "app", "Samba"
                )
                self.assert_ok(
                    "delete", j, i, "on", "eth0", "to", "192.168.0.1", "app", "Samba"
                )
                self.assert_ok(
                    "delete", j, i, "on", "eth0", "from", "10.0.0.1", "app", "Samba"
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "from",
                    "10.0.0.1",
                    "to",
                    "any",
                    "app",
                    "Samba",
                )
            self.assert_ok("allow", i, "on", "eth0", "to", "any", "app", "Samba")
            self.assert_ok("allow", i, "on", "eth1", "to", "any", "port", "13")
            self.assert_ok(
                "insert", "2", "allow", i, "on", "eth2", "to", "any", "app", "Samba"
            )
            self.assert_ok(
                "delete", "allow", i, "on", "eth0", "to", "any", "app", "Samba"
            )
            self.assert_ok(
                "delete", "allow", i, "on", "eth1", "to", "any", "port", "13"
            )
            self.assert_ok(
                "delete", "allow", i, "on", "eth2", "to", "any", "app", "Samba"
            )

        # shipped application profiles (enumerated dynamically from the
        # ufw-* profiles in applications.d)
        names = []
        for path in sorted(glob.glob(os.path.join(self.appsd, "ufw-*"))):
            for line in self.read(path).splitlines():
                m = re.match(r"^\[(.*)\]", line)
                if m:
                    names.append(m.group(1))
        for name in names:
            self.assert_ok("app", "info", name)
            self.assert_ok("allow", name)
            self.assert_ok("delete", "allow", name)
        self.assertEqual(self.tuple_count(self.user_rules), 0)

        # Prepend
        self.assert_ok("allow", "to", "any", "app", "Samba")
        self.assert_ok(
            "prepend", "deny", "to", "any", "app", "Samba", "from", "10.0.0.1"
        )
        self.assert_ok("delete", "allow", "to", "any", "app", "Samba")
        self.assert_ok(
            "delete", "deny", "to", "any", "app", "Samba", "from", "10.0.0.1"
        )

        # Prepend (no rules)
        self.assert_ok(
            "prepend", "allow", "to", "any", "app", "Samba", "from", "10.0.0.1"
        )
        self.assert_ok(
            "delete", "allow", "to", "any", "app", "Samba", "from", "10.0.0.1"
        )

    def test_netmasks(self):
        """tests/good/netmasks"""
        # valid CIDR
        for i in range(0, 33):
            self.assert_ok("--dry-run", "allow", "from", "10.0.0.1/%d" % i)

        # valid dotted
        for i in range(0, 256, 16):
            self.assert_ok("--dry-run", "allow", "from", "10.0.0.1/255.255.255.%d" % i)
            self.assert_ok("--dry-run", "allow", "from", "10.0.0.1/255.255.%d.255" % i)
            self.assert_ok("--dry-run", "allow", "from", "10.0.0.1/255.%d.255.255" % i)
            self.assert_ok("--dry-run", "allow", "from", "10.0.0.1/%d.255.255.255" % i)
            self.assert_ok(
                "--dry-run", "allow", "from", "10.0.0.1/%d.%d.%d.%d" % (i, i, i, i)
            )

    def test_policy(self):
        """tests/good/policy"""
        # good default policy
        for i in ("INPUT", "OUTPUT", "FORWARD"):
            for j in ("ACCEPT", "DROP", "REJECT"):
                self.set_default("DEFAULT_%s_POLICY" % i, j)
                self.assert_ok("--dry-run", "status")
                # put it back to something valid
                self.set_default("DEFAULT_%s_POLICY" % i, "DROP")

        # args (default)
        for i in ("", "incoming", "outgoing", "input", "output"):
            for j in ("allow", "deny", "reject", "ALLOW", "DENY", "REJECT"):
                self.assert_ok("--dry-run", "default", j, *i.split())

    def test_args(self):
        """tests/good/args"""
        # logging
        self.assert_ok("--dry-run", "logging", "on")
        self.assert_ok("--dry-run", "logging", "off")
        self.assert_ok("--dry-run", "LOGGING", "ON")
        self.assert_ok("--dry-run", "LOGGING", "OFF")

        # enable/disable
        self.assert_ok("--dry-run", "enable")
        self.assert_ok("--dry-run", "disable")
        self.assert_ok("--dry-run", "ENABLE")
        self.assert_ok("--dry-run", "DISABLE")

        # status
        self.assert_ok("--dry-run", "status")
        self.assert_ok("--dry-run", "status", "verbose")
        self.assert_ok("--dry-run", "status", "numbered")

        # parser: basic. version/--version are replayed here for routing/parity
        # like every other command; from src/ the #VERSION# token is unsubstituted,
        # so the transcript pins it literally. The real substituted version string
        # is asserted against the installed artifact by
        # SubprocessTestCase.test_version.
        for i in (
            "enable",
            "disable",
            "help",
            "--help",
            "version",
            "--version",
            "reload",
        ):
            self.assert_ok("--dry-run", i)

        # application
        self.assert_ok("--dry-run", "app", "list")
        self.assert_ok("--dry-run", "app", "info", "Apache")
        self.assert_ok("--dry-run", "app", "update", "Apache")
        self.assert_ok("--dry-run", "app", "update", "--add-new", "Apache")
        self.assert_ok("--dry-run", "app", "default", "skip")

        # logging
        for i in ("on", "off", "low", "medium", "high", "full"):
            self.assert_ok("--dry-run", "logging", i)

        # default
        for i in ("allow", "deny", "reject"):
            self.assert_ok("--dry-run", "default", i)
            self.assert_ok("--dry-run", "default", i, "incoming")
            self.assert_ok("--dry-run", "default", i, "outgoing")
            self.assert_ok("--dry-run", "default", i, "routed")

        # status
        for i in ("", "verbose", "numbered"):
            self.assert_ok("--dry-run", "status", *i.split())

        # show
        for i in (
            "raw",
            "builtins",
            "before-rules",
            "user-rules",
            "after-rules",
            "logging-rules",
        ):
            self.assert_ok("--dry-run", "show", i)

        # rules
        self.assert_ok("allow", "80")
        self.assert_ok("--dry-run", "insert", "1", "allow", "53")
        self.assert_ok("delete", "allow", "80")
        self.assert_ok("--dry-run", "allow", "in", "53")
        self.assert_ok("--dry-run", "allow", "log", "53")
        self.assert_ok("--dry-run", "allow", "in", "log", "53")

        self.assert_ok("deny", "to", "any", "port", "80", "from", "any", "proto", "tcp")
        self.assert_ok(
            "--dry-run",
            "insert",
            "1",
            "deny",
            "to",
            "any",
            "port",
            "53",
            "from",
            "any",
            "proto",
            "udp",
        )
        self.assert_ok(
            "delete", "deny", "to", "any", "port", "80", "from", "any", "proto", "tcp"
        )
        self.assert_ok(
            "--dry-run",
            "deny",
            "out",
            "to",
            "any",
            "port",
            "53",
            "from",
            "any",
            "proto",
            "udp",
        )
        self.assert_ok(
            "--dry-run",
            "deny",
            "log-all",
            "to",
            "any",
            "port",
            "53",
            "from",
            "any",
            "proto",
            "udp",
        )
        self.assert_ok(
            "--dry-run",
            "deny",
            "out",
            "log-all",
            "to",
            "any",
            "port",
            "53",
            "from",
            "any",
            "proto",
            "udp",
        )

        # --force enable
        self.assert_ok("--dry-run", "--force", "enable")
        self.assert_ok("--dry-run", "-f", "enable")
        self.assert_ok("--dry-run", "--force", "ENABLE")
        self.assert_ok("--dry-run", "-f", "ENABLE")
        self.assert_ok("--dry-run", "disable")

    # destination specs shared by the add/delete loops in test_reports
    _REPORT_DESTS = [
        ["to", "any"],
        ["to", "any", "proto", "udp"],
        ["to", "any", "proto", "tcp"],
        ["to", "10.0.2.101"],
        ["to", "10.0.2.9"],
        ["to", "10.0.0.0/16"],
        ["to", "10.0.2.0/24"],
        ["to", "10.0.3.0/24"],
        ["to", "2001::211:aaaa:bbbb:d54c"],
        ["to", "2001::211:aaaa:bbbb:d54c/112"],
        ["to", "10.0.2.101", "port", "123"],
        ["to", "10.0.0.0/16", "port", "123"],
        ["to", "10.0.2.0/24", "port", "123"],
        ["to", "10.0.3.0/24", "port", "123"],
        ["to", "2001::211:aaaa:bbbb:d54c", "port", "123"],
        ["to", "2001::211:aaaa:bbbb:d54c/112", "port", "123"],
        ["to", "10.0.2.101", "port", "123", "proto", "udp"],
        ["to", "10.0.0.0/16", "app", "OpenNTPD"],
        ["to", "10.0.2.0/24", "port", "123", "proto", "udp"],
        ["to", "10.0.3.0/24", "port", "123", "proto", "udp"],
        ["to", "2001::211:aaaa:bbbb:d54c", "port", "123", "proto", "udp"],
        ["to", "2001::211:aaaa:bbbb:d54c/112", "port", "123", "proto", "udp"],
        ["to", "10.0.2.101", "port", "123", "proto", "tcp"],
        ["to", "10.0.0.0/16", "port", "123", "proto", "tcp"],
        ["to", "10.0.2.0/24", "port", "123", "proto", "tcp"],
        ["to", "10.0.3.0/24", "port", "123", "proto", "tcp"],
        ["to", "2001::211:aaaa:bbbb:d54c", "port", "123", "proto", "tcp"],
        ["to", "2001::211:aaaa:bbbb:d54c/112", "port", "123", "proto", "tcp"],
    ]

    def _report_rules(self, delete):
        pre = ["delete"] if delete else []
        for i in ("", "in on eth0"):
            parts = i.split()
            if i == "":
                self.assert_ok(*pre, "allow", "in", "123")
                self.assert_ok(*pre, "allow", "in", "OpenNTPD")
                self.assert_ok(*pre, "allow", "in", "123/tcp")
            else:
                self.assert_ok(*pre, "allow", "out", "123")
                self.assert_ok(*pre, "allow", "out", "123/udp")
                self.assert_ok(*pre, "allow", "out", "123/tcp")
            for dest in self._REPORT_DESTS:
                self.assert_ok(*pre, "allow", *parts, *dest)

    def test_reports(self):
        """tests/good/reports"""
        self.enable_ipv6()
        with mock.patch(
            "ufw.util.get_netstat_output",
            tests.functional.support.reports_netstat_output,
        ), mock.patch(
            "ufw.util.get_ip_from_if", tests.functional.support.reports_get_ip_from_if
        ), mock.patch(
            "ufw.util.get_if_from_ip", tests.functional.support.reports_get_if_from_ip
        ):
            # show listening with no rules
            self.assert_ok("show", "listening")

            # add rules for test
            self._report_rules(delete=False)

            # show listening with rules
            out = self.assert_ok("show", "listening")
            self.assertIn("123", out)
            self.assertIn("OpenNTPD", out)

            # cleanup the above rules
            self._report_rules(delete=True)

            # show listening (live) with rules (output not asserted; environment-specific)
            self.assert_ok("allow", "13/tcp")
            self.assert_ok("allow", "123/udp")
            self.assert_ok("show", "listening")
            self.assert_ok("delete", "allow", "13/tcp")
            self.assert_ok("delete", "allow", "123/udp")

            # show added
            self.assert_ok("limit", "13/tcp")
            self.assert_ok(
                "allow",
                "in",
                "on",
                "eth0",
                "to",
                "2001::211:aaaa:bbbb:d54c",
                "port",
                "123",
                "proto",
                "tcp",
            )
            self.assert_ok("deny", "Samba")
            out = self.assert_ok("show", "added")
            self.assertIn("13/tcp", out)
            self.assertIn("Samba", out)
            self.assert_ok("delete", "limit", "13/tcp")
            self.assert_ok("show", "added")
            self.assert_ok(
                "delete",
                "allow",
                "in",
                "on",
                "eth0",
                "to",
                "2001::211:aaaa:bbbb:d54c",
                "port",
                "123",
                "proto",
                "tcp",
            )
            self.assert_ok("show", "added")
            self.assert_ok("delete", "deny", "Samba")
            self.assert_ok("show", "added")

    def test_route(self):
        """tests/good/route"""
        in_if = "fake0"
        out_if = "fake1"
        frm = "192.168.0.1"
        to = "10.0.0.1"

        # Man page
        self.assert_ok(
            "--dry-run",
            "route",
            "deny",
            "proto",
            "udp",
            "from",
            "1.2.3.4",
            "to",
            "any",
            "port",
            "514",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "deny",
            "proto",
            "udp",
            "from",
            "1.2.3.4",
            "to",
            "any",
            "port",
            "514",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "allow",
            "proto",
            "udp",
            "from",
            "1.2.3.5",
            "port",
            "5469",
            "to",
            "1.2.3.4",
            "port",
            "5469",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "allow",
            "proto",
            "udp",
            "from",
            "1.2.3.5",
            "port",
            "5469",
            "to",
            "1.2.3.4",
            "port",
            "5469",
        )

        # SIMPLE
        self.assert_ok("--dry-run", "route", "allow", "daytime")
        self.assert_ok("--dry-run", "route", "delete", "allow", "daytime")
        self.assert_ok("--dry-run", "route", "allow", "daytime/tcp")
        self.assert_ok("--dry-run", "route", "delete", "allow", "daytime/tcp")
        self.assert_ok("--dry-run", "route", "allow", "daytime/udp")
        self.assert_ok("--dry-run", "route", "delete", "allow", "daytime/udp")

        # Interfaces
        self.assert_ok("--dry-run", "route", "allow", "in", "on", in_if)
        self.assert_ok("--dry-run", "route", "delete", "allow", "in", "on", in_if)
        self.assert_ok("--dry-run", "route", "deny", "out", "on", out_if)
        self.assert_ok("--dry-run", "route", "delete", "deny", "out", "on", out_if)

        # TO/FROM
        self.assert_ok("--dry-run", "route", "allow", "from", frm)
        self.assert_ok("--dry-run", "route", "delete", "allow", "from", frm)
        self.assert_ok("--dry-run", "route", "deny", "to", to)
        self.assert_ok("--dry-run", "route", "delete", "deny", "to", to)
        self.assert_ok("--dry-run", "route", "limit", "to", to, "from", frm)
        self.assert_ok("--dry-run", "route", "delete", "limit", "to", to, "from", frm)

        self.assert_ok("--dry-run", "route", "allow", "in", "on", in_if, "from", frm)
        self.assert_ok(
            "--dry-run", "route", "delete", "allow", "in", "on", in_if, "from", frm
        )
        self.assert_ok("--dry-run", "route", "deny", "out", "on", out_if, "to", to)
        self.assert_ok(
            "--dry-run", "route", "delete", "deny", "out", "on", out_if, "to", to
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "limit",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "from",
            frm,
            "to",
            to,
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "limit",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "from",
            frm,
            "to",
            to,
        )

        self.assert_ok("--dry-run", "route", "allow", "from", frm, "port", "80")
        self.assert_ok(
            "--dry-run", "route", "delete", "allow", "from", frm, "port", "80"
        )
        self.assert_ok("--dry-run", "route", "deny", "to", to, "port", "25")
        self.assert_ok("--dry-run", "route", "delete", "deny", "to", to, "port", "25")
        self.assert_ok(
            "--dry-run",
            "route",
            "limit",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "from",
            frm,
            "port",
            "25",
            "to",
            to,
            "port",
            "25",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "limit",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "from",
            frm,
            "port",
            "25",
            "to",
            to,
            "port",
            "25",
            "proto",
            "tcp",
        )

        # Services
        self.assert_ok(
            "--dry-run",
            "route",
            "allow",
            "to",
            "any",
            "port",
            "smtp",
            "from",
            "any",
            "port",
            "smtp",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "allow",
            "to",
            "any",
            "port",
            "smtp",
            "from",
            "any",
            "port",
            "smtp",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "allow",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "to",
            "any",
            "port",
            "smtp",
            "from",
            "any",
            "port",
            "smtp",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "allow",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "to",
            "any",
            "port",
            "smtp",
            "from",
            "any",
            "port",
            "smtp",
        )

        # Netmasks
        self.assert_ok(
            "--dry-run",
            "route",
            "reject",
            "from",
            "192.168.0.1/32",
            "to",
            "192.168.0.0/16",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "reject",
            "from",
            "192.168.0.1/32",
            "to",
            "192.168.0.0/16",
        )

        # Multiports
        self.assert_ok("--dry-run", "route", "limit", "23,21,15:19,13/tcp")
        self.assert_ok("--dry-run", "route", "delete", "limit", "23,21,15:19,13/tcp")
        self.assert_ok(
            "--dry-run",
            "route",
            "allow",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "from",
            "192.168.0.1",
            "port",
            "23,21,15:19,13",
            "to",
            "10.0.0.0/8",
            "port",
            "24:26",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "allow",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "from",
            "192.168.0.1",
            "port",
            "23,21,15:19,13",
            "to",
            "10.0.0.0/8",
            "port",
            "24:26",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "deny",
            "in",
            "on",
            in_if,
            "to",
            "any",
            "port",
            "34,35:39",
            "from",
            "any",
            "port",
            "24",
            "proto",
            "udp",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "deny",
            "in",
            "on",
            in_if,
            "to",
            "any",
            "port",
            "34,35:39",
            "from",
            "any",
            "port",
            "24",
            "proto",
            "udp",
        )

        # Insert
        self.assert_ok("route", "allow", "13")
        self.assert_ok("route", "allow", "23")
        self.assert_ok("route", "insert", "1", "allow", "9999")
        self.assert_ok("route", "insert", "1", "allow", "log", "9998")
        self.assert_ok(
            "route", "insert", "2", "reject", "to", "192.168.0.1", "from", "10.0.0.1"
        )
        # on-disk: five route rules now present
        self.assertEqual(self.tuple_count(self.user_rules), 5)
        self.assertIn("9999", self.read(self.user_rules))

        self.assert_ok("route", "delete", "allow", "13")
        self.assert_ok("route", "delete", "allow", "23")
        self.assert_ok("route", "delete", "allow", "9999")
        self.assert_ok("route", "delete", "allow", "log", "9998")
        self.assert_ok(
            "route", "delete", "reject", "to", "192.168.0.1", "from", "10.0.0.1"
        )
        # on-disk: all removed
        self.assertEqual(self.tuple_count(self.user_rules), 0)

        # ipv6 protocols
        self.assert_ok(
            "--dry-run",
            "route",
            "allow",
            "in",
            "on",
            in_if,
            "to",
            "10.0.0.1",
            "proto",
            "ipv6",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "allow",
            "in",
            "on",
            in_if,
            "to",
            "10.0.0.1",
            "proto",
            "ipv6",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "deny",
            "out",
            "on",
            out_if,
            "to",
            "10.0.0.1",
            "from",
            "10.4.0.0/16",
            "proto",
            "ah",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "deny",
            "out",
            "on",
            out_if,
            "to",
            "10.0.0.1",
            "from",
            "10.4.0.0/16",
            "proto",
            "ah",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "limit",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "to",
            "10.0.0.1",
            "proto",
            "esp",
        )
        self.assert_ok(
            "--dry-run",
            "route",
            "delete",
            "limit",
            "in",
            "on",
            in_if,
            "out",
            "on",
            out_if,
            "to",
            "10.0.0.1",
            "proto",
            "esp",
        )

    def test_logging(self):
        """tests/good/logging"""
        # loglevels: 'logging' persists LOGLEVEL even under --dry-run
        for i in (
            "off",
            "low",
            "medium",
            "high",
            "full",
            "OFF",
            "LOW",
            "MEDIUM",
            "HIGH",
            "FULL",
        ):
            self.assert_ok("--dry-run", "logging", i)
            self.assertRegex(self.read(self.ufw_conf), r"(?m)^LOGLEVEL=%s$" % i.lower())

        # loglevels ('on'): 'on' -> 'low' when off, else keeps the current level
        for i, exp in (
            ("off", "off"),
            ("on", "low"),
            ("medium", "medium"),
            ("on", "medium"),
        ):
            self.assert_ok("--dry-run", "logging", i)
            self.assertRegex(self.read(self.ufw_conf), r"(?m)^LOGLEVEL=%s$" % exp)

        # log rules
        for i in ("allow", "deny", "limit", "reject"):
            for j in ("log", "log-all"):
                self.assert_ok(i, j, "23")
                self.assert_ok(i, j, "smtp")
                self.assert_ok(i, j, "tftp")
                self.assert_ok(i, j, "daytime")
                self.assert_ok(i, j, "Samba")
                self.assert_ok(i, j, "Apache")
                self.assert_ok(
                    i,
                    j,
                    "from",
                    "192.168.0.1",
                    "port",
                    "smtp",
                    "to",
                    "10.0.0.1",
                    "port",
                    "smtp",
                )
                self.assert_ok(
                    i,
                    j,
                    "from",
                    "192.168.0.1",
                    "app",
                    "Samba",
                    "to",
                    "10.0.0.1",
                    "app",
                    "Samba",
                )
                # on-disk: log rules were written
                rules = self.read(self.user_rules)
                self.assertIn("LOG", rules)
                self.assertIn("23", rules)

                self.assert_ok("delete", i, j, "23")
                self.assert_ok("delete", i, j, "smtp")
                self.assert_ok("delete", i, j, "tftp")
                self.assert_ok("delete", i, j, "daytime")
                self.assert_ok("delete", i, j, "Samba")
                self.assert_ok("delete", i, j, "Apache")
                self.assert_ok(
                    "delete",
                    i,
                    j,
                    "from",
                    "192.168.0.1",
                    "port",
                    "smtp",
                    "to",
                    "10.0.0.1",
                    "port",
                    "smtp",
                )
                self.assert_ok(
                    "delete",
                    i,
                    j,
                    "from",
                    "192.168.0.1",
                    "app",
                    "Samba",
                    "to",
                    "10.0.0.1",
                    "app",
                    "Samba",
                )
                # on-disk: all removed again
                self.assertEqual(self.tuple_count(self.user_rules), 0)

        # log rules (updating)
        self.assert_ok("allow", "log", "Samba")
        self.assert_ok(
            "deny",
            "log-all",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "23",
            "proto",
            "tcp",
        )
        self.assert_ok("limit", "log", "Samba")
        self.assert_ok(
            "reject",
            "log-all",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "23",
            "proto",
            "tcp",
        )
        self.assert_ok("delete", "limit", "log", "Samba")
        self.assert_ok(
            "delete",
            "reject",
            "log-all",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "23",
            "proto",
            "tcp",
        )

        # log rules (interfaces)
        self.assert_ok("allow", "in", "on", "eth0", "log")
        self.assert_ok(
            "allow",
            "in",
            "on",
            "eth0",
            "log",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "24",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "deny",
            "in",
            "on",
            "eth0",
            "log-all",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "25",
            "proto",
            "tcp",
        )
        self.assert_ok("allow", "out", "on", "eth0", "log")
        self.assert_ok(
            "allow",
            "out",
            "on",
            "eth0",
            "log",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "24",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "deny",
            "out",
            "on",
            "eth0",
            "log-all",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "25",
            "proto",
            "tcp",
        )
        self.assert_ok("delete", "allow", "in", "on", "eth0", "log")
        self.assert_ok(
            "delete",
            "allow",
            "in",
            "on",
            "eth0",
            "log",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "24",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "delete",
            "deny",
            "in",
            "on",
            "eth0",
            "log-all",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "25",
            "proto",
            "tcp",
        )
        self.assert_ok("delete", "allow", "out", "on", "eth0", "log")
        self.assert_ok(
            "delete",
            "allow",
            "out",
            "on",
            "eth0",
            "log",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "24",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "delete",
            "deny",
            "out",
            "on",
            "eth0",
            "log-all",
            "from",
            "192.168.0.1",
            "to",
            "10.0.0.1",
            "port",
            "25",
            "proto",
            "tcp",
        )
        # on-disk: all interface log rules removed
        self.assertEqual(self.tuple_count(self.user_rules), 0)

        # writing loglevels (these persist)
        for i in ("off", "low", "medium", "high", "full", "on"):
            self.assert_ok("logging", i)
            if i == "on":
                self.assertNotRegex(self.read(self.ufw_conf), r"(?m)^LOGLEVEL=off$")
            else:
                self.assertRegex(self.read(self.ufw_conf), r"(?m)^LOGLEVEL=%s$" % i)
            self.assert_ok("--dry-run", "allow", "13")


def test_main():
    tests.functional.support.run_unittest(GoodTests)


if __name__ == "__main__":
    unittest.main()
