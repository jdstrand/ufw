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
# Functional tests converted from tests/bad/

import unittest

import tests.functional.support
from tests.functional.support import FunctionalTestCase

# Long multiport lists used by test_args (mirrors tests/bad/args/runtest.sh).
MP = "20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35"
MP36 = "20,21,22,23,24,25,26,27,28,29,30,31,32,33,34:36"
MP39 = "20,21,22,23,24,25,26,27,28,29,30,31,32,33,34:39"


class BadTests(FunctionalTestCase):
    class_name = "bad"

    def test_policy(self):
        """tests/bad/policy"""
        for i in ("INPUT", "OUTPUT", "FORWARD"):
            for j in ("", "ACCEP", "DRP", "REJCT", "ALLOW", "DENY", "LIMIT"):
                self.set_default("DEFAULT_%s_POLICY" % i, j)
                self.assert_fail("--dry-run", "status")
                # put it back to something valid
                self.set_default("DEFAULT_%s_POLICY" % i, "DROP")

    def test_netmasks(self):
        """tests/bad/netmasks"""
        # invalid CIDR
        for i in ("16a", "33", "-1"):
            self.assert_fail("--dry-run", "allow", "to", "10.0.0.1/%s" % i)
            self.assert_fail("--dry-run", "allow", "from", "10.0.0.1/%s" % i)

        # invalid dotted
        five = [
            "256.255.255.255",
            "255.256.255.255",
            "255.256.256.255",
            "255.255.255.256",
            "256.256.256.256",
        ]
        for m in five:
            self.assert_fail("--dry-run", "allow", "to", "192.168.0.0/%s" % m)
        for m in five:
            self.assert_fail("--dry-run", "allow", "from", "192.168.0.0/%s" % m)
        self.assert_fail(
            "--dry-run",
            "allow",
            "from",
            "192.168.0.0/33",
            "to",
            "192.168.0.0/256.256.256.256",
        )

        masks = [
            ".255.255.255",
            "255.255.255.",
            "255.255.255",
            "s55.255.255.255",
            "255.2s5.255.255",
            "255.255.25s.255",
            "255.255.255.s55",
            "s55.s55.s55.s55",
            "-1.255.255.255",
            "255.-1.255.255",
            "255.255.-1.255",
            "255.255.255.-1",
            "-1.-1.-1.-1",
        ]
        for m in masks:
            self.assert_fail("--dry-run", "allow", "to", "192.168.0.0/%s" % m)
        for m in masks:
            self.assert_fail("--dry-run", "allow", "from", "192.168.0.0/%s" % m)

    def test_args(self):
        """tests/bad/args"""
        # logging
        self.assert_fail("--dry-run", "logging")
        self.assert_fail("--dry-run", "logging", "foo")
        self.assert_fail("--dry-run", "loggin", "on")

        # default
        for i in ("", "input", "incoming", "output", "outgoing", "routed"):
            self.assert_fail("--dry-run", "default", *i.split())
            self.assert_fail("--dry-run", "default", "foo", *i.split())
            self.assert_fail("--dry-run", "default", "accept", *i.split())
            self.assert_fail("--dry-run", "defaul", "allow", *i.split())
            self.assert_fail("--dry-run", "default", "limit", *i.split())

        # enable/disable
        self.assert_fail("--dry-run", "enabled")
        self.assert_fail("--dry-run", "disabled")
        self.assert_fail("--dry-run", "enable", "OpenSSH")
        self.assert_fail("--dry-run", "disable", "OpenSSH")

        # allow/deny/limit (missing args)
        self.assert_fail("--dry-run", "allow")
        self.assert_fail("--dry-run", "deny")
        self.assert_fail("--dry-run", "limit")

        # allow/deny/limit bad port
        self.assert_fail("--dry-run", "alow", "25")
        self.assert_fail("--dry-run", "dny", "25")
        self.assert_fail("--dry-run", "limt", "25")
        self.assert_fail("--dry-run", "allow", "25a")
        self.assert_fail("--dry-run", "deny", "25a")
        self.assert_fail("--dry-run", "limit", "25a")
        self.assert_fail("--dry-run", "allow", "65536")
        self.assert_fail("--dry-run", "deny", "65536")
        self.assert_fail("--dry-run", "limit", "65536")
        self.assert_fail("--dry-run", "allow", "0")
        self.assert_fail("--dry-run", "deny", "0")
        self.assert_fail("--dry-run", "limit", "0")
        self.assert_fail("--dry-run", "deny", "XXX")
        self.assert_fail("--dry-run", "deny", "foobar")

        # allow/deny/limit bad to/from
        ip = "192.168.0.1"
        for action in ("allow", "deny", "limit"):
            self.assert_fail("--dry-run", action, "prot", "tcp", "from", "any")
            self.assert_fail("--dry-run", action, "proto", "tcp", "fro", "any")
            self.assert_fail("--dry-run", action, "proto", "tcp", "top", "any")
            self.assert_fail(
                "--dry-run", action, "proto", "tcp", "to", "any", "por", "25"
            )

            self.assert_fail("--dry-run", action, "port", "25")
            self.assert_fail("--dry-run", action, "to", "anu")
            self.assert_fail(
                "--dry-run", action, "proto", "tcq", "to", "any", "port", "25"
            )
            self.assert_fail(
                "--dry-run",
                action,
                "proto",
                "tcp",
                "proto",
                "udp",
                "to",
                "any",
                "port",
                "25",
            )

            self.assert_fail("--dry-run", action, "to")
            self.assert_fail("--dry-run", action, "to", "port", "25")

            self.assert_fail("--dry-run", action, "from")
            self.assert_fail("--dry-run", action, "from", "port", "25")

            self.assert_fail("--dry-run", action, "to", "any", "port")
            self.assert_fail("--dry-run", action, "to", "port", "25")

            self.assert_fail("--dry-run", action, "from", ip, "to")
            self.assert_fail("--dry-run", action, "from", ip, "from")
            self.assert_fail("--dry-run", action, "from", ip, "port", "25", "to")
            self.assert_fail("--dry-run", action, "from", ip, "port", "25", "from")

            self.assert_fail("--dry-run", action, "to", ip, "from")
            self.assert_fail("--dry-run", action, "to", ip, "to")
            self.assert_fail("--dry-run", action, "to", ip, "port", "smtp", "from")
            self.assert_fail("--dry-run", action, "to", ip, "port", "smtp", "to")

            self.assert_fail("--dry-run", action, "to", "from", ip)
            self.assert_fail("--dry-run", action, "from", "to", ip)
            self.assert_fail("--dry-run", action, "to", "from", ip, "port", "25")
            self.assert_fail("--dry-run", action, "from", "to", ip, "port", "25")

            self.assert_fail("--dry-run", action, "from", "from", ip)
            self.assert_fail("--dry-run", action, "to", "to", ip)
            self.assert_fail("--dry-run", action, "from", "from", ip, "port", "smtp")
            self.assert_fail("--dry-run", action, "to", "to", ip, "port", "smtp")

        # bad ip
        self.assert_fail("--dry-run", "allow", "to", "192.168.0.")
        self.assert_fail("--dry-run", "allow", "to", "192.168.0.1.1")
        self.assert_fail("--dry-run", "allow", "to", "foo")
        self.assert_fail("--dry-run", "allow", "to", "xxx.xxx.xxx.xx")
        self.assert_fail("--dry-run", "allow", "to", "192a.168.0.1")
        self.assert_fail("--dry-run", "allow", "to", "192.168a.0.1")
        self.assert_fail("--dry-run", "allow", "to", "192.168.0a.1")
        self.assert_fail("--dry-run", "allow", "to", "192.168.1.a1")
        self.assert_fail("--dry-run", "allow", "to", "192.168.1..1")
        self.assert_fail("--dry-run", "allow", "to", "192.168.1..1/24")
        self.assert_fail("--dry-run", "allow", "to", "192.168.1.256")
        self.assert_fail("--dry-run", "allow", "to", "256.0.0.0")
        self.assert_fail("--dry-run", "allow", "to", "10.256.0.0")

        # delete
        self.assert_fail("--dry-run", "delete")

        # allow/deny/limit mixed ipv4/ipv6
        self.assert_fail(
            "--dry-run", "allow", "to", "10.0.0.1", "from", "2001:db8::/32"
        )
        self.assert_fail(
            "--dry-run",
            "deny",
            "to",
            "10.0.0.1",
            "port",
            "25",
            "from",
            "2001:db8::/32",
            "proto",
            "tcp",
        )
        self.assert_fail(
            "--dry-run",
            "limit",
            "to",
            "10.0.0.1",
            "port",
            "25",
            "from",
            "2001:db8::/32",
            "proto",
            "tcp",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "to",
            "2001:db8::/32",
            "port",
            "25",
            "from",
            "10.0.0.1",
            "proto",
            "udp",
        )
        self.assert_fail("--dry-run", "deny", "to", "2001:db8::/32", "from", "10.0.0.1")
        self.assert_fail(
            "--dry-run", "limit", "to", "2001:db8::/32", "from", "10.0.0.1"
        )

        # allow/deny/limit ipv6 when not enabled
        self.assert_fail(
            "--dry-run",
            "deny",
            "proto",
            "tcp",
            "from",
            "2001:db8::/32",
            "to",
            "any",
            "port",
            "25",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "proto",
            "tcp",
            "from",
            "2001:db8::/32",
            "port",
            "25",
            "to",
            "any",
        )
        self.assert_fail(
            "--dry-run",
            "limit",
            "proto",
            "tcp",
            "from",
            "2001:db8::/32",
            "port",
            "25",
            "to",
            "any",
        )
        self.assert_fail(
            "--dry-run",
            "deny",
            "proto",
            "udp",
            "to",
            "2001:db8::/32",
            "from",
            "any",
            "port",
            "25",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "proto",
            "udp",
            "to",
            "2001:db8::/32",
            "port",
            "25",
            "from",
            "any",
        )
        self.assert_fail(
            "--dry-run",
            "limit",
            "proto",
            "udp",
            "to",
            "2001:db8::/32",
            "port",
            "25",
            "from",
            "any",
        )

        # bad services
        self.assert_fail("--dry-run", "allow", "smtp/esp")
        self.assert_fail("--dry-run", "allow", "tftp/tcp")
        self.assert_fail(
            "--dry-run",
            "allow",
            "to",
            "any",
            "port",
            "smtp",
            "from",
            "any",
            "port",
            "tftp",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "to",
            "any",
            "port",
            "tftp",
            "from",
            "any",
            "port",
            "smtp",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "to",
            "any",
            "port",
            "smtp",
            "from",
            "any",
            "port",
            "23",
            "proto",
            "esp",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "to",
            "any",
            "port",
            "23",
            "from",
            "any",
            "port",
            "smtp",
            "proto",
            "esp",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "to",
            "any",
            "port",
            "tftp",
            "from",
            "any",
            "port",
            "23",
            "proto",
            "tcp",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "to",
            "any",
            "port",
            "23",
            "from",
            "any",
            "port",
            "tftp",
            "proto",
            "tcp",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "to",
            "any",
            "port",
            "smtp",
            "from",
            "any",
            "port",
            "daytime",
            "proto",
            "esp",
        )
        self.assert_fail(
            "--dry-run",
            "allow",
            "to",
            "any",
            "port",
            "tftp",
            "from",
            "any",
            "port",
            "daytime",
            "proto",
            "tcp",
        )

        # bad multiports (extended syntax)
        for i in ("allow", "deny", "limit"):
            for j in ("from", "to"):
                self.assert_fail(
                    "--dry-run",
                    i,
                    j,
                    "any",
                    "port",
                    MP,
                    "from",
                    "any",
                    "port",
                    MP,
                    "proto",
                    "tcp",
                )
                self.assert_fail(
                    "--dry-run",
                    i,
                    j,
                    "any",
                    "port",
                    MP,
                    "from",
                    "any",
                    "port",
                    MP,
                    "proto",
                    "udp",
                )
                self.assert_fail(
                    "--dry-run",
                    i,
                    j,
                    "any",
                    "port",
                    MP,
                    "from",
                    "any",
                    "port",
                    MP36,
                    "proto",
                    "tcp",
                )
                self.assert_fail(
                    "--dry-run",
                    i,
                    j,
                    "any",
                    "port",
                    MP,
                    "from",
                    "any",
                    "port",
                    MP36,
                    "proto",
                    "udp",
                )
                self.assert_fail("--dry-run", i, j, "any", "port", "20,21")
                self.assert_fail("--dry-run", i, j, "any", "port", "20,2L")
                self.assert_fail("--dry-run", i, j, "any", "port", "2o,21")
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "20,", "proto", "udp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", ",20", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", ",20,", "proto", "udp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "20:", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", ":20", "proto", "udp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", ":20:", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "20:65536", "proto", "udp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "0:65", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", ",20:24", "proto", "udp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "20:24,", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", ",20:24,", "proto", "udp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "24:20", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "2A:20", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "24:2o", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "daytime,smtp", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "13,smtp", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "daytime,25", "proto", "tcp"
                )

            self.assert_fail(
                "--dry-run",
                i,
                "to",
                "any",
                "port",
                MP,
                "from",
                "any",
                "port",
                MP,
                "proto",
                "tcp",
            )
            self.assert_fail(
                "--dry-run",
                i,
                "to",
                "any",
                "port",
                MP,
                "from",
                "any",
                "port",
                MP,
                "proto",
                "udp",
            )
            self.assert_fail(
                "--dry-run",
                i,
                "to",
                "any",
                "port",
                MP39,
                "from",
                "any",
                "port",
                MP39,
                "proto",
                "tcp",
            )
            self.assert_fail(
                "--dry-run",
                i,
                "to",
                "any",
                "port",
                MP39,
                "from",
                "any",
                "port",
                MP39,
                "proto",
                "tcp",
            )

        # bad multiports (simple syntax)
        for i in ("allow", "deny", "limit"):
            self.assert_fail("--dry-run", i, "34,35")
            self.assert_fail("--dry-run", i, "34,35:39")
            self.assert_fail("--dry-run", i, "35:39")
            self.assert_fail("--dry-run", i, "23,21,15:19,22")

            for j in ("tcp", "udp"):
                self.assert_fail("--dry-run", i, "%s/%s" % (MP, j))
                self.assert_fail("--dry-run", i, "20,2L/%s" % j)
                self.assert_fail("--dry-run", i, "2o,21/%s" % j)
                self.assert_fail("--dry-run", i, "20,/%s" % j)
                self.assert_fail("--dry-run", i, ",20/%s" % j)
                self.assert_fail("--dry-run", i, ",20,/%s" % j)
                self.assert_fail("--dry-run", i, "20:/%s" % j)
                self.assert_fail("--dry-run", i, ":20/%s" % j)
                self.assert_fail("--dry-run", i, ":20:/%s" % j)
                self.assert_fail("--dry-run", i, "20:65536/%s" % j)
                self.assert_fail("--dry-run", i, "0:65/%s" % j)
                self.assert_fail("--dry-run", i, ",20:24/%s" % j)
                self.assert_fail("--dry-run", i, "20:24,/%s" % j)
                self.assert_fail("--dry-run", i, ",20:24,/%s" % j)
                self.assert_fail("--dry-run", i, "24:20/%s" % j)
                self.assert_fail("--dry-run", i, "2A:20/%s" % j)
                self.assert_fail("--dry-run", i, "24:2o/%s" % j)
                self.assert_fail("--dry-run", i, "daytime,smtp/tcp")
                self.assert_fail("--dry-run", i, "13,smtp/tcp")
                self.assert_fail("--dry-run", i, "daytime,25/tcp")

        # app
        self.assert_fail("--dry-run", "app")
        self.assert_fail("--dry-run", "app", "lis")
        self.assert_fail("--dry-run", "app", "info")
        self.assert_fail("--dry-run", "app", "ino", "foo")
        self.assert_fail("--dry-run", "app", "default")
        self.assert_fail("--dry-run", "app", "defalt", "foo")
        self.assert_fail("--dry-run", "app", "update")
        self.assert_fail("--dry-run", "app", "rfresh", "foo")
        self.assert_fail("--dry-run", "app", "info", "foo%")

        # logging (bad) -- the LOGLEVEL must remain unchanged
        self.assert_fail("--dry-run", "logging", "offf")
        self.assertRegex(self.read(self.ufw_conf), r"(?m)^LOGLEVEL=low")
        self.assert_fail("--dry-run", "logging", "onn")
        self.assert_fail("--dry-run", "logging", "loww")
        self.assert_fail("--dry-run", "logging", "meduim")
        self.assertRegex(self.read(self.ufw_conf), r"(?m)^LOGLEVEL=low")
        self.assert_fail("--dry-run", "logging", "hih")
        self.assertRegex(self.read(self.ufw_conf), r"(?m)^LOGLEVEL=low")
        self.assert_fail("--dry-run", "logging", "ful1")
        self.assertRegex(self.read(self.ufw_conf), r"(?m)^LOGLEVEL=low")

        self.assert_fail("--dry-run", "allow", "logg", "13")
        self.assert_fail("--dry-run", "allow", "logall", "13")
        self.assert_fail("--dry-run", "allow", "log-al1", "13")

        # insert
        self.assert_ok("allow", "13")
        self.assert_ok("allow", "23")

        self.assert_fail("insert", "0", "allow", "24")
        self.assert_fail("insert", "3", "allow", "24")
        self.assert_fail("insert", "allow", "24")
        self.assert_fail("allow", "insert", "2", "24")
        self.assert_ok("insert", "1", "allow", "13")
        self.assert_ok("insert", "1", "allow", "log", "13")

        self.assert_ok("delete", "allow", "13")
        self.assert_ok("delete", "allow", "23")

        # interfaces
        for j in ("in", "out"):
            for i in ("allow", "deny", "limit"):
                self.assert_fail("--dry-run", i, j, "on", "eth0:1")
                self.assert_fail("--dry-run", i, j, "on", "e?th0")
                self.assert_fail("--dry-run", i, "on", "eth0")
                self.assert_fail("--dry-run", i, "ina", "on", "eth0")
                self.assert_fail("--dry-run", i, j, "ona", "eth0")
                self.assert_fail("--dry-run", i, j, "eth0")
                self.assert_fail("--dry-run", i, j, "on", "eth0", "to")
                self.assert_fail("--dry-run", i, j, "on", "eth0", "from")
                self.assert_fail("--dry-run", i, j, "on", "eth0", "from", "any", "to")
                self.assert_fail("--dry-run", i, j, "on", "eth0", "any", "from")
                self.assert_fail(
                    "--dry-run", i, j, "on", "eth0", "any", "from", "to", "any", "proto"
                )
                self.assert_fail("--dry-run", i, "log", j, "on", "eth0")
                self.assert_fail("--dry-run", i, "log-all", j, "on", "eth0")

        # status
        self.assert_fail("--dry-run", "status", "foo")
        self.assert_fail("--dry-run", "status", "numbere")
        self.assert_fail("--dry-run", "status", "erbose")

        # show
        self.assert_fail("--dry-run", "show")
        self.assert_fail("--dry-run", "show", "ra")

    def test_apps(self):
        """tests/bad/apps"""
        self.stage_bad_profiles()

        # bad profile (command name); 'Custom Web App' is unquoted in the old
        # test, so it word-splits into extra args (too many args -> rc 1)
        self.assert_fail("app", "info", "foo")
        self.assert_fail("app", "info", "Custom", "Web", "App")

        # bad profile (name)
        self.assert_fail("app", "info", "bad-description1")
        self.assert_fail("app", "info", "bad-description2")
        self.assert_fail("app", "info", "bad-title1")
        self.assert_fail("app", "info", "bad-title2")
        self.assert_fail("app", "info", "bad-ports1")
        self.assert_fail("app", "info", "bad-ports2")
        self.assert_fail("app", "info", "bad-ports3")
        self.assert_fail("app", "info", "bad-ports4")
        self.assert_fail("app", "info", "bad-ports5")
        self.assert_fail("app", "info", "bad-ports6")
        self.assert_fail("app", "info", "ssh")
        self.assert_fail("app", "update", "--add-new", "all")

        # application integration (bad simple rules)
        for target in ("allow", "deny", "limit"):
            self.assert_fail(target, "NONEXISTENT")
            self.assert_fail(target, "Apache/tcp")

        # application integration (bad extended rules)
        for target in ("allow", "deny", "limit"):
            for i in ("to", "from"):
                k = "from" if i == "to" else "to"
                for loc in ("192.168.0.0/16", "any"):
                    self.assert_fail("--dry-run", target, i, loc, "app", "NONEXISTENT")
                    self.assert_fail(
                        "--dry-run", target, i, loc, "app", "Apache", "proto", "tcp"
                    )
                    self.assert_fail(
                        "--dry-run", target, i, loc, "app", "Apache", "proto", "udp"
                    )
                    self.assert_fail(
                        "--dry-run", target, i, loc, "app", "No Protocol Multi"
                    )
                    self.assert_fail(
                        "--dry-run",
                        target,
                        i,
                        loc,
                        "app",
                        "Samba",
                        k,
                        loc,
                        "port",
                        "http",
                        http_or_www=True,
                    )
                    self.assert_fail(
                        "--dry-run",
                        target,
                        i,
                        loc,
                        "app",
                        "Samba",
                        k,
                        loc,
                        "port",
                        "13",
                        "proto",
                        "tcp",
                    )

        # application integration (case sensitive)
        self.add_profile(
            "Runtest",
            "[Runtest]\ntitle=runtest title\ndescription=runtest description\n"
            "ports=23/tcp\n",
        )
        self.add_profile(
            "RunTest",
            "[RunTest]\ntitle=runtest title\ndescription=runtest description\n"
            "ports=24/tcp\n",
        )
        self.assert_fail("--dry-run", "allow", "runtest")
        self.remove(self.app_profile_path("Runtest"))
        self.remove(self.app_profile_path("RunTest"))

        # args (interfaces)
        for j in ("in", "out"):
            for i in ("allow", "deny", "limit"):
                self.assert_fail(
                    "--dry-run", i, j, "on", "eth0:1", "to", "any", "app", "Bind9"
                )
                self.assert_fail(
                    "--dry-run", i, "on", "eth0", "to", "any", "app", "Bind9"
                )
                self.assert_fail(
                    "--dry-run", i, j, "ina", "on", "eth0", "to", "any", "app", "Bind9"
                )
                self.assert_fail(
                    "--dry-run", i, j, "ona", "eth0", "to", "any", "app", "Bind9"
                )
                self.assert_fail("--dry-run", i, j, "eth0", "to", "any", "app", "Bind9")


def test_main():
    tests.functional.support.run_unittest(BadTests)


if __name__ == "__main__":
    unittest.main()
