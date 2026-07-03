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
# Functional tests converted from tests/ipv6/

import unittest

import tests.functional.support
from tests.functional.support import FunctionalTestCase

# Long multiport lists used by test_bad_args6.
MP = "20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35"
MP39 = "20,21,22,23,24,25,26,27,28,29,30,31,32,33,34:39"


class Ipv6Tests(FunctionalTestCase):
    class_name = "ipv6"

    def test_bad_args6(self):
        """tests/ipv6/bad_args6"""
        self.enable_ipv6()

        # logging
        self.assert_fail("--dry-run", "logging")
        self.assert_fail("--dry-run", "logging", "foo")
        self.assert_fail("--dry-run", "loggin", "on")

        # default
        self.assert_fail("--dry-run", "default")
        self.assert_fail("--dry-run", "default", "foo")
        self.assert_fail("--dry-run", "default", "accept")
        self.assert_fail("--dry-run", "defaul", "allow")
        self.assert_fail("--dry-run", "default", "limit")

        # enable/disable
        self.assert_fail("--dry-run", "enabled")
        self.assert_fail("--dry-run", "disabled")

        # allow/deny/limit (missing args)
        self.assert_fail("--dry-run", "allow")
        self.assert_fail("--dry-run", "deny")
        self.assert_fail("--dry-run", "limit")

        # bad port
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

        # bad to/from
        ip = "2001:db8:3:4:5:6:7:8"
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
        for bad in (
            "2001:db8:::/32",
            "2001:db8::/129",
            "2001:gb8::/32",
            "2001:db8:3:4:5:6:7:8:9",
            "foo",
            "xxx:xxx:xxx:xx:xxx:xxx:xxx:xxx",
            "g001:db8:3:4:5:6:7:8",
            "2001:gb8:3:4:5:6:7:8",
            "2001:db8:g:4:5:6:7:8",
            "2001:db8:3:g:5:6:7:8",
            "2001:db8:3:4:g:6:7:8",
            "2001:db8:3:4:5:g:7:8",
            "2001:db8:3:4:5:6:g:8",
            "2001:db8:3:4:5:6:7:g",
            "2001:0db8:0000:0000:0000:0000:0000:0000/129",
            "2001:0db8:0000:0000:0000:0000:0000:00000/128",
            "2001:0db8:0000:0000:0000:0000:0000:00000/12a",
        ):
            self.assert_fail("--dry-run", "allow", "to", bad)

        # delete
        self.assert_fail("--dry-run", "delete")

        # mixed ipv4/ipv6
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
            "ssh",
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
            "ssh",
            "proto",
            "tcp",
        )

        # bad multiports
        for i in ("allow", "deny", "limit"):
            for j in ("from", "to"):
                self.assert_fail("--dry-run", i, j, "any", "port", "20,21")
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "20,2L", "proto", "udp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "2o,21", "proto", "tcp"
                )
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
                    "--dry-run", i, j, "any", "port", "http,smtp", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "80,smtp", "proto", "tcp"
                )
                self.assert_fail(
                    "--dry-run", i, j, "any", "port", "http,25", "proto", "tcp"
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
                "from",
                "any",
                "port",
                MP39,
                "to",
                "any",
                "port",
                MP39,
                "proto",
                "tcp",
            )
            self.assert_fail(
                "--dry-run",
                i,
                "from",
                "any",
                "port",
                MP39,
                "to",
                "any",
                "port",
                MP39,
                "proto",
                "udp",
            )

        # bad interfaces
        for i in ("in", "out"):
            for j in ("allow", "deny", "limit", "reject"):
                self.assert_fail("--dry-run", j, i, "on", "e?th0", "to", ip)
                self.assert_fail("--dry-run", j, i, "eth0", "to", ip)
                self.assert_fail("--dry-run", j, "ina", "eth0", "to", ip)
                self.assert_fail("--dry-run", j, "on", "eth0", "to", ip)
                self.assert_fail("--dry-run", j, "log", i, "on", "eth0", "to", ip)

    def test_rules64(self):
        """tests/ipv6/rules64"""
        self.enable_ipv6()
        a1 = "2001:db8:85a3:8d3:1319:8a2e:370:7341"
        a2 = "2001:db8:85a3:8d3:1319:8a2e:370:7342"
        addr = "2001:db8:85a3:8d3:1319:8a2e:370:734"

        # Man page
        self.assert_ok("--dry-run", "allow", "53")
        self.assert_ok("--dry-run", "allow", "25/tcp")
        self.assert_ok("--dry-run", "allow", "smtp")
        self.assert_ok("--dry-run", "deny", "proto", "tcp", "to", "any", "port", "80")
        self.assert_ok(
            "--dry-run",
            "deny",
            "proto",
            "tcp",
            "from",
            "10.0.0.0/8",
            "to",
            "192.168.0.1",
            "port",
            "25",
        )
        self.assert_ok(
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
        self.assert_ok("--dry-run", "deny", "80/tcp")
        self.assert_ok("--dry-run", "delete", "deny", "80/tcp")
        self.assert_ok("--dry-run", "limit", "daytime/tcp")
        self.assert_ok("--dry-run", "deny", "53")
        self.assert_ok("--dry-run", "allow", "80/tcp")
        self.assert_ok("--dry-run", "allow", "from", "10.0.0.0/8")
        self.assert_ok("--dry-run", "allow", "from", "172.16.0.0/12")
        self.assert_ok("--dry-run", "allow", "from", "192.168.0.0/16")
        self.assert_ok(
            "--dry-run",
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

        # Services SIMPLE
        for svc in (
            "smtp",
            "smtp/tcp",
            "tftp",
            "tftp/udp",
            "daytime",
            "daytime/tcp",
            "daytime/udp",
        ):
            self.assert_ok("--dry-run", "allow", svc)
            self.assert_ok("--dry-run", "delete", "allow", svc)

        # Services EXTENDED
        for dport, sport in (
            ("smtp", "daytime"),
            ("tftp", "daytime"),
            ("daytime", "domain"),
        ):
            self.assert_ok(
                "--dry-run",
                "allow",
                "to",
                "any",
                "port",
                dport,
                "from",
                "any",
                "port",
                sport,
            )
            self.assert_ok(
                "--dry-run",
                "delete",
                "allow",
                "to",
                "any",
                "port",
                dport,
                "from",
                "any",
                "port",
                sport,
            )

        # Netmasks
        self.assert_ok("--dry-run", "allow", "to", "192.168.0.0/0")
        self.assert_ok("--dry-run", "allow", "to", "192.168.0.0/16")
        self.assert_ok("--dry-run", "allow", "to", "192.168.0.1/32")
        self.assert_ok("--dry-run", "allow", "from", "192.168.0.0/0")
        self.assert_ok("--dry-run", "allow", "from", "192.168.0.0/16")
        self.assert_ok("--dry-run", "allow", "from", "192.168.0.1/32")
        self.assert_ok(
            "--dry-run", "allow", "from", "192.168.0.1/32", "to", "192.168.0.2/32"
        )
        self.assert_ok("--dry-run", "allow", "to", "::1/0")
        self.assert_ok("--dry-run", "allow", "to", "::1/32")
        self.assert_ok("--dry-run", "allow", "to", "::1/128")
        self.assert_ok("--dry-run", "allow", "from", "::1/0")
        self.assert_ok("--dry-run", "allow", "from", "::1/32")
        self.assert_ok("--dry-run", "allow", "from", "::1/128")
        self.assert_ok("--dry-run", "allow", "from", "::1/32", "to", "::1/16")

        # Netmasks (CIDR)
        for i in range(0, 33):
            self.assert_ok("--dry-run", "allow", "to", "192.168.0.1/%d" % i)
            self.assert_ok("--dry-run", "allow", "from", "192.168.0.1/%d" % i)
            self.assert_ok(
                "--dry-run",
                "allow",
                "from",
                "192.168.0.1/%d" % i,
                "to",
                "192.168.0.2/%d" % i,
            )

        # valid dotted
        for i in range(0, 256, 16):
            self.assert_ok("--dry-run", "allow", "from", "10.0.0.1/255.255.255.%d" % i)
            self.assert_ok("--dry-run", "allow", "from", "10.0.0.1/255.255.%d.255" % i)
            self.assert_ok("--dry-run", "allow", "from", "10.0.0.1/255.%d.255.255" % i)
            self.assert_ok("--dry-run", "allow", "from", "10.0.0.1/%d.255.255.255" % i)
            self.assert_ok(
                "--dry-run", "allow", "from", "10.0.0.1/%d.%d.%d.%d" % (i, i, i, i)
            )

        # Multiports
        self.assert_ok(
            "--dry-run", "allow", "from", "192.168.0.1", "port", "34,35", "proto", "tcp"
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "from",
            "192.168.0.1",
            "port",
            "34,35:39",
            "proto",
            "udp",
        )
        self.assert_ok(
            "--dry-run", "allow", "from", "192.168.0.1", "port", "35:39", "proto", "tcp"
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "from",
            "192.168.0.1",
            "port",
            "210,23,21,15:19,13",
            "proto",
            "udp",
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "from",
            "192.168.0.1",
            "port",
            "34,35",
            "to",
            "192.168.0.2",
            "port",
            "24",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "from",
            "192.168.0.1",
            "port",
            "34,35:39",
            "to",
            "192.168.0.2",
            "port",
            "24",
            "proto",
            "udp",
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "to",
            a1,
            "port",
            "35:39",
            "from",
            a2,
            "port",
            "24",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "to",
            a1,
            "port",
            "23,21,15:19,13",
            "from",
            a2,
            "port",
            "24",
            "proto",
            "udp",
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "to",
            a1,
            "port",
            "34,35",
            "from",
            a2,
            "port",
            "24:26",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "to",
            a1,
            "port",
            "34,35:39",
            "from",
            a2,
            "port",
            "24:26",
            "proto",
            "udp",
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "to",
            a1,
            "port",
            "35:39",
            "from",
            a2,
            "port",
            "24:26",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "--dry-run",
            "allow",
            "to",
            a1,
            "port",
            "23,21,15:19,13",
            "from",
            a2,
            "port",
            "24:26",
            "proto",
            "udp",
        )

        # simple syntax
        for i in ("allow", "deny", "limit"):
            for j in ("tcp", "udp"):
                self.assert_ok("--dry-run", i, "34,35/%s" % j)
                self.assert_ok("--dry-run", i, "34,35:39/%s" % j)
                self.assert_ok("--dry-run", i, "35:39/%s" % j)
                self.assert_ok("--dry-run", i, "23,21,15:19,13/%s" % j)

        # Man page (reject)
        self.assert_ok("--dry-run", "reject", "auth")

        # Reject
        self.assert_ok(
            "--dry-run",
            "reject",
            "to",
            "any",
            "port",
            "auth",
            "from",
            "any",
            "port",
            "smtp",
        )
        self.assert_ok(
            "--dry-run",
            "delete",
            "reject",
            "to",
            "any",
            "port",
            "auth",
            "from",
            "any",
            "port",
            "smtp",
        )
        self.assert_ok(
            "--dry-run",
            "reject",
            "to",
            "10.0.0.1",
            "port",
            "domain",
            "from",
            "192.168.0.1",
            "port",
            "auth",
        )
        self.assert_ok(
            "--dry-run",
            "delete",
            "reject",
            "to",
            "10.0.0.1",
            "port",
            "domain",
            "from",
            "192.168.0.1",
            "port",
            "auth",
        )
        for i in ("any", "tcp", "udp"):
            if i == "any":
                p = ""
            else:
                p = "/%s" % i
                self.assert_ok("--dry-run", "reject", "23,21,15:19,13%s" % p)
            self.assert_ok("--dry-run", "reject", "116%s" % p)
        self.assert_ok(
            "--dry-run", "reject", "from", "2001:db8::/32", "to", "any", "port", "25"
        )
        self.assert_ok(
            "--dry-run",
            "reject",
            "to",
            a1,
            "port",
            "35:39",
            "from",
            a2,
            "port",
            "24",
            "proto",
            "tcp",
        )
        self.assert_ok(
            "--dry-run",
            "reject",
            "to",
            a1,
            "port",
            "35:39",
            "from",
            a2,
            "port",
            "24",
            "proto",
            "udp",
        )

        # Insert: ipv4/ipv6 rules must go to their own section
        self.assert_ok("allow", "to", "127.0.0.1", "port", "13")
        self.assert_ok("allow", "to", "127.0.0.1", "port", "23")
        self.assert_ok("allow", "to", "::1", "port", "24")
        self.assert_ok("allow", "to", "::1", "port", "25")

        # ipv4 rule in ipv4 section
        self.assert_ok("insert", "2", "allow", "to", "127.0.0.1", "port", "8888")
        self.assertIn("8888", self.read(self.user_rules))
        self.assertNotIn("8888", self.read(self.user6_rules))
        # ipv6 rule in ipv6 section
        self.assert_ok("delete", "allow", "to", "127.0.0.1", "port", "8888")
        self.assert_ok("insert", "4", "allow", "to", "::1", "port", "8888")
        self.assertIn("8888", self.read(self.user6_rules))
        self.assertNotIn("8888", self.read(self.user_rules))
        # ipv6 rule in ipv4 section (must fail)
        self.assert_ok("delete", "allow", "to", "::1", "port", "8888")
        self.assert_fail("insert", "2", "allow", "to", "::1", "port", "8888")
        # ipv4 rule in ipv6 section (must fail)
        self.assert_ok("delete", "allow", "to", "::1", "port", "8888")
        self.assert_fail("insert", "4", "allow", "to", "127.0.0.1", "port", "8888")
        # 'both' rule in ipv4 section
        self.assert_ok("delete", "allow", "to", "127.0.0.1", "port", "8888")
        self.assert_ok("insert", "2", "allow", "8888")
        self.assertIn("8888", self.read(self.user_rules))
        self.assertIn("8888", self.read(self.user6_rules))
        # 'both' rule in ipv6 section
        self.assert_ok("delete", "allow", "8888")
        self.assert_ok("insert", "4", "allow", "log", "8888")
        self.assertIn("8888", self.read(self.user_rules))
        self.assertIn("8888", self.read(self.user6_rules))

        self.assert_ok("delete", "allow", "to", "127.0.0.1", "port", "13")
        self.assert_ok("delete", "allow", "to", "127.0.0.1", "port", "23")
        self.assert_ok("delete", "allow", "to", "::1", "port", "24")
        self.assert_ok("delete", "allow", "to", "::1", "port", "25")
        self.assert_ok("delete", "allow", "log", "8888")
        self.assertEqual(self.tuple_count(self.user_rules), 0)
        self.assertEqual(self.tuple_count(self.user6_rules), 0)

        # Interfaces
        for i in ("in", "out"):
            self.assert_ok("allow", i, "on", "eth0")
            self.assert_ok("allow", i, "on", "eth0", "to", "192.168.0.1")
            self.assert_ok(
                "deny",
                i,
                "on",
                "eth0",
                "from",
                "192.168.0.1",
                "port",
                "13",
                "proto",
                "tcp",
            )
            self.assert_ok("reject", i, "on", "eth0", "to", addr)
            self.assert_ok(
                "allow", i, "on", "eth0", "from", addr, "port", "13", "proto", "tcp"
            )
            self.assert_ok("delete", "allow", i, "on", "eth0")
            self.assert_ok("delete", "allow", i, "on", "eth0", "to", "192.168.0.1")
            self.assert_ok(
                "delete",
                "deny",
                i,
                "on",
                "eth0",
                "from",
                "192.168.0.1",
                "port",
                "13",
                "proto",
                "tcp",
            )
            self.assert_ok("delete", "reject", i, "on", "eth0", "to", addr)
            self.assert_ok(
                "delete",
                "allow",
                i,
                "on",
                "eth0",
                "from",
                addr,
                "port",
                "13",
                "proto",
                "tcp",
            )

        # IPSec
        self.assert_ok("--dry-run", "allow", "to", "10.0.0.1", "proto", "esp")
        self.assert_ok(
            "--dry-run",
            "allow",
            "to",
            "10.0.0.1",
            "from",
            "10.4.0.0/16",
            "proto",
            "esp",
        )
        self.assert_ok("--dry-run", "allow", "to", "10.0.0.1", "proto", "ah")
        self.assert_ok(
            "--dry-run", "allow", "to", "10.0.0.1", "from", "10.4.0.0/16", "proto", "ah"
        )
        self.assert_ok("--dry-run", "allow", "to", addr, "proto", "esp")
        self.assert_ok(
            "--dry-run", "allow", "to", addr, "from", "2001:db8::/32", "proto", "esp"
        )
        self.assert_ok("--dry-run", "allow", "to", addr, "proto", "ah")
        self.assert_ok(
            "--dry-run", "allow", "to", addr, "from", "2001:db8::/32", "proto", "ah"
        )
        self.assert_ok("--dry-run", "allow", "to", "any", "proto", "esp")
        self.assert_ok("--dry-run", "allow", "to", "any", "proto", "ah")

        # Comments
        self.assert_ok(
            "allow", "to", "10.0.0.1", "from", "10.4.0.0/16", "comment", '"SSH port"'
        )
        self.assert_ok(
            "allow",
            "to",
            addr,
            "from",
            "2001:db8::/32",
            "proto",
            "ah",
            "comment",
            '"SSH port"',
        )
        self.assert_ok(
            "delete",
            "allow",
            "to",
            "10.0.0.1",
            "from",
            "10.4.0.0/16",
            "comment",
            '"SSH port"',
        )
        self.assert_ok(
            "delete",
            "allow",
            "to",
            addr,
            "from",
            "2001:db8::/32",
            "proto",
            "ah",
            "comment",
            '"SSH port"',
        )

        # Prepend
        self.assert_ok("allow", "22/tcp")
        self.assert_ok("allow", "from", "1.2.3.4")
        self.assert_ok("allow", "from", "2001:db8::/32")
        self.assert_ok("prepend", "deny", "from", "2a02:2210:12:a:b820:fff:fea2:25d1")
        self.assert_ok("prepend", "deny", "from", "6.7.8.9")
        self.assertLess(
            self.read(self.user_rules).index("6.7.8.9"),
            self.read(self.user_rules).index("1.2.3.4"),
        )
        self.assert_ok("delete", "allow", "22/tcp")
        self.assert_ok("delete", "allow", "from", "1.2.3.4")
        self.assert_ok("delete", "allow", "from", "2001:db8::/32")
        self.assert_ok("delete", "deny", "from", "2a02:2210:12:a:b820:fff:fea2:25d1")
        self.assert_ok("delete", "deny", "from", "6.7.8.9")

        # Prepend (no rules)
        self.assert_ok("prepend", "allow", "22/tcp")
        self.assert_ok("delete", "allow", "22/tcp")
        self.assert_ok("prepend", "allow", "to", "any", "app", "Samba")
        self.assert_ok("delete", "allow", "to", "any", "app", "Samba")

        # Prepend (multi rules)
        self.assert_ok("allow", "22/tcp")
        self.assert_ok("prepend", "deny", "23")
        self.assert_ok("prepend", "deny", "to", "any", "app", "Samba")
        self.assert_ok("delete", "allow", "22/tcp")
        self.assert_ok("delete", "deny", "23")
        self.assert_ok("delete", "deny", "to", "any", "app", "Samba")

        # Prepend (example rules)
        self.assert_ok("allow", "22/tcp")
        self.assert_ok("allow", "from", "1.2.3.4")
        self.assert_ok("allow", "from", "2001:db8::/32")
        self.assert_ok("prepend", "deny", "from", "2a02:2210:12:a:b820:fff:fea2:25d1")
        self.assert_ok("prepend", "deny", "from", "6.7.8.9")
        self.assert_ok("delete", "allow", "22/tcp")
        self.assert_ok("delete", "allow", "from", "1.2.3.4")
        self.assert_ok("delete", "allow", "from", "2001:db8::/32")
        self.assert_ok("delete", "deny", "from", "2a02:2210:12:a:b820:fff:fea2:25d1")
        self.assert_ok("delete", "deny", "from", "6.7.8.9")

    def test_rules6(self):
        """tests/ipv6/rules6"""
        self.enable_ipv6()
        frm = "2001:db8::/32"
        to = "2001:db8:3:4:5:6:7:8"
        addr = "2001:db8:85a3:8d3:1319:8a2e:370:734"

        # Man page
        self.assert_ok(
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

        # TO/FROM
        for x in ("allow", "deny", "limit"):
            self.assert_ok("--dry-run", x, "from", frm)
            self.assert_ok("--dry-run", "delete", x, "from", frm)
            self.assert_ok("--dry-run", x, "to", to)
            self.assert_ok("--dry-run", "delete", x, "to", to)
            self.assert_ok("--dry-run", x, "to", to, "from", frm)
            self.assert_ok("--dry-run", "delete", x, "to", to, "from", frm)

            self.assert_ok("--dry-run", x, "from", frm, "port", "80")
            self.assert_ok("--dry-run", "delete", x, "from", frm, "port", "80")
            self.assert_ok("--dry-run", x, "to", to, "port", "25")
            self.assert_ok("--dry-run", "delete", x, "to", to, "port", "25")
            self.assert_ok("--dry-run", x, "to", to, "from", frm, "port", "80")
            self.assert_ok(
                "--dry-run", "delete", x, "to", to, "from", frm, "port", "80"
            )
            self.assert_ok("--dry-run", x, "to", to, "port", "25", "from", frm)
            self.assert_ok(
                "--dry-run", "delete", x, "to", to, "port", "25", "from", frm
            )
            self.assert_ok(
                "--dry-run", x, "to", to, "port", "25", "from", frm, "port", "80"
            )
            self.assert_ok(
                "--dry-run",
                "delete",
                x,
                "to",
                to,
                "port",
                "25",
                "from",
                frm,
                "port",
                "80",
            )
            for y in ("udp", "tcp"):
                self.assert_ok("--dry-run", x, "from", frm, "port", "80", "proto", y)
                self.assert_ok(
                    "--dry-run", "delete", x, "from", frm, "port", "80", "proto", y
                )
                self.assert_ok("--dry-run", x, "to", to, "port", "25", "proto", y)
                self.assert_ok(
                    "--dry-run", "delete", x, "to", to, "port", "25", "proto", y
                )
                self.assert_ok(
                    "--dry-run", x, "to", to, "from", frm, "port", "80", "proto", y
                )
                self.assert_ok(
                    "--dry-run",
                    "delete",
                    x,
                    "to",
                    to,
                    "from",
                    frm,
                    "port",
                    "80",
                    "proto",
                    y,
                )
                self.assert_ok(
                    "--dry-run", x, "to", to, "port", "25", "proto", y, "from", frm
                )
                self.assert_ok(
                    "--dry-run",
                    "delete",
                    x,
                    "to",
                    to,
                    "port",
                    "25",
                    "proto",
                    y,
                    "from",
                    frm,
                )
                self.assert_ok(
                    "--dry-run",
                    x,
                    "to",
                    to,
                    "port",
                    "25",
                    "proto",
                    y,
                    "from",
                    frm,
                    "port",
                    "80",
                )
                self.assert_ok(
                    "--dry-run",
                    "delete",
                    x,
                    "to",
                    to,
                    "port",
                    "25",
                    "proto",
                    y,
                    "from",
                    frm,
                    "port",
                    "80",
                )

            self.assert_ok(
                "--dry-run", x, "to", to, "port", "smtp", "from", frm, "port", "daytime"
            )
            self.assert_ok(
                "--dry-run",
                "delete",
                x,
                "to",
                to,
                "port",
                "smtp",
                "from",
                frm,
                "port",
                "daytime",
            )
            self.assert_ok(
                "--dry-run", x, "to", to, "port", "tftp", "from", frm, "port", "daytime"
            )
            self.assert_ok(
                "--dry-run",
                "delete",
                x,
                "to",
                to,
                "port",
                "tftp",
                "from",
                frm,
                "port",
                "daytime",
            )
            self.assert_ok(
                "--dry-run",
                x,
                "to",
                to,
                "port",
                "daytime",
                "from",
                frm,
                "port",
                "domain",
            )
            self.assert_ok(
                "--dry-run",
                "delete",
                x,
                "to",
                to,
                "port",
                "daytime",
                "from",
                frm,
                "port",
                "domain",
            )

        # Netmasks
        self.assert_ok("--dry-run", "allow", "to", "::1/0")
        self.assert_ok("--dry-run", "allow", "to", "::1/32")
        self.assert_ok("--dry-run", "allow", "to", "::1/128")
        self.assert_ok("--dry-run", "allow", "from", "::1/0")
        self.assert_ok("--dry-run", "allow", "from", "::1/32")
        self.assert_ok("--dry-run", "allow", "from", "::1/128")
        self.assert_ok("--dry-run", "allow", "from", "::1/32", "to", "::1/128")

        # Multiports
        for i in (addr, "any"):
            for j in ("from", "to"):
                k = "from" if j == "to" else "to"
                m = "%s1" % i if i != "any" else "any"
                n = "%s2" % i if i != "any" else "any"
                self.assert_ok(
                    "--dry-run", "allow", j, m, "port", "34,35", "proto", "tcp"
                )
                self.assert_ok(
                    "--dry-run", "allow", j, m, "port", "34,35:39", "proto", "udp"
                )
                self.assert_ok(
                    "--dry-run", "allow", j, m, "port", "35:39", "proto", "tcp"
                )
                self.assert_ok(
                    "--dry-run",
                    "allow",
                    j,
                    m,
                    "port",
                    "210,23,21,15:19,13",
                    "proto",
                    "udp",
                )
                self.assert_ok(
                    "--dry-run",
                    "allow",
                    j,
                    m,
                    "port",
                    "34,35",
                    k,
                    n,
                    "port",
                    "24",
                    "proto",
                    "tcp",
                )
                self.assert_ok(
                    "--dry-run",
                    "allow",
                    j,
                    m,
                    "port",
                    "34,35:39",
                    k,
                    n,
                    "port",
                    "24",
                    "proto",
                    "udp",
                )
                self.assert_ok(
                    "--dry-run",
                    "allow",
                    j,
                    m,
                    "port",
                    "35:39",
                    k,
                    n,
                    "port",
                    "24",
                    "proto",
                    "tcp",
                )
                self.assert_ok(
                    "--dry-run",
                    "allow",
                    j,
                    m,
                    "port",
                    "23,21,15:19,13",
                    k,
                    n,
                    "port",
                    "24",
                    "proto",
                    "udp",
                )
                self.assert_ok(
                    "--dry-run",
                    "allow",
                    j,
                    m,
                    "port",
                    "34,35",
                    k,
                    n,
                    "port",
                    "24:26",
                    "proto",
                    "tcp",
                )
                self.assert_ok(
                    "--dry-run",
                    "allow",
                    j,
                    m,
                    "port",
                    "34,35:39",
                    k,
                    n,
                    "port",
                    "24:26",
                    "proto",
                    "udp",
                )
                self.assert_ok(
                    "--dry-run",
                    "allow",
                    j,
                    m,
                    "port",
                    "35:39",
                    k,
                    n,
                    "port",
                    "24:26",
                    "proto",
                    "tcp",
                )
                self.assert_ok(
                    "--dry-run",
                    "allow",
                    j,
                    m,
                    "port",
                    "23,21,15:19,13",
                    k,
                    n,
                    "port",
                    "24:26",
                    "proto",
                    "udp",
                )

        # Interfaces
        for i in ("in", "out"):
            for j in ("allow", "deny", "reject"):
                self.assert_ok("--dry-run", j, i, "on", "eth0", "to", addr)
                self.assert_ok(
                    "--dry-run",
                    j,
                    i,
                    "on",
                    "eth0",
                    "from",
                    addr,
                    "port",
                    "13",
                    "proto",
                    "tcp",
                )

        # IPSec
        self.assert_ok("--dry-run", "allow", "to", addr, "proto", "esp")
        self.assert_ok(
            "--dry-run", "allow", "to", addr, "from", "2001:db8::/32", "proto", "esp"
        )
        self.assert_ok("--dry-run", "allow", "to", addr, "proto", "ah")
        self.assert_ok(
            "--dry-run", "allow", "to", addr, "from", "2001:db8::/32", "proto", "ah"
        )

        # Comments
        self.assert_ok(
            "allow",
            "to",
            addr,
            "from",
            "2001:db8::/32",
            "proto",
            "ah",
            "comment",
            '"SSH port"',
        )
        self.assertIn(addr, self.read(self.user6_rules))
        self.assert_ok(
            "delete",
            "allow",
            "to",
            addr,
            "from",
            "2001:db8::/32",
            "proto",
            "ah",
            "comment",
            '"SSH port"',
        )
        self.assertEqual(self.tuple_count(self.user6_rules), 0)

        # Prepend
        self.assert_ok("allow", "from", "2001:db8::/32")
        self.assert_ok("prepend", "deny", "from", "2a02:2210:12:a:b820:fff:fea2:25d1")
        r = self.read(self.user6_rules)
        self.assertLess(r.index("2a02:2210"), r.index("2001:db8::"))
        self.assert_ok("delete", "allow", "from", "2001:db8::/32")
        self.assert_ok("delete", "deny", "from", "2a02:2210:12:a:b820:fff:fea2:25d1")

        # Prepend (no rules)
        self.assert_ok("prepend", "allow", "from", "2001:db8::/32")
        self.assert_ok("delete", "allow", "from", "2001:db8::/32")
        self.assert_ok(
            "prepend", "allow", "from", "2001:db8::/32", "to", "any", "app", "Samba"
        )
        self.assert_ok(
            "delete", "allow", "from", "2001:db8::/32", "to", "any", "app", "Samba"
        )

        # Prepend (multi rules)
        self.assert_ok("allow", "from", "2001:db8::/32")
        self.assert_ok(
            "prepend", "deny", "to", "2a02:2210:12:a:b820:fff:fea2:25d1", "port", "23"
        )
        self.assert_ok(
            "prepend", "deny", "to", "2a02:2210:12:a:b820:fff:fea2:25d1", "app", "Samba"
        )
        self.assert_ok("delete", "allow", "from", "2001:db8::/32")
        self.assert_ok(
            "delete", "deny", "to", "2a02:2210:12:a:b820:fff:fea2:25d1", "port", "23"
        )
        self.assert_ok(
            "delete", "deny", "to", "2a02:2210:12:a:b820:fff:fea2:25d1", "app", "Samba"
        )

    def test_logging(self):
        """tests/ipv6/logging"""
        self.enable_ipv6()
        frm = "2001:db8::/32"
        to = "2001:db8:3:4:5:6:7:8"

        for i in ("allow", "deny", "limit", "reject"):
            for j in ("log", "log-all"):
                self.assert_ok(i, j, "23")
                self.assert_ok(i, j, "Samba")
                # v4 rules are always written (v6 'limit' is unsupported in the
                # test caps, so we only assert the round-trip cleans up below)
                self.assertGreater(self.tuple_count(self.user_rules), 0)
                self.assert_ok("delete", i, j, "23")
                self.assert_ok("delete", i, j, "Samba")
                self.assertEqual(self.tuple_count(self.user_rules), 0)
                self.assertEqual(self.tuple_count(self.user6_rules), 0)

                self.assert_ok(i, j, "from", frm, "to", to, "port", "smtp")
                self.assert_ok("delete", i, j, "from", frm, "to", to, "port", "smtp")
                self.assertEqual(self.tuple_count(self.user6_rules), 0)

        # updating
        self.assert_ok("allow", "log", "Samba")
        self.assert_ok("deny", "log-all", "from", frm, "to", to, "port", "smtp")
        self.assert_ok("deny", "log", "Samba")
        self.assert_ok("reject", "log-all", "from", frm, "to", to, "port", "smtp")
        self.assert_ok("delete", "deny", "log", "Samba")
        self.assert_ok(
            "delete", "reject", "log-all", "from", frm, "to", to, "port", "smtp"
        )

        # interfaces
        self.assert_ok("allow", "in", "on", "eth0", "log")
        self.assert_ok(
            "allow",
            "in",
            "on",
            "eth0",
            "log",
            "from",
            frm,
            "to",
            to,
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
            frm,
            "to",
            to,
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
            frm,
            "to",
            to,
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
            frm,
            "to",
            to,
            "port",
            "25",
            "proto",
            "tcp",
        )

    def test_good_args6(self):
        """tests/ipv6/good_args6"""
        self.enable_ipv6()

        # logging
        self.assert_ok("--dry-run", "logging", "on")
        self.assert_ok("--dry-run", "logging", "off")
        self.assert_ok("--dry-run", "LOGGING", "ON")
        self.assert_ok("--dry-run", "LOGGING", "OFF")

        # default
        self.assert_ok("--dry-run", "default", "allow")
        self.assert_ok("--dry-run", "default", "deny")
        self.assert_ok("--dry-run", "default", "reject")
        self.assert_ok("--dry-run", "DEFAULT", "ALLOW")
        self.assert_ok("--dry-run", "DEFAULT", "DENY")
        self.assert_ok("--dry-run", "DEFAULT", "REJECT")

        # enable/disable
        self.assert_ok("--dry-run", "enable")
        self.assert_ok("--dry-run", "disable")
        self.assert_ok("--dry-run", "ENABLE")
        self.assert_ok("--dry-run", "DISABLE")

        # status
        self.assert_ok("--dry-run", "status")


def test_main():
    tests.functional.support.run_unittest(Ipv6Tests)


if __name__ == "__main__":
    unittest.main()
