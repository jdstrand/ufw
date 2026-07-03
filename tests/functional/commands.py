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
# Driver-agnostic ufw command sequences, shared between the in-process functest
# (FunctionalTestCase, fake iptables) and the real-iptables e2e suite
# (E2ETestCase). A sequence calls only self.ufw/assert_ok plus the on-disk
# generation checks below, which are REAL in functest and NO-OPS in e2e: e2e
# strips --dry-run so commands actually apply, which changes the persisted
# rule state -- there, apply-acceptance via exit codes is what matters, and
# generation is already pinned by the functest transcript.


class RuleCommands:
    """The good/rules command sequence (tests/good/rules)."""

    # -- on-disk generation checks (real in functest, no-op in e2e) --------
    def assert_rule_count(self, n):
        if self.verify_on_disk:
            self.assertEqual(self.tuple_count(self.user_rules), n)

    def assert_rules_contain(self, s):
        if self.verify_on_disk:
            self.assertIn(s, self.read(self.user_rules))

    def assert_rules_exclude(self, s):
        if self.verify_on_disk:
            self.assertNotIn(s, self.read(self.user_rules))

    def assert_rules_order(self, first, second):
        if self.verify_on_disk:
            rules = self.read(self.user_rules)
            self.assertLess(rules.index(first), rules.index(second))

    def test_rules(self):
        """tests/good/rules"""
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

        # SIMPLE
        self.assert_ok("--dry-run", "allow", "1")
        self.assert_ok("--dry-run", "allow", "9/udp")
        self.assert_ok("--dry-run", "allow", "25")
        self.assert_ok("--dry-run", "allow", "25/tcp")
        self.assert_ok("--dry-run", "allow", "25/udp")
        self.assert_ok("--dry-run", "delete", "allow", "25")
        self.assert_ok("--dry-run", "delete", "allow", "25/tcp")
        self.assert_ok("--dry-run", "delete", "allow", "25/udp")
        self.assert_ok("--dry-run", "allow", "smtp")
        self.assert_ok("--dry-run", "delete", "allow", "smtp")
        self.assert_ok("--dry-run", "allow", "smtp/tcp")
        self.assert_ok("--dry-run", "delete", "allow", "smtp/tcp")
        self.assert_ok("--dry-run", "allow", "tftp")
        self.assert_ok("--dry-run", "delete", "allow", "tftp")
        self.assert_ok("--dry-run", "allow", "tftp/udp")
        self.assert_ok("--dry-run", "delete", "allow", "tftp/udp")
        self.assert_ok("--dry-run", "allow", "daytime")
        self.assert_ok("--dry-run", "delete", "allow", "daytime")
        self.assert_ok("--dry-run", "allow", "daytime/tcp")
        self.assert_ok("--dry-run", "delete", "allow", "daytime/tcp")
        self.assert_ok("--dry-run", "allow", "daytime/udp")
        self.assert_ok("--dry-run", "delete", "allow", "daytime/udp")

        # TO/FROM
        frm = "192.168.0.1"
        to = "10.0.0.1"
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

        # Services
        svc = [
            ("smtp", "smtp"),
            ("smtp", "daytime"),
            ("daytime", "smtp"),
            ("smtp", "23"),
            ("23", "smtp"),
            ("tftp", "tftp"),
            ("tftp", "daytime"),
            ("daytime", "tftp"),
            ("tftp", "23"),
            ("23", "tftp"),
            ("daytime", "23"),
            ("23", "daytime"),
            ("daytime", "domain"),
        ]
        for dport, sport in svc:
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
        svc_proto = [
            ("smtp", "smtp", "tcp"),
            ("smtp", "daytime", "tcp"),
            ("daytime", "smtp", "tcp"),
            ("smtp", "23", "tcp"),
            ("23", "smtp", "tcp"),
            ("tftp", "tftp", "udp"),
            ("tftp", "daytime", "udp"),
            ("daytime", "tftp", "udp"),
            ("tftp", "23", "udp"),
            ("23", "tftp", "udp"),
            ("daytime", "23", "tcp"),
            ("23", "daytime", "tcp"),
            ("daytime", "domain", "tcp"),
            ("daytime", "23", "udp"),
            ("23", "daytime", "udp"),
            ("daytime", "domain", "udp"),
        ]
        for dport, sport, proto in svc_proto:
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
                "proto",
                proto,
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
                "proto",
                proto,
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

        # ISP style
        self.assert_ok("--dry-run", "allow", "from", "192.168.0.2/255.255.0.2")

        # Multiports
        for i in ("192.168.0", "any"):
            for j in ("from", "to"):
                k = "from" if j == "to" else "to"
                m = "%s.1" % i
                n = "%s.2" % i
                if i == "any":
                    m = "any"
                    n = "any"
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
                    "221,23,21,15:19,13",
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

        # simple syntax
        for i in ("allow", "deny", "limit"):
            for j in ("tcp", "udp"):
                self.assert_ok("--dry-run", i, "34,35/%s" % j)
                self.assert_ok("--dry-run", i, "34,35:39/%s" % j)
                self.assert_ok("--dry-run", i, "35:39/%s" % j)
                self.assert_ok("--dry-run", i, "23,21,15:19,13/%s" % j)
                self.assert_ok("--dry-run", i, "1,9/%s" % j)

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
            to,
            "port",
            "domain",
            "from",
            frm,
            "port",
            "auth",
        )
        self.assert_ok(
            "--dry-run",
            "delete",
            "reject",
            "to",
            to,
            "port",
            "domain",
            "from",
            frm,
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

        # Insert
        self.assert_ok("allow", "13")
        self.assert_ok("allow", "23")
        self.assert_ok("insert", "1", "allow", "9999")
        self.assert_ok("insert", "1", "allow", "log", "9998")
        self.assert_ok("insert", "2", "reject", "to", "192.168.0.1", "from", "10.0.0.1")
        # on-disk: five rules inserted
        self.assert_rule_count(5)
        self.assert_rules_contain("9999")
        self.assert_ok("delete", "allow", "13")
        self.assert_ok("delete", "allow", "23")
        self.assert_ok("delete", "allow", "9999")
        self.assert_ok("delete", "allow", "log", "9998")
        self.assert_ok("delete", "reject", "to", "192.168.0.1", "from", "10.0.0.1")
        self.assert_rule_count(0)

        # Man page (interface)
        self.assert_ok(
            "--dry-run",
            "allow",
            "in",
            "on",
            "eth0",
            "to",
            "any",
            "port",
            "80",
            "proto",
            "tcp",
        )

        # Interfaces
        for i in ("in", "out"):
            for j in ("allow", "deny", "limit", "reject"):
                self.assert_ok(j, i, "on", "eth0")
                self.assert_ok(j, i, "on", "eth0", "to", "192.168.0.1", "port", "13")
                self.assert_ok(j, i, "on", "eth0", "from", "10.0.0.1", "port", "80")
                self.assert_ok(
                    j, i, "on", "eth0", "to", "192.168.0.1", "from", "10.0.0.1"
                )
                self.assert_ok(
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "from",
                    "10.0.0.1",
                )
                self.assert_ok(
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "from",
                    "10.0.0.1",
                    "port",
                    "80",
                )
                self.assert_ok(
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "from",
                    "10.0.0.1",
                    "port",
                    "80",
                )
                self.assert_ok(
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "proto",
                    "tcp",
                )
                self.assert_ok(
                    j, i, "on", "eth0", "from", "10.0.0.1", "port", "80", "proto", "tcp"
                )
                self.assert_ok(
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "from",
                    "10.0.0.1",
                    "proto",
                    "tcp",
                )
                self.assert_ok(
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "from",
                    "10.0.0.1",
                    "proto",
                    "udp",
                )
                self.assert_ok(
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "from",
                    "10.0.0.1",
                    "port",
                    "80",
                    "proto",
                    "udp",
                )
                self.assert_ok(
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "from",
                    "10.0.0.1",
                    "port",
                    "80",
                    "proto",
                    "udp",
                )

                self.assert_ok("delete", j, i, "on", "eth0")
                self.assert_ok(
                    "delete", j, i, "on", "eth0", "to", "192.168.0.1", "port", "13"
                )
                self.assert_ok(
                    "delete", j, i, "on", "eth0", "from", "10.0.0.1", "port", "80"
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "from",
                    "10.0.0.1",
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "from",
                    "10.0.0.1",
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "from",
                    "10.0.0.1",
                    "port",
                    "80",
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "from",
                    "10.0.0.1",
                    "port",
                    "80",
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "proto",
                    "tcp",
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "from",
                    "10.0.0.1",
                    "port",
                    "80",
                    "proto",
                    "tcp",
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "from",
                    "10.0.0.1",
                    "proto",
                    "tcp",
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "from",
                    "10.0.0.1",
                    "proto",
                    "udp",
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "from",
                    "10.0.0.1",
                    "port",
                    "80",
                    "proto",
                    "udp",
                )
                self.assert_ok(
                    "delete",
                    j,
                    i,
                    "on",
                    "eth0",
                    "to",
                    "192.168.0.1",
                    "port",
                    "13",
                    "from",
                    "10.0.0.1",
                    "port",
                    "80",
                    "proto",
                    "udp",
                )
            self.assert_ok("allow", i, "on", "eth0")
            self.assert_ok("deny", i, "on", "eth0")
            self.assert_ok("delete", "deny", i, "on", "eth0")

        # Man page (ipv6)
        self.assert_ok("--dry-run", "allow", "to", "10.0.0.1", "proto", "ipv6")
        self.assert_ok(
            "--dry-run",
            "allow",
            "to",
            "10.0.0.1",
            "from",
            "10.4.0.0/16",
            "proto",
            "ipv6",
        )

        # Man page (ipsec)
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

        # Interface with '+'
        self.assert_ok(
            "--dry-run",
            "allow",
            "in",
            "on",
            "eth+",
            "to",
            "any",
            "port",
            "80",
            "proto",
            "tcp",
        )

        # Comments
        self.assert_ok("allow", "2222/tcp", "comment", '"SSH port"')
        self.assert_rules_contain("2222")
        self.assert_ok(
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
            "comment",
            '"dns port"',
        )
        # delete exact
        self.assert_ok(
            "delete",
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
            "comment",
            '"dns port"',
        )
        # delete without comment
        self.assert_ok("delete", "allow", "2222/tcp")
        self.assert_rules_exclude("2222")

        # Prepend
        self.assert_ok("allow", "22/tcp")
        self.assert_ok("allow", "from", "1.2.3.4")
        self.assert_ok("prepend", "deny", "from", "6.7.8.9")
        # prepended rule lands before the previously-added 1.2.3.4 rule
        self.assert_rules_order("6.7.8.9", "1.2.3.4")
        self.assert_ok("delete", "allow", "22/tcp")
        self.assert_ok("delete", "allow", "from", "1.2.3.4")
        self.assert_ok("delete", "deny", "from", "6.7.8.9")

        # Prepend (no rules)
        self.assert_ok("prepend", "allow", "from", "1.2.3.4")
        self.assert_ok("delete", "allow", "from", "1.2.3.4")

        # Prepend (multi rules)
        self.assert_ok("allow", "from", "1.2.3.4")
        self.assert_ok("prepend", "deny", "23")
        self.assert_ok("delete", "allow", "from", "1.2.3.4")
        self.assert_ok("delete", "deny", "23")
