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
# Rendering oracle (the "depth" layer).
#
# These are HAND-CURATED, human-readable assertions of exactly what a command
# should render. There is one test per atomic rendering feature (source, dest,
# port range, multiport, interfaces, the actions, limit, logging, app, v6) plus
# the handful of feature combinations worth pinning by hand. Each asserts the
# boilerplate-factored render (assert_render strips the constant chain
# scaffolding -- see support.py), so a test reads as the few lines the command
# is *supposed* to produce.
#
# This layer is the independent oracle. The generated covering-set transcript is
# the exhaustive net that catches any change to any shape; these tests are what
# keep that transcript honest -- because a human pinned the expected value here
# (e.g. limit's "--hitcount 6"), the net cannot silently bless a regression.

import tests.functional.support
from tests.functional.support import FunctionalTestCase


class BoilerplateTests(FunctionalTestCase):
    """The constant chain scaffolding that assert_render factors out, verified
    once here so the per-feature tests don't repeat it."""

    # No old-harness golden to replay: this is a hand-written oracle.
    class_name = None

    # The 8 scaffolding lines emitted on every iptables dry-run at the default
    # LOGLEVEL (low): the logging chains and the limit reject/accept chains.
    SCAFFOLDING = [
        '-A ufw-after-logging-input -j LOG --log-prefix "[UFW BLOCK] " '
        "-m limit --limit 3/min --limit-burst 10",
        '-A ufw-after-logging-forward -j LOG --log-prefix "[UFW BLOCK] " '
        "-m limit --limit 3/min --limit-burst 10",
        "-I ufw-logging-deny -m conntrack --ctstate INVALID -j RETURN "
        "-m limit --limit 3/min --limit-burst 10",
        '-A ufw-logging-deny -j LOG --log-prefix "[UFW BLOCK] " '
        "-m limit --limit 3/min --limit-burst 10",
        '-A ufw-logging-allow -j LOG --log-prefix "[UFW ALLOW] " '
        "-m limit --limit 3/min --limit-burst 10",
        "-A ufw-user-limit -m limit --limit 3/minute -j LOG "
        '--log-prefix "[UFW LIMIT BLOCK] "',
        "-A ufw-user-limit -j REJECT",
        "-A ufw-user-limit-accept -j ACCEPT",
    ]

    # The chain declarations a dry-run emits. The transcript factors these out too
    # (they are part of the constant frame), so they are pinned here: a renamed,
    # added or removed chain is a real change that must fail a test.
    CHAIN_DECLS_V4 = [
        ":ufw-user-input - [0:0]",
        ":ufw-user-output - [0:0]",
        ":ufw-user-forward - [0:0]",
        ":ufw-before-logging-input - [0:0]",
        ":ufw-before-logging-output - [0:0]",
        ":ufw-before-logging-forward - [0:0]",
        ":ufw-user-logging-input - [0:0]",
        ":ufw-user-logging-output - [0:0]",
        ":ufw-user-logging-forward - [0:0]",
        ":ufw-after-logging-input - [0:0]",
        ":ufw-after-logging-output - [0:0]",
        ":ufw-after-logging-forward - [0:0]",
        ":ufw-logging-deny - [0:0]",
        ":ufw-logging-allow - [0:0]",
        ":ufw-user-limit - [0:0]",
        ":ufw-user-limit-accept - [0:0]",
    ]
    # With IPV6=yes the same set is declared again for the ufw6- chains, minus the
    # limit chains (rate limiting is v4-only).
    CHAIN_DECLS_V6_EXTRA = [
        ":ufw6-user-input - [0:0]",
        ":ufw6-user-output - [0:0]",
        ":ufw6-user-forward - [0:0]",
        ":ufw6-before-logging-input - [0:0]",
        ":ufw6-before-logging-output - [0:0]",
        ":ufw6-before-logging-forward - [0:0]",
        ":ufw6-user-logging-input - [0:0]",
        ":ufw6-user-logging-output - [0:0]",
        ":ufw6-user-logging-forward - [0:0]",
        ":ufw6-after-logging-input - [0:0]",
        ":ufw6-after-logging-output - [0:0]",
        ":ufw6-after-logging-forward - [0:0]",
        ":ufw6-logging-deny - [0:0]",
        ":ufw6-logging-allow - [0:0]",
    ]

    def test_scaffolding_is_constant(self):
        # The scaffolding is identical no matter the command, which is precisely
        # why assert_render can factor it out: verify the exact lines, and verify
        # two unrelated commands produce byte-identical scaffolding.
        self.assertEqual(self.SCAFFOLDING, self.scaffolding("allow", "22"))
        self.assertEqual(
            self.scaffolding("allow", "22"),
            self.scaffolding("deny", "out", "on", "eth0"),
        )

    def test_chain_declarations(self):
        self.assertEqual(self.CHAIN_DECLS_V4, self.chain_decls("allow", "22"))

    def test_chain_declarations_ipv6(self):
        self.enable_ipv6()
        self.assertEqual(
            self.CHAIN_DECLS_V4 + self.CHAIN_DECLS_V6_EXTRA,
            self.chain_decls("allow", "22"),
        )


class RenderTests(FunctionalTestCase):
    """One readable assertion per atomic rendering feature."""

    class_name = None

    # -- actions -----------------------------------------------------------

    def test_accept_single_proto(self):
        # A port with an explicit proto renders one ACCEPT line.
        self.assert_render(
            "allow 80/tcp",
            ["-A ufw-user-input -p tcp --dport 80 -j ACCEPT"],
        )

    def test_accept_both_protos(self):
        # A bare port defaults to both tcp and udp (two rules).
        self.assert_render(
            "allow 22",
            [
                "-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
                "-A ufw-user-input -p udp --dport 22 -j ACCEPT",
            ],
        )

    def test_deny_renders_drop(self):
        self.assert_render(
            "deny 25",
            [
                "-A ufw-user-input -p tcp --dport 25 -j DROP",
                "-A ufw-user-input -p udp --dport 25 -j DROP",
            ],
        )

    def test_reject_renders_reject_with(self):
        # 'auth' is 113/tcp; reject adds --reject-with tcp-reset.
        self.assert_render(
            "reject auth",
            ["-A ufw-user-input -p tcp --dport 113 -j REJECT --reject-with tcp-reset"],
        )

    # -- match dimensions --------------------------------------------------

    def test_source_address(self):
        self.assert_render(
            "allow from 10.0.0.1",
            ["-A ufw-user-input -s 10.0.0.1 -j ACCEPT"],
        )

    def test_dest_address(self):
        self.assert_render(
            "allow to 10.0.0.1",
            ["-A ufw-user-input -d 10.0.0.1 -j ACCEPT"],
        )

    def test_source_port(self):
        # A source port + interface + proto, on the output chain.
        self.assert_render(
            "allow out on eth0 from 10.0.0.1 port 80 proto tcp",
            ["-A ufw-user-output -o eth0 -p tcp -s 10.0.0.1 --sport 80 -j ACCEPT"],
        )

    def test_multiport(self):
        # A mixed list+range collapses to one -m multiport rule, sorted.
        self.assert_render(
            "allow to any port 23,21,15:19 proto tcp",
            ["-A ufw-user-input -p tcp -m multiport --dports 15:19,21,23 -j ACCEPT"],
        )

    def test_in_interface(self):
        self.assert_render(
            "allow in on eth0",
            ["-A ufw-user-input -i eth0 -j ACCEPT"],
        )

    def test_out_interface(self):
        self.assert_render(
            "allow out on eth0",
            ["-A ufw-user-output -o eth0 -j ACCEPT"],
        )

    # -- routing (FORWARD chain) ------------------------------------------

    def test_route_both_interfaces(self):
        # A full route rule: in+out iface, src+dst subnet, dport, proto, on the
        # forward chain.
        self.assert_render(
            "route allow in on eth0 out on eth1 "
            "from 10.0.0.0/24 to 10.0.1.0/24 port 80 proto tcp",
            [
                "-A ufw-user-forward -i eth0 -o eth1 -p tcp -d 10.0.1.0/24 "
                "--dport 80 -s 10.0.0.0/24 -j ACCEPT"
            ],
        )

    # -- limit -------------------------------------------------------------

    def test_limit(self):
        # The limit rule is the canonical regression target: --hitcount 6 is
        # pinned here by hand, so a change to that value fails this oracle even
        # if a generated transcript were re-blessed.
        self.assert_render(
            "limit ssh",
            [
                "-A ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW "
                "-m recent --set",
                "-A ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW "
                "-m recent --update --seconds 30 --hitcount 6 -j ufw-user-limit",
                "-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit-accept",
            ],
        )

    # -- per-rule logging --------------------------------------------------

    def test_log_jumps_to_logging_chain(self):
        # 'allow log' inserts a jump to ufw-user-logging-input before ACCEPT.
        self.assert_render(
            "allow log 22",
            [
                "-A ufw-user-input -p tcp --dport 22 -j ufw-user-logging-input",
                "-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
                "-A ufw-user-input -p udp --dport 22 -j ufw-user-logging-input",
                "-A ufw-user-input -p udp --dport 22 -j ACCEPT",
            ],
        )

    # -- application profiles ---------------------------------------------

    def test_app_profile(self):
        # An app rule expands to the profile's ports, tagged with a dapp_ comment
        # so it can be reconstituted. CIFS is udp 137,138 + tcp 139,445; the
        # udp rule appears twice below because a dry-run emits one full
        # *filter dump per profile item and rendered_rules() concatenates the
        # dumps -- on disk each rule is written once.
        self.assert_render(
            "allow CIFS",
            [
                "-A ufw-user-input -p udp -m multiport --dports 137,138 -j ACCEPT "
                "-m comment --comment 'dapp_CIFS'",
                "-A ufw-user-input -p udp -m multiport --dports 137,138 -j ACCEPT "
                "-m comment --comment 'dapp_CIFS'",
                "-A ufw-user-input -p tcp -m multiport --dports 139,445 -j ACCEPT "
                "-m comment --comment 'dapp_CIFS'",
            ],
        )


class CombinationTests(FunctionalTestCase):
    """The feature *combinations* worth pinning by hand -- the bug-prone overlaps
    where two dimensions interact (multiport+reject, route+sport, log+limit, two
    addresses, a port range as source, an interface on a route). The generated
    transcript covers every combination structurally; these pin the ones a human
    most wants to read and that are most likely to regress."""

    class_name = None

    def test_multiport_reject(self):
        # A mixed list+range with reject: sorted dports + tcp-reset.
        self.assert_render(
            "reject 23,21,15:19,13/tcp",
            [
                "-A ufw-user-input -p tcp -m multiport --dports 13,15:19,21,23 "
                "-j REJECT --reject-with tcp-reset"
            ],
        )

    def test_range_alone_uses_multiport(self):
        # Even a lone port range renders via -m multiport.
        self.assert_render(
            "allow 15:19/tcp",
            ["-A ufw-user-input -p tcp -m multiport --dports 15:19 -j ACCEPT"],
        )

    def test_route_source_port_both_protos(self):
        # A route with a source port but no proto expands to tcp+udp on FORWARD.
        self.assert_render(
            "route allow from 192.168.0.1 port 80",
            [
                "-A ufw-user-forward -p tcp -s 192.168.0.1 --sport 80 -j ACCEPT",
                "-A ufw-user-forward -p udp -s 192.168.0.1 --sport 80 -j ACCEPT",
            ],
        )

    def test_route_reject_both_interfaces(self):
        self.assert_render(
            "route reject in on eth0 out on eth1 to 10.0.1.0/24 port 443 proto tcp",
            [
                "-A ufw-user-forward -i eth0 -o eth1 -p tcp -d 10.0.1.0/24 "
                "--dport 443 -j REJECT --reject-with tcp-reset"
            ],
        )

    def test_out_interface_source_port_deny(self):
        self.assert_render(
            "deny out on eth0 from 10.0.0.1 port 80 proto tcp",
            ["-A ufw-user-output -o eth0 -p tcp -s 10.0.0.1 --sport 80 -j DROP"],
        )

    def test_source_and_dest_with_port(self):
        # Both endpoints plus a dest port on one rule.
        self.assert_render(
            "allow from 10.0.0.1 to 10.0.0.2 port 22 proto tcp",
            ["-A ufw-user-input -p tcp -d 10.0.0.2 --dport 22 -s 10.0.0.1 -j ACCEPT"],
        )

    def test_source_port_range(self):
        # A source port range renders as -m multiport --sports.
        self.assert_render(
            "allow from any port 1000:2000 proto udp",
            ["-A ufw-user-input -p udp -m multiport --sports 1000:2000 -j ACCEPT"],
        )

    def test_subnet_source(self):
        self.assert_render(
            "allow from 10.0.0.0/8",
            ["-A ufw-user-input -s 10.0.0.0/8 -j ACCEPT"],
        )

    def test_in_interface_subnet_proto_deny(self):
        self.assert_render(
            "deny in on eth0 from 10.0.0.0/24 proto udp",
            ["-A ufw-user-input -i eth0 -p udp -s 10.0.0.0/24 -j DROP"],
        )

    def test_log_and_reject(self):
        # Logging jump precedes the reject.
        self.assert_render(
            "reject log smtp",
            [
                "-A ufw-user-input -p tcp --dport 25 -j ufw-user-logging-input",
                "-A ufw-user-input -p tcp --dport 25 -j REJECT --reject-with tcp-reset",
            ],
        )

    def test_log_and_limit(self):
        # log + limit: the logging jump precedes the full recent/limit sequence.
        self.assert_render(
            "limit log ssh",
            [
                "-A ufw-user-input -p tcp --dport 22 -j ufw-user-logging-input",
                "-A ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW "
                "-m recent --set",
                "-A ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW "
                "-m recent --update --seconds 30 --hitcount 6 -j ufw-user-limit",
                "-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit-accept",
            ],
        )

    def test_app_single_port(self):
        # Apache is a single tcp port; the dapp_ comment is still attached.
        self.assert_render(
            "allow Apache",
            [
                "-A ufw-user-input -p tcp --dport 80 -j ACCEPT "
                "-m comment --comment 'dapp_Apache'"
            ],
        )

    # -- portless protocols (gre / igmp / vrrp / ipv6) --------------------
    # ufw supports these (util.py portless_protocols) but the original tests
    # only ever exercised ah/esp. They render like esp/ah: a bare -p <proto>.

    def test_proto_gre(self):
        self.assert_render(
            "allow to 10.0.0.1 proto gre",
            ["-A ufw-user-input -p gre -d 10.0.0.1 -j ACCEPT"],
        )

    def test_proto_igmp(self):
        self.assert_render(
            "allow to 10.0.0.1 proto igmp",
            ["-A ufw-user-input -p igmp -d 10.0.0.1 -j ACCEPT"],
        )

    def test_proto_vrrp(self):
        self.assert_render(
            "allow to 10.0.0.1 proto vrrp",
            ["-A ufw-user-input -p vrrp -d 10.0.0.1 -j ACCEPT"],
        )

    def test_proto_ipv6(self):
        # proto ipv6 (6in4 tunnels) is portless and, counterintuitively,
        # v4-only (util.py ipv4_only_protocols): it is protocol 41 carried
        # over IPv4.
        self.assert_render(
            "allow to 10.0.0.1 proto ipv6",
            ["-A ufw-user-input -p ipv6 -d 10.0.0.1 -j ACCEPT"],
        )


class RenderV6Tests(FunctionalTestCase):
    """The v4/v6 differential: with IPV6=yes the same command also renders the
    ufw6-* chains. Kept separate because it toggles IPV6 on in setUp."""

    class_name = None

    def setUp(self):
        super().setUp()
        self.enable_ipv6()

    def test_v4_and_v6_rendered_together(self):
        self.assert_render(
            "allow 22",
            [
                "-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
                "-A ufw-user-input -p udp --dport 22 -j ACCEPT",
                "-A ufw6-user-input -p tcp --dport 22 -j ACCEPT",
                "-A ufw6-user-input -p udp --dport 22 -j ACCEPT",
            ],
        )

    def test_v6_only_source(self):
        # A v6 source address renders only on the ufw6 chain.
        self.assert_render(
            "allow from 2001:db8::/32 port 80 proto udp",
            ["-A ufw6-user-input -p udp -s 2001:db8::/32 --sport 80 -j ACCEPT"],
        )

    def test_multiport_both_families(self):
        # A multiport rule with no address renders on both v4 and v6 chains.
        self.assert_render(
            "allow 23,21,15:19,13/tcp",
            [
                "-A ufw-user-input -p tcp -m multiport --dports 13,15:19,21,23 "
                "-j ACCEPT",
                "-A ufw6-user-input -p tcp -m multiport --dports 13,15:19,21,23 "
                "-j ACCEPT",
            ],
        )

    def test_v6_reject_proto_differs_by_family(self):
        # tcp gets --reject-with tcp-reset; udp gets a plain REJECT. A v6 source
        # keeps the rule on the ufw6 chain only.
        self.assert_render(
            "reject from 2001:db8::/32 to any port 25",
            [
                "-A ufw6-user-input -p tcp --dport 25 -s 2001:db8::/32 "
                "-j REJECT --reject-with tcp-reset",
                "-A ufw6-user-input -p udp --dport 25 -s 2001:db8::/32 -j REJECT",
            ],
        )

    def test_limit_is_v4_only(self):
        # limit is unsupported on v6, so even with IPV6=yes it renders only v4.
        self.assert_render(
            "limit ssh",
            [
                "-A ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW "
                "-m recent --set",
                "-A ufw-user-input -p tcp --dport 22 -m conntrack --ctstate NEW "
                "-m recent --update --seconds 30 --hitcount 6 -j ufw-user-limit",
                "-A ufw-user-input -p tcp --dport 22 -j ufw-user-limit-accept",
            ],
        )

    def test_proto_gre_v6(self):
        # A v6 destination with a portless proto renders on the ufw6 chain.
        self.assert_render(
            "allow to 2001:db8::1 proto gre",
            ["-A ufw6-user-input -p gre -d 2001:db8::1 -j ACCEPT"],
        )


class LoggingTests(FunctionalTestCase):
    """Pin the rendered logging output.

    The old good/logging test only ever checked the ``LOGLEVEL=`` string in
    ufw.conf -- it never verified the LOG *rules* that string produces, and they
    differ materially: off disables logging; low logs blocked packets; medium
    adds output logging and AUDIT of new connections; high drops the rate
    limits from block/allow logging and audits all packets (rate-limited);
    full drops the audit rate limit too. A regression swapping those
    is security-relevant and previously went uncaught. This pins each level's
    block for v4 and v6, plus the per-rule log / log-all distinction."""

    class_name = None

    # The ### LOGGING ### block ufw renders at each LOGLEVEL (v4 chains).
    LOG_BLOCKS = {
        "off": [
            "-I ufw-user-logging-input -j RETURN",
            "-I ufw-user-logging-output -j RETURN",
            "-I ufw-user-logging-forward -j RETURN",
        ],
        "low": [
            '-A ufw-after-logging-input -j LOG --log-prefix "[UFW BLOCK] " '
            "-m limit --limit 3/min --limit-burst 10",
            '-A ufw-after-logging-forward -j LOG --log-prefix "[UFW BLOCK] " '
            "-m limit --limit 3/min --limit-burst 10",
            "-I ufw-logging-deny -m conntrack --ctstate INVALID -j RETURN "
            "-m limit --limit 3/min --limit-burst 10",
            '-A ufw-logging-deny -j LOG --log-prefix "[UFW BLOCK] " '
            "-m limit --limit 3/min --limit-burst 10",
            '-A ufw-logging-allow -j LOG --log-prefix "[UFW ALLOW] " '
            "-m limit --limit 3/min --limit-burst 10",
        ],
        "medium": [
            '-A ufw-after-logging-input -j LOG --log-prefix "[UFW BLOCK] " '
            "-m limit --limit 3/min --limit-burst 10",
            '-A ufw-after-logging-output -j LOG --log-prefix "[UFW ALLOW] " '
            "-m limit --limit 3/min --limit-burst 10",
            '-A ufw-after-logging-forward -j LOG --log-prefix "[UFW BLOCK] " '
            "-m limit --limit 3/min --limit-burst 10",
            "-A ufw-logging-deny -m conntrack --ctstate INVALID -j LOG "
            '--log-prefix "[UFW AUDIT INVALID] " -m limit --limit 3/min '
            "--limit-burst 10",
            '-A ufw-logging-deny -j LOG --log-prefix "[UFW BLOCK] " '
            "-m limit --limit 3/min --limit-burst 10",
            '-A ufw-logging-allow -j LOG --log-prefix "[UFW ALLOW] " '
            "-m limit --limit 3/min --limit-burst 10",
            '-I ufw-before-logging-input -j LOG --log-prefix "[UFW AUDIT] " '
            "-m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10",
            '-I ufw-before-logging-output -j LOG --log-prefix "[UFW AUDIT] " '
            "-m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10",
            '-I ufw-before-logging-forward -j LOG --log-prefix "[UFW AUDIT] " '
            "-m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10",
        ],
        "high": [
            '-A ufw-after-logging-input -j LOG --log-prefix "[UFW BLOCK] "',
            '-A ufw-after-logging-output -j LOG --log-prefix "[UFW ALLOW] "',
            '-A ufw-after-logging-forward -j LOG --log-prefix "[UFW BLOCK] "',
            "-A ufw-logging-deny -m conntrack --ctstate INVALID -j LOG "
            '--log-prefix "[UFW AUDIT INVALID] "',
            '-A ufw-logging-deny -j LOG --log-prefix "[UFW BLOCK] "',
            '-A ufw-logging-allow -j LOG --log-prefix "[UFW ALLOW] "',
            '-I ufw-before-logging-input -j LOG --log-prefix "[UFW AUDIT] " '
            "-m limit --limit 3/min --limit-burst 10",
            '-I ufw-before-logging-output -j LOG --log-prefix "[UFW AUDIT] " '
            "-m limit --limit 3/min --limit-burst 10",
            '-I ufw-before-logging-forward -j LOG --log-prefix "[UFW AUDIT] " '
            "-m limit --limit 3/min --limit-burst 10",
        ],
        "full": [
            '-A ufw-after-logging-input -j LOG --log-prefix "[UFW BLOCK] "',
            '-A ufw-after-logging-output -j LOG --log-prefix "[UFW ALLOW] "',
            '-A ufw-after-logging-forward -j LOG --log-prefix "[UFW BLOCK] "',
            "-A ufw-logging-deny -m conntrack --ctstate INVALID -j LOG "
            '--log-prefix "[UFW AUDIT INVALID] "',
            '-A ufw-logging-deny -j LOG --log-prefix "[UFW BLOCK] "',
            '-A ufw-logging-allow -j LOG --log-prefix "[UFW ALLOW] "',
            '-I ufw-before-logging-input -j LOG --log-prefix "[UFW AUDIT] "',
            '-I ufw-before-logging-output -j LOG --log-prefix "[UFW AUDIT] "',
            '-I ufw-before-logging-forward -j LOG --log-prefix "[UFW AUDIT] "',
        ],
    }

    def test_logging_block_per_level(self):
        self.maxDiff = None
        for level, expected in self.LOG_BLOCKS.items():
            with self.subTest(level=level):
                self.assert_ok("logging", level)
                self.assertEqual(
                    expected,
                    self.logging_block("allow", "22"),
                    "v4 LOGGING block wrong at LOGLEVEL=%s" % level,
                )

    def test_v6_logging_block_per_level(self):
        # The v6 block is the v4 block on the ufw6- chains; asserting that parity
        # pins the v6 rendering at every level without duplicating the data.
        self.maxDiff = None
        self.enable_ipv6()
        for level, expected in self.LOG_BLOCKS.items():
            with self.subTest(level=level):
                self.assert_ok("logging", level)
                v6 = [x for x in self.logging_block("allow", "22") if "ufw6-" in x]
                derived = [x.replace("ufw-", "ufw6-") for x in expected]
                self.assertEqual(
                    derived, v6, "v6 LOGGING block wrong at LOGLEVEL=%s" % level
                )

    def test_log_logs_new_connections(self):
        # 'log' logs only NEW connections: the ufw-user-logging-input rule carries
        # -m conntrack --ctstate NEW.
        self.assertEqual(
            [
                "-A ufw-user-logging-input -p tcp --dport 22 -m conntrack "
                "--ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG "
                '--log-prefix "[UFW ALLOW] "',
                "-A ufw-user-logging-input -p tcp --dport 22 -j RETURN",
                "-A ufw-user-input -p tcp --dport 22 -j ufw-user-logging-input",
                "-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
                "-A ufw-user-logging-input -p udp --dport 22 -m conntrack "
                "--ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG "
                '--log-prefix "[UFW ALLOW] "',
                "-A ufw-user-logging-input -p udp --dport 22 -j RETURN",
                "-A ufw-user-input -p udp --dport 22 -j ufw-user-logging-input",
                "-A ufw-user-input -p udp --dport 22 -j ACCEPT",
            ],
            self.rule_block("allow", "log", "22"),
        )

    def test_log_all_logs_every_packet(self):
        # 'log-all' logs every packet: identical to 'log' but WITHOUT the
        # -m conntrack --ctstate NEW match.
        self.assertEqual(
            [
                "-A ufw-user-logging-input -p tcp --dport 22 -m limit "
                '--limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW ALLOW] "',
                "-A ufw-user-logging-input -p tcp --dport 22 -j RETURN",
                "-A ufw-user-input -p tcp --dport 22 -j ufw-user-logging-input",
                "-A ufw-user-input -p tcp --dport 22 -j ACCEPT",
                "-A ufw-user-logging-input -p udp --dport 22 -m limit "
                '--limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW ALLOW] "',
                "-A ufw-user-logging-input -p udp --dport 22 -j RETURN",
                "-A ufw-user-input -p udp --dport 22 -j ufw-user-logging-input",
                "-A ufw-user-input -p udp --dport 22 -j ACCEPT",
            ],
            self.rule_block("allow", "log-all", "22"),
        )


def test_main():
    tests.functional.support.run_unittest(
        BoilerplateTests,
        RenderTests,
        CombinationTests,
        RenderV6Tests,
        LoggingTests,
    )
