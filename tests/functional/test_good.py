# -*- coding: utf-8 -*-
#
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

import os
import unittest

from tests.functional.testutil import UFWTestEnvironment


class TestGoodApps(unittest.TestCase):
    """
    Test valid application profile usage.

    Equivalent to: tests/good/apps
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()
        self.env.setup_profiles()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_app_list_and_info(self) -> None:
        """Test listing and getting info about application profiles."""
        self.env.run_cmd(["app", "list"], expected_rc=0)

        profiles = [
            "Apache",
            "Apache Secure",
            "Apache Full",
            "Bind9",
            "Samba",
            "Custom Web App",
            "Custom Web App2",
            "all",
            "0verkill",
        ]

        for profile in profiles:
            with self.subTest(profile=profile):
                self.env.run_cmd(
                    ["app", "info", profile],
                    expected_rc=0,
                    capture_output=False,
                )

    def test_app_simple_rules(self) -> None:
        """Test simple application rules (allow/deny/limit AppName)."""
        actions = ["allow", "deny", "limit"]
        profiles = [
            "Apache",
            "Apache Secure",
            "Apache Full",
            "Bind9",
            "Samba",
            "OpenNTPD",
            "Multi TCP",
            "Multi UDP",
            "Custom Web App2",
        ]

        for action in actions:
            for profile in profiles:
                with self.subTest(action=action, profile=profile):
                    self.env.run_cmd(
                        ["--dry-run", action, profile],
                        expected_rc=0,
                        capture_output=False,
                    )

    def test_app_extended_rules(self) -> None:
        """Test extended application rules with to/from specifiers."""
        actions = ["allow", "deny", "limit"]
        directions = ["to", "from"]
        locations = ["192.168.0.0/16", "any"]
        profiles = ["Apache", "Bind9", "Samba"]

        for action in actions:
            for direction in directions:
                for location in locations:
                    for profile in profiles:
                        with self.subTest(
                            action=action,
                            direction=direction,
                            location=location,
                            profile=profile,
                        ):
                            self.env.run_cmd(
                                [
                                    "--dry-run",
                                    action,
                                    direction,
                                    location,
                                    "app",
                                    profile,
                                ],
                                expected_rc=0,
                                capture_output=False,
                            )


class TestGoodArgs(unittest.TestCase):
    """
    Test valid command-line argument parsing.

    Equivalent to: tests/good/args
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()
        self.env.setup_profiles()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_logging_commands(self) -> None:
        """Test logging command variations."""
        logging_levels = ["on", "off", "ON", "OFF"]

        for level in logging_levels:
            with self.subTest(level=level):
                self.env.run_cmd(
                    ["--dry-run", "logging", level],
                    expected_rc=0,
                    capture_output=False,
                )

    def test_enable_disable_commands(self) -> None:
        """Test enable/disable commands."""
        commands = ["enable", "disable", "ENABLE", "DISABLE"]

        for cmd in commands:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run", cmd],
                    expected_rc=0,
                    capture_output=False,
                )

    def test_status_commands(self) -> None:
        """Test status command variations."""
        status_cmds = [
            ["status"],
            ["status", "verbose"],
            ["status", "numbered"],
        ]

        for cmd in status_cmds:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run"] + cmd,
                    expected_rc=0,
                    capture_output=False,
                )

    def test_basic_commands(self) -> None:
        """Test basic parser commands."""
        commands = [
            "enable",
            "disable",
            "help",
            "--help",
            "version",
            "--version",
            "reload",
        ]

        for cmd in commands:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run", cmd],
                    expected_rc=0,
                    capture_output=False,
                )

    def test_app_commands(self) -> None:
        """Test application commands."""
        app_cmds = [
            ["app", "list"],
            ["app", "info", "Apache"],
            ["app", "update", "Apache"],
            ["app", "update", "--add-new", "Apache"],
            ["app", "default", "skip"],
        ]

        for cmd in app_cmds:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run"] + cmd,
                    expected_rc=0,
                    capture_output=False,
                )

    def test_logging_levels(self) -> None:
        """Test all logging levels."""
        levels = ["on", "off", "low", "medium", "high", "full"]

        for level in levels:
            with self.subTest(level=level):
                self.env.run_cmd(
                    ["--dry-run", "logging", level],
                    expected_rc=0,
                    capture_output=False,
                )

    def test_default_policies(self) -> None:
        """Test default policy commands."""
        actions = ["allow", "deny", "reject"]
        directions = ["", "incoming", "outgoing", "routed"]

        for action in actions:
            for direction in directions:
                cmd = (
                    ["default", action]
                    if not direction
                    else ["default", action, direction]
                )
                with self.subTest(cmd=cmd):
                    self.env.run_cmd(
                        ["--dry-run"] + cmd,
                        expected_rc=0,
                        capture_output=False,
                    )

    def test_show_commands(self) -> None:
        """Test show report commands."""
        show_types = [
            "raw",
            "builtins",
            "before-rules",
            "user-rules",
            "after-rules",
            "logging-rules",
        ]

        for show_type in show_types:
            with self.subTest(show_type=show_type):
                self.env.run_cmd(
                    ["--dry-run", "show", show_type],
                    expected_rc=0,
                    capture_output=False,
                )


class TestGoodLogging(unittest.TestCase):
    """
    Test logging functionality.

    Equivalent to: tests/good/logging
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()
        self.env.setup_profiles()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_loglevel_settings(self) -> None:
        """Test that log levels are properly set in configuration."""
        if self.env.testconfig is None:
            self.fail("Test environment not set up")

        levels = ["off", "low", "medium", "high", "full"]

        for level in levels:
            with self.subTest(level=level):
                self.env.run_cmd(
                    ["--dry-run", "logging", level],
                    expected_rc=0,
                    capture_output=False,
                )

                ufw_conf = os.path.join(self.env.testconfig, "ufw.conf")
                with open(ufw_conf, "r", encoding="utf-8") as f:
                    content = f.read()

                self.assertIn(f"LOGLEVEL={level}", content)


class TestGoodNetmasks(unittest.TestCase):
    """
    Test valid netmask specifications.

    Equivalent to: tests/good/netmasks
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_valid_cidr(self) -> None:
        """Test all valid CIDR notations from /0 to /32."""
        for cidr in range(0, 33):
            with self.subTest(cidr=cidr):
                self.env.run_cmd(
                    ["--dry-run", "allow", "from", f"10.0.0.1/{cidr}"],
                    expected_rc=0,
                    capture_output=False,
                )

    def test_valid_dotted_netmask(self) -> None:
        """Test valid dotted decimal netmask notations."""
        test_values = list(range(0, 256, 16))

        for val in test_values:
            test_cases = [
                f"255.255.255.{val}",
                f"255.255.{val}.255",
                f"255.{val}.255.255",
                f"{val}.255.255.255",
                f"{val}.{val}.{val}.{val}",
            ]

            for netmask in test_cases:
                with self.subTest(netmask=netmask):
                    self.env.run_cmd(
                        ["--dry-run", "allow", "from", f"10.0.0.1/{netmask}"],
                        expected_rc=0,
                        capture_output=False,
                    )


class TestGoodPolicy(unittest.TestCase):
    """
    Test valid default policy configurations.

    Equivalent to: tests/good/policy
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_valid_default_policies(self) -> None:
        """Test that valid default policies are accepted."""
        if self.env.testconfig is None:
            self.fail("Test environment not set up")

        default_ufw = os.path.join(self.env.testconfig, "..", "default", "ufw")

        policy_chains = ["INPUT", "OUTPUT", "FORWARD"]
        valid_policies = ["ACCEPT", "DROP", "REJECT"]

        for chain in policy_chains:
            for policy in valid_policies:
                with self.subTest(chain=chain, policy=policy):
                    with open(default_ufw, "r", encoding="utf-8") as f:
                        original_content = f.read()

                    modified_content = original_content

                    for existing_policy in valid_policies:
                        modified_content = modified_content.replace(
                            f"DEFAULT_{chain}_POLICY={existing_policy}",
                            f"DEFAULT_{chain}_POLICY={policy}",
                        )

                    with open(default_ufw, "w", encoding="utf-8") as f:
                        f.write(modified_content)

                    self.env.run_cmd(
                        ["--dry-run", "status"],
                        expected_rc=0,
                        capture_output=False,
                    )

                    with open(default_ufw, "w", encoding="utf-8") as f:
                        f.write(original_content)


class TestGoodReports(unittest.TestCase):
    """
    Test report generation functionality.

    Equivalent to: tests/good/reports
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_show_reports(self) -> None:
        """Test various show report commands."""
        report_types = [
            "raw",
            "builtins",
            "before-rules",
            "user-rules",
            "after-rules",
            "logging-rules",
            "listening",
            "added",
        ]

        for report_type in report_types:
            with self.subTest(report_type=report_type):
                self.env.run_cmd(
                    ["--dry-run", "show", report_type],
                    expected_rc=0,
                    capture_output=False,
                )


class TestGoodRoute(unittest.TestCase):
    """
    Test route command functionality.

    Equivalent to: tests/good/route
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_route_commands(self) -> None:
        """Test basic route commands."""
        route_cmds = [
            ["route", "allow", "to", "10.0.0.1"],
            ["route", "deny", "from", "192.168.0.0/24", "to", "10.0.0.0/8"],
            [
                "route",
                "allow",
                "to",
                "10.0.0.1",
                "port",
                "80",
                "proto",
                "tcp",
            ],
        ]

        for cmd in route_cmds:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run"] + cmd,
                    expected_rc=0,
                    capture_output=False,
                )


class TestGoodRules(unittest.TestCase):
    """
    Test comprehensive rule specifications.

    Equivalent to: tests/good/rules
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_simple_port_rules(self) -> None:
        """Test simple port specifications."""
        test_cases = [
            ["allow", "53"],
            ["allow", "25/tcp"],
            ["allow", "smtp"],
            ["deny", "proto", "tcp", "to", "any", "port", "80"],
            [
                "deny",
                "proto",
                "tcp",
                "from",
                "10.0.0.0/8",
                "to",
                "192.168.0.1",
                "port",
                "25",
            ],
            ["limit", "daytime/tcp"],
        ]

        for rule in test_cases:
            with self.subTest(rule=rule):
                self.env.run_cmd(
                    ["--dry-run"] + rule,
                    expected_rc=0,
                    capture_output=False,
                )

    def test_from_to_rules(self) -> None:
        """Test rules with from/to specifications."""
        from_ip = "192.168.0.1"
        to_ip = "10.0.0.1"
        actions = ["allow", "deny", "limit"]

        for action in actions:
            test_cases = [
                [action, "from", from_ip],
                [action, "to", to_ip],
                [action, "to", to_ip, "from", from_ip],
                [action, "from", from_ip, "port", "80"],
                [action, "to", to_ip, "port", "25"],
                [action, "to", to_ip, "from", from_ip, "port", "80"],
                [action, "to", to_ip, "port", "25", "from", from_ip],
                [
                    action,
                    "to",
                    to_ip,
                    "port",
                    "25",
                    "from",
                    from_ip,
                    "port",
                    "80",
                ],
            ]

            for rule in test_cases:
                with self.subTest(rule=rule):
                    self.env.run_cmd(
                        ["--dry-run"] + rule,
                        expected_rc=0,
                        capture_output=False,
                    )

    def test_protocol_specifications(self) -> None:
        """Test rules with protocol specifications."""
        from_ip = "192.168.0.1"
        to_ip = "10.0.0.1"
        actions = ["allow", "deny", "limit"]
        protocols = ["tcp", "udp"]

        for action in actions:
            for proto in protocols:
                test_cases = [
                    [action, "from", from_ip, "port", "80", "proto", proto],
                    [action, "to", to_ip, "port", "25", "proto", proto],
                    [
                        action,
                        "to",
                        to_ip,
                        "from",
                        from_ip,
                        "port",
                        "80",
                        "proto",
                        proto,
                    ],
                    [
                        action,
                        "to",
                        to_ip,
                        "port",
                        "25",
                        "proto",
                        proto,
                        "from",
                        from_ip,
                    ],
                    [
                        action,
                        "to",
                        to_ip,
                        "port",
                        "25",
                        "proto",
                        proto,
                        "from",
                        from_ip,
                        "port",
                        "80",
                    ],
                ]

                for rule in test_cases:
                    with self.subTest(rule=rule):
                        self.env.run_cmd(
                            ["--dry-run"] + rule,
                            expected_rc=0,
                            capture_output=False,
                        )

    def test_service_names(self) -> None:
        """Test using service names in rules."""
        service_rules = [
            ["allow", "to", "any", "port", "smtp", "from", "any", "port", "smtp"],
            ["allow", "to", "any", "port", "smtp", "from", "any", "port", "25"],
            ["allow", "to", "any", "port", "25", "from", "any", "port", "smtp"],
        ]

        for rule in service_rules:
            with self.subTest(rule=rule):
                self.env.run_cmd(
                    ["--dry-run"] + rule,
                    expected_rc=0,
                    capture_output=False,
                )


if __name__ == "__main__":
    unittest.main()
