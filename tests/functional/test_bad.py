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
import shutil
import unittest

from tests.functional.testutil import UFWTestEnvironment


class TestBadArgs(unittest.TestCase):
    """
    Test invalid argument handling.

    Equivalent to: tests/bad/args
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_bad_logging_args(self) -> None:
        """Test invalid logging arguments."""
        bad_logging_cmds = [
            ["logging"],
            ["logging", "foo"],
            ["loggin", "on"],
        ]

        for cmd in bad_logging_cmds:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run"] + cmd, expected_rc=1, capture_output=False
                )

    def test_bad_default_args(self) -> None:
        """Test invalid default policy arguments."""
        directions = ["", "input", "incoming", "output", "outgoing", "routed"]
        bad_actions = [
            ("", ""),
            ("foo", ""),
            ("accept", ""),
            ("", "defaul"),
            ("limit", ""),
        ]

        for direction in directions:
            for action, cmd_prefix in bad_actions:
                cmd = (
                    [cmd_prefix or "default", action]
                    if direction == ""
                    else [cmd_prefix or "default", action, direction]
                )
                if action or direction:
                    with self.subTest(cmd=cmd):
                        self.env.run_cmd(
                            ["--dry-run"] + cmd,
                            expected_rc=1,
                            capture_output=False,
                        )

    def test_bad_enable_disable_args(self) -> None:
        """Test invalid enable/disable arguments."""
        bad_cmds = [
            ["enabled"],
            ["disabled"],
            ["enable", "OpenSSH"],
            ["disable", "OpenSSH"],
        ]

        for cmd in bad_cmds:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run"] + cmd, expected_rc=1, capture_output=False
                )

    def test_bad_rule_commands(self) -> None:
        """Test invalid allow/deny/limit commands without arguments."""
        for cmd in ["allow", "deny", "limit"]:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run", cmd], expected_rc=1, capture_output=False
                )

    def test_bad_ports(self) -> None:
        """Test invalid port specifications."""
        bad_ports = [
            "25a",
            "65536",
            "0",
            "XXX",
            "foobar",
        ]
        actions = ["allow", "deny", "limit"]

        for action in actions:
            for port in bad_ports:
                with self.subTest(action=action, port=port):
                    self.env.run_cmd(
                        ["--dry-run", action, port],
                        expected_rc=1,
                        capture_output=False,
                    )

    def test_bad_ip_addresses(self) -> None:
        """Test invalid IP address specifications."""
        bad_ips = [
            "192.168.0.",
            "192.168.0.1.1",
            "foo",
            "xxx.xxx.xxx.xx",
            "192a.168.0.1",
            "192.168a.0.1",
            "192.168.0a.1",
            "192.168.1.a1",
            "192.168.1..1",
            "192.168.1..1/24",
            "192.168.1.256",
            "256.0.0.0",
            "10.256.0.0",
        ]

        for ip in bad_ips:
            with self.subTest(ip=ip):
                self.env.run_cmd(
                    ["--dry-run", "allow", "to", ip],
                    expected_rc=1,
                    capture_output=False,
                )

    def test_bad_delete_args(self) -> None:
        """Test delete command without arguments."""
        self.env.run_cmd(["--dry-run", "delete"], expected_rc=1, capture_output=False)

    def test_mixed_ipv4_ipv6(self) -> None:
        """Test mixing IPv4 and IPv6 addresses is rejected."""
        mixed_specs = [
            ["allow", "to", "10.0.0.1", "from", "2001:db8::/32"],
            [
                "deny",
                "to",
                "10.0.0.1",
                "port",
                "25",
                "from",
                "2001:db8::/32",
                "proto",
                "tcp",
            ],
            ["allow", "to", "2001:db8::/32", "from", "10.0.0.1"],
        ]

        for spec in mixed_specs:
            with self.subTest(spec=spec):
                self.env.run_cmd(
                    ["--dry-run"] + spec, expected_rc=1, capture_output=False
                )

    def test_bad_interface_args(self) -> None:
        """Test invalid interface specifications."""
        directions = ["in", "out"]
        actions = ["allow", "deny", "limit"]
        bad_interface_specs = [
            ["on", "eth0:1"],
            ["on", "e?th0"],
            [],
            ["ona", "eth0"],
            ["eth0"],
        ]

        for direction in directions:
            for action in actions:
                for spec in bad_interface_specs:
                    cmd = ["--dry-run", action, direction] + spec
                    if spec:
                        with self.subTest(cmd=cmd):
                            self.env.run_cmd(cmd, expected_rc=1, capture_output=False)

    def test_bad_status_args(self) -> None:
        """Test invalid status arguments."""
        bad_status_cmds = [
            ["status", "foo"],
            ["status", "numbere"],
            ["status", "erbose"],
        ]

        for cmd in bad_status_cmds:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run"] + cmd, expected_rc=1, capture_output=False
                )

    def test_bad_show_args(self) -> None:
        """Test invalid show arguments."""
        bad_show_cmds = [
            ["show"],
            ["show", "ra"],
        ]

        for cmd in bad_show_cmds:
            with self.subTest(cmd=cmd):
                self.env.run_cmd(
                    ["--dry-run"] + cmd, expected_rc=1, capture_output=False
                )


class TestBadApps(unittest.TestCase):
    """
    Test invalid application profile handling.

    Equivalent to: tests/bad/apps
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()
        self.env.setup_profiles()

        bad_profiles_dir = "tests/defaults/profiles.bad"
        if os.path.exists(bad_profiles_dir) and self.env.testconfig:
            apps_dir = os.path.join(self.env.testconfig, "applications.d")
            for profile_file in os.listdir(bad_profiles_dir):
                src = os.path.join(bad_profiles_dir, profile_file)
                dst = os.path.join(apps_dir, profile_file)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_nonexistent_profiles(self) -> None:
        """Test referencing non-existent application profiles."""
        bad_profile_names = [
            "foo",
        ]

        for profile in bad_profile_names:
            with self.subTest(profile=profile):
                self.env.run_cmd(
                    ["app", "info", profile], expected_rc=1, capture_output=False
                )

    def test_bad_profile_definitions(self) -> None:
        """Test profiles with invalid definitions."""
        bad_profiles = [
            "bad-description1",
            "bad-description2",
            "bad-title1",
            "bad-title2",
            "bad-ports1",
            "bad-ports2",
            "bad-ports3",
            "bad-ports4",
            "bad-ports5",
            "bad-ports6",
            "ssh",
        ]

        for profile in bad_profiles:
            with self.subTest(profile=profile):
                self.env.run_cmd(
                    ["app", "info", profile], expected_rc=1, capture_output=False
                )

    def test_bad_app_commands(self) -> None:
        """Test invalid application commands."""
        self.env.run_cmd(
            ["app", "update", "--add-new", "all"],
            expected_rc=1,
            capture_output=False,
        )

    def test_app_integration_nonexistent(self) -> None:
        """Test using non-existent apps in rules."""
        actions = ["allow", "deny", "limit"]

        for action in actions:
            with self.subTest(action=action, profile="NONEXISTENT"):
                self.env.run_cmd(
                    [action, "NONEXISTENT"], expected_rc=1, capture_output=False
                )

    def test_app_with_protocol_spec(self) -> None:
        """Test that apps with protocol suffixes are rejected."""
        actions = ["allow", "deny", "limit"]

        for action in actions:
            with self.subTest(action=action):
                self.env.run_cmd(
                    [action, "Apache/tcp"], expected_rc=1, capture_output=False
                )


class TestBadNetmasks(unittest.TestCase):
    """
    Test invalid netmask specifications.

    Equivalent to: tests/bad/netmasks
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_invalid_cidr(self) -> None:
        """Test invalid CIDR notations."""
        bad_cidrs = ["16a", "33", "-1"]

        for cidr in bad_cidrs:
            with self.subTest(cidr=cidr, direction="to"):
                self.env.run_cmd(
                    ["--dry-run", "allow", "to", f"10.0.0.1/{cidr}"],
                    expected_rc=1,
                    capture_output=False,
                )
            with self.subTest(cidr=cidr, direction="from"):
                self.env.run_cmd(
                    ["--dry-run", "allow", "from", f"10.0.0.1/{cidr}"],
                    expected_rc=1,
                    capture_output=False,
                )

    def test_invalid_dotted_netmask(self) -> None:
        """Test invalid dotted decimal netmasks."""
        bad_netmasks = [
            "256.255.255.255",
            "255.256.255.255",
            "255.256.256.255",
            "255.255.255.256",
            "256.256.256.256",
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

        for netmask in bad_netmasks:
            with self.subTest(netmask=netmask, direction="to"):
                self.env.run_cmd(
                    ["--dry-run", "allow", "to", f"192.168.0.0/{netmask}"],
                    expected_rc=1,
                    capture_output=False,
                )
            with self.subTest(netmask=netmask, direction="from"):
                self.env.run_cmd(
                    ["--dry-run", "allow", "from", f"192.168.0.0/{netmask}"],
                    expected_rc=1,
                    capture_output=False,
                )


class TestBadPolicy(unittest.TestCase):
    """
    Test invalid default policy configurations.

    Equivalent to: tests/bad/policy
    """

    def setUp(self) -> None:
        """Set up test environment before each test."""
        self.env = UFWTestEnvironment()
        self.env.setup()

    def tearDown(self) -> None:
        """Clean up test environment after each test."""
        if hasattr(self, "env"):
            self.env.teardown()

    def test_invalid_default_policies(self) -> None:
        """Test that invalid default policies in config are rejected."""
        if self.env.testconfig is None:
            self.fail("Test environment not set up")

        default_ufw = os.path.join(self.env.testconfig, "..", "default", "ufw")

        policy_chains = ["INPUT", "OUTPUT", "FORWARD"]
        bad_policies = ["", "ACCEP", "DRP", "REJCT", "ALLOW", "DENY", "LIMIT"]

        for chain in policy_chains:
            for policy in bad_policies:
                with self.subTest(chain=chain, policy=policy):
                    with open(default_ufw, "r", encoding="utf-8") as f:
                        original_content = f.read()

                    content_modified = original_content

                    for existing_policy in ["ACCEPT", "DROP", "REJECT"]:
                        content_modified = content_modified.replace(
                            f"DEFAULT_{chain}_POLICY={existing_policy}",
                            f"DEFAULT_{chain}_POLICY={policy}",
                        )

                    with open(default_ufw, "w", encoding="utf-8") as f:
                        f.write(content_modified)

                    self.env.run_cmd(["status"], expected_rc=1, capture_output=True)

                    with open(default_ufw, "w", encoding="utf-8") as f:
                        f.write(original_content)


if __name__ == "__main__":
    unittest.main()
