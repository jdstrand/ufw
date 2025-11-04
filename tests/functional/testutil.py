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
import subprocess
import sys
import tempfile
from typing import List, Optional, Tuple


class UFWTestEnvironment:
    """
    Test environment for functional UFW tests.

    This class manages a complete UFW installation in a temporary directory,
    allowing tests to run commands and verify results in isolation.
    """

    def __init__(self) -> None:
        """Initialize test environment."""
        self.tmpdir: Optional[str] = None
        self.testpath: Optional[str] = None
        self.testtmp: Optional[str] = None
        self.teststate: Optional[str] = None
        self.testconfig: Optional[str] = None
        self.ufw_sbin: Optional[str] = None
        self.count: int = 0
        self.result_lines: List[str] = []

    def setup(self) -> None:
        """Set up the test environment by installing UFW to a temporary directory."""
        if self.tmpdir is not None:
            return

        self.tmpdir = tempfile.mkdtemp(prefix="ufw-functional-test-")
        self.testpath = os.path.join(self.tmpdir, "testarea")
        self.testtmp = os.path.join(self.testpath, "tmp")
        self.teststate = os.path.join(self.testpath, "lib", "ufw")
        self.testconfig = os.path.join(self.testpath, "etc", "ufw")

        os.makedirs(os.path.join(self.testpath, "usr", "sbin"), exist_ok=True)
        os.makedirs(os.path.join(self.testpath, "etc"), exist_ok=True)
        os.makedirs(self.testtmp, exist_ok=True)

        env = os.environ.copy()
        env["UFW_SKIP_CHECKS"] = "1"

        cwd = os.getcwd()
        proc = subprocess.run(
            [sys.executable, "./setup.py", "install", f"--home={self.testpath}"],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            shell=False,
        )

        if proc.returncode != 0:
            raise RuntimeError(f"Failed to install UFW for testing: {proc.stderr}")

        self.ufw_sbin = os.path.join(self.testpath, "usr", "sbin", "ufw")

        if not os.path.exists(self.ufw_sbin):
            raise RuntimeError(
                f"UFW binary not found at {self.ufw_sbin} after installation"
            )

    def setup_profiles(self, profiles_dir: str = "tests/defaults/profiles") -> None:
        """
        Copy application profiles to the test environment.

        Args:
            profiles_dir: Directory containing application profile files
        """
        if self.testconfig is None:
            raise RuntimeError("Test environment not set up")

        apps_dir = os.path.join(self.testconfig, "applications.d")
        os.makedirs(apps_dir, exist_ok=True)

        if os.path.exists(profiles_dir):
            for profile_file in os.listdir(profiles_dir):
                src = os.path.join(profiles_dir, profile_file)
                dst = os.path.join(apps_dir, profile_file)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)

    def setup_from_orig(self, orig_dir: str) -> None:
        """
        Copy configuration from an orig directory to the test environment.

        Args:
            orig_dir: Path to directory containing original configuration files
        """
        if self.testpath is None or self.testconfig is None:
            raise RuntimeError("Test environment not set up")

        dest_etc = os.path.join(self.testpath, "etc")

        if os.path.exists(orig_dir):
            for item in os.listdir(orig_dir):
                src_path = os.path.join(orig_dir, item)
                dst_path = os.path.join(dest_etc, item)

                if os.path.islink(src_path):
                    link_target = os.readlink(src_path)
                    if os.path.isabs(link_target):
                        shutil.copytree(link_target, dst_path, dirs_exist_ok=True)
                    else:
                        abs_target = os.path.join(
                            os.path.dirname(src_path), link_target
                        )
                        abs_target = os.path.normpath(abs_target)
                        shutil.copytree(abs_target, dst_path, dirs_exist_ok=True)
                elif os.path.isdir(src_path):
                    shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                else:
                    shutil.copy2(src_path, dst_path)

    def disable_ipv6(self) -> None:
        """Disable IPv6 in UFW configuration."""
        if self.testconfig is None:
            raise RuntimeError("Test environment not set up")

        default_ufw = os.path.join(self.testconfig, "..", "default", "ufw")
        if os.path.exists(default_ufw):
            with open(default_ufw, "r", encoding="utf-8") as f:
                content = f.read()

            content = content.replace("IPV6=yes", "IPV6=no")

            with open(default_ufw, "w", encoding="utf-8") as f:
                f.write(content)

    def run_cmd(
        self,
        args: List[str],
        expected_rc: int = 0,
        capture_output: bool = True,
    ) -> Tuple[int, str, str]:
        """
        Run a UFW command in the test environment.

        Args:
            args: Command arguments to pass to UFW
            expected_rc: Expected return code (0 or 1)
            capture_output: Whether to capture and record output

        Returns:
            Tuple of (return_code, stdout, stderr)

        Raises:
            AssertionError: If return code does not match expected
        """
        if self.ufw_sbin is None or self.testpath is None:
            raise RuntimeError("Test environment not set up")

        cmd = [self.ufw_sbin] + args

        env = os.environ.copy()
        env["PYTHONPATH"] = (
            f"{os.path.join(self.testpath, 'lib', 'python')}:"
            f"{env.get('PYTHONPATH', '')}"
        )

        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            shell=False,
        )

        if capture_output:
            self.result_lines.append(f"{self.count}: {' '.join(args)}")
            self.result_lines.append(proc.stdout.rstrip())
            self.result_lines.append("")
            self.result_lines.append("")
            self.count += 1

        if proc.returncode != expected_rc:
            raise AssertionError(
                f"Command {args} returned {proc.returncode}, " f"expected {expected_rc}"
            )

        return proc.returncode, proc.stdout, proc.stderr

    def get_result(self) -> str:
        """
        Get accumulated test results.

        Returns:
            Combined result output from all commands
        """
        return "\n".join(self.result_lines)

    def teardown(self) -> None:
        """Clean up the test environment."""
        if self.tmpdir is not None and os.path.exists(self.tmpdir):
            try:
                shutil.rmtree(self.tmpdir)
            except Exception as e:
                print(f"Warning: Failed to clean up {self.tmpdir}: {e}")
            finally:
                self.tmpdir = None
                self.testpath = None
                self.testtmp = None
                self.teststate = None
                self.testconfig = None
                self.ufw_sbin = None

    def reset(self) -> None:
        """Reset the result accumulator for a new test."""
        self.count = 0
        self.result_lines = []


def recursive_rm(dir_path: str, contents_only: bool = False) -> None:
    """
    Recursively remove directory.

    Args:
        dir_path: Path to directory to remove
        contents_only: If True, only remove contents, not the directory itself
    """
    if not os.path.exists(dir_path):
        return

    for name in os.listdir(dir_path):
        path = os.path.join(dir_path, name)
        if os.path.islink(path) or not os.path.isdir(path):
            os.unlink(path)
        else:
            recursive_rm(path, contents_only=False)

    if not contents_only:
        os.rmdir(dir_path)


def normalize_output(output: str) -> str:
    """
    Normalize output for comparison.

    This handles differences between Python versions and implementations.

    Args:
        output: Raw output string

    Returns:
        Normalized output string
    """
    lines = output.split("\n")
    normalized = []

    for line in lines:
        if line.startswith("usage:"):
            line = "Usage:" + line[6:]
        elif line.startswith("options:"):
            line = "Options:" + line[8:]
        normalized.append(line)

    return "\n".join(normalized)
