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
# In-process functional test harness for ufw. Mirrors tests/unit/support.py:
# 'make install' lays down a sandbox, ufw is imported from src/ (via the
# ./ufw -> ./src symlink) and ufw.common globals are repointed at the sandbox.
# Each command is driven in-process by replicating main_ufw()'s dispatch with a
# freshly constructed UFWFrontend, so no per-command state leaks between calls.

from __future__ import print_function

import errno
import glob
import io
import os
import re
import shutil
import subprocess
import sys
import traceback
import unittest

# ufw must be imported from src/ (not the installed copy) so coverage measures
# the source. Ensure the ./ufw -> ./src symlink exists before importing, so that
# this works whether driven via runner.py or `python -m unittest`.
if not os.path.islink("./ufw") and not os.path.exists("./ufw"):
    os.symlink("./src", "./ufw")

import ufw.common  # noqa: E402
import ufw.frontend  # noqa: E402
import ufw.util  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_DIR = os.path.join(REPO_ROOT, "tests", "functional", "data")

# Self-contained fake iptables binaries: report a fixed modern version and
# succeed otherwise, so the suite is deterministic and needs no real iptables.
# Used both in-process (ufw.common.iptables_dir) and baked into the installed
# binary (make install IPTABLES_DIR=) for the subprocess smoke tests.
FAKE_BIN = os.path.join(REPO_ROOT, "tests", "functional", "fake-binaries")

topdir = "./tests/functional/tmp"

# Set by run_setup() to the pristine post-install copy of the sandbox's etc/
# tree, restored at the start of every test so each test starts clean.
_pristine_etc = None


class Error(Exception):
    """Error"""


class TestFailed(Error):
    """Test failed"""


class Result:
    """Result of a single ufw invocation."""

    def __init__(self, rc, out):
        self.rc = rc
        self.out = out


def recursive_rm(dir_path, contents_only=False):
    """Recursively remove a directory (mirrors tests/unit/support.py)."""
    for name in os.listdir(dir_path):
        path = os.path.join(dir_path, name)
        if os.path.islink(path) or not os.path.isdir(path):
            os.unlink(path)
        else:
            recursive_rm(path)
    if contents_only is False:
        os.rmdir(dir_path)


def _read(path):
    with open(path) as f:
        return f.read()


def _sed_default(path, key, value):
    """Set KEY=value in a ufw KEY=value config file (like the old sed calls)."""
    lines = []
    found = False
    with open(path) as f:
        for line in f:
            if line.startswith("%s=" % key):
                lines.append("%s=%s\n" % (key, value))
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append("%s=%s\n" % (key, value))
    with open(path, "w") as f:
        f.writelines(lines)


# --- reports mocks -------------------------------------------------------
# The reports tests need deterministic netstat output, /proc files and
# eth0/eth1 addresses, so patch the three ufw.util helpers that read them
# with these fixture-backed equivalents (the fixtures live in DATA_DIR).


def reports_netstat_output(v6):
    _ = v6  # the fixture contains both v4 and v6 lines
    return _read(os.path.join(DATA_DIR, "netstat.enlp"))


def reports_get_ip_from_if(ifname, v6=False):
    if v6:
        proc = os.path.join(DATA_DIR, "proc_net_if_inet6")
        addr = ""
        for line in open(proc).readlines():
            tmp = line.split()
            if ifname == tmp[5]:
                addr = ":".join([tmp[0][i : i + 4] for i in range(0, len(tmp[0]), 4)])
                if tmp[2].lower() != "80":
                    addr = "%s/%s" % (addr, int(tmp[2].lower(), 16))
        if addr == "":
            raise IOError(errno.ENODEV, "No such device")
    elif ifname == "eth0":
        addr = "10.0.2.9"
    elif ifname == "eth1":
        addr = "10.0.2.101"
    else:
        raise IOError
    return ufw.util.normalize_address(addr, v6)[0]


def reports_get_if_from_ip(addr):
    v6 = False
    proc = os.path.join(DATA_DIR, "proc_net_dev")
    if ufw.util.valid_address6(addr):
        v6 = True
        proc = os.path.join(DATA_DIR, "proc_net_if_inet6")
    elif not ufw.util.valid_address4(addr):
        raise IOError(errno.ENODEV, "No such device")

    matched = ""
    if v6:
        for line in open(proc).readlines():
            tmp = line.split()
            ifname = tmp[5].strip()
            tmp_addr = ":".join([tmp[0][i : i + 4] for i in range(0, len(tmp[0]), 4)])
            if tmp[2].lower() != "80":
                tmp_addr = "%s/%s" % (tmp_addr, int(tmp[2].lower(), 16))
            if addr == tmp_addr or (
                "/" in tmp_addr and ufw.util.in_network(addr, tmp_addr, True)
            ):
                matched = ifname
                break
    else:
        for line in open(proc).readlines():
            if ":" not in line:
                continue
            ifname = line.split(":")[0].strip()
            try:
                ip = reports_get_ip_from_if(ifname, False)
            except IOError:
                continue
            if ip == addr:
                matched = ifname
                break
    return matched


def init_gettext():
    """Set up gettext for ufw (stolen from src/ufw and tests/unit/support.py)."""
    import gettext

    gettext.install("ufw")
    gettext.bindtextdomain("ufw", os.path.join("./locales/mo"))
    gettext.textdomain("ufw")
    return gettext.gettext


def initvars():
    """Repoint ufw.common globals at the sandbox install (mirrors unit harness)."""
    global tr
    tr = init_gettext()

    real_top = os.path.realpath(topdir)
    ufw.common.iptables_dir = FAKE_BIN
    ufw.common.config_dir = os.path.join(real_top, "ufw/etc")
    ufw.common.state_dir = os.path.join(real_top, "ufw/lib/ufw")
    ufw.common.share_dir = os.path.join(real_top, "ufw/usr/share/ufw")
    ufw.common.trans_dir = ufw.common.share_dir
    ufw.common.prefix_dir = os.path.join(real_top, "ufw/usr")
    # Allow running as a non-root (or root) user without the install checks.
    ufw.common.do_checks = False


def run_setup():
    """'make install' into the sandbox and snapshot a pristine etc/ tree."""
    global _pristine_etc

    install_dir = os.path.join(topdir, "ufw")
    if os.path.exists(topdir):
        recursive_rm(topdir)
    os.makedirs(topdir)

    abs_install_dir = os.path.abspath(install_dir)
    env = os.environ.copy()
    env["UFW_SKIP_CHECKS"] = "1"

    sp = subprocess.run(
        [
            "make",
            "install",
            "DESTDIR=",
            "PREFIX=%s/usr" % abs_install_dir,
            "SYSCONFDIR=%s/etc" % abs_install_dir,
            "LIBDIR=%s/lib" % abs_install_dir,
            "IPTABLES_DIR=%s" % FAKE_BIN,
        ],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=env,
    )
    if sp.returncode != 0:
        raise Error("make install failed:\n%s\n%s" % (sp.stdout, sp.stderr))

    _pristine_etc = os.path.join(abs_install_dir, "etc.pristine")
    if os.path.exists(_pristine_etc):
        recursive_rm(_pristine_etc)
    shutil.copytree(os.path.join(abs_install_dir, "etc"), _pristine_etc)

    return install_dir


def run_unittest(*classes):
    """Run the given TestCase classes (mirrors tests/unit/support.py)."""
    run_setup()
    initvars()

    suite = unittest.TestSuite()
    for cls in classes:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(sys.stdout, verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        if len(result.errors) == 1 and not result.failures:
            err = result.errors[0][1]
        elif len(result.failures) == 1 and not result.errors:
            err = result.failures[0][1]
        else:
            err = "multiple errors occurred"
        raise TestFailed(err)

    if os.path.exists(topdir):
        recursive_rm(topdir)


def _norm_exit_code(code):
    """Normalize a SystemExit code to an int return code like a shell would."""
    if isinstance(code, int):
        return code
    return 0 if code is None else 1


class FunctionalTestCase(unittest.TestCase):
    """Base class for in-process functional tests.

    Subclasses set ``class_name`` (e.g. "good") which selects the matching
    tests/<class_name>/<name> data when needed. Each test method replays a
    sequence of ufw commands via self.ufw()/assert_ok()/assert_fail() and makes
    targeted assertions on output and on-disk rule files.
    """

    class_name = None
    backend_name = os.environ.get("UFW_BACKEND", "iptables")

    # -- lifecycle ---------------------------------------------------------

    def setUp(self):
        # Restore the pristine sandbox config so each test starts clean.
        etc = ufw.common.config_dir
        if os.path.exists(etc):
            recursive_rm(etc)
        shutil.copytree(_pristine_etc, etc)

        # Stage the shared application profiles into applications.d, mirroring
        # the old testlib.sh (cp tests/defaults/profiles/* .../applications.d).
        for f in glob.glob(os.path.join(DATA_DIR, "defaults", "profiles", "*")):
            if os.path.isfile(f):
                shutil.copy(f, self.appsd)

        # Tests assume IPv6 is disabled unless they enable it (run_tests.sh).
        self.set_default("IPV6", "no")

        ufw.common.do_checks = False
        ufw.util.msg_output = None
        self._count = 0
        self._trace = []
        self._ui = None

    def tearDown(self):
        # Opt-in completeness oracle: assert the exact ufw command sequence this
        # test issued matches the old shell test's golden "N: <args>" headers, so
        # we have parity in *which* commands are tested (and their order).
        if os.environ.get("UFW_TEST_VERIFY_PARITY") and self.class_name:
            sub = self._testMethodName
            if sub.startswith("test_"):
                sub = sub[len("test_") :]
            golden = os.path.join(REPO_ROOT, "tests", self.class_name, sub, "result")
            if not os.path.exists(golden):
                self.fail("no old golden to verify parity: %s" % golden)
            # Compare the ufw argument sequences, not the leading "N:" counter:
            # some old goldens have stale/inconsistent counters (they were
            # regenerated piecemeal), but the command args + order are the real
            # parity signal.
            expected = [
                re.sub(r"^\d+: ", "", line.rstrip("\n"))
                for line in _read(golden).splitlines()
                if re.match(r"^\d+: ", line)
            ]
            got = [re.sub(r"^\d+: ", "", line) for line in self._trace]
            self.assertEqual(
                expected,
                got,
                "command-sequence parity mismatch for %s/%s" % (self.class_name, sub),
            )

    # -- sandbox paths -----------------------------------------------------

    @property
    def etc(self):
        return ufw.common.config_dir

    @property
    def appsd(self):
        return os.path.join(self.etc, "ufw", "applications.d")

    @property
    def user_rules(self):
        return os.path.join(self.etc, "ufw", "user.rules")

    @property
    def user6_rules(self):
        return os.path.join(self.etc, "ufw", "user6.rules")

    @property
    def ufw_conf(self):
        return os.path.join(self.etc, "ufw", "ufw.conf")

    @property
    def default_ufw(self):
        return os.path.join(self.etc, "default", "ufw")

    # -- invocation --------------------------------------------------------

    def ufw(self, *args, http_or_www=False):
        """Run one ufw command in-process and return a Result(rc, out).

        Combined stdout+stderr are captured into one buffer. A fresh
        UFWFrontend is constructed for the command (no state carries over).
        """
        args = [str(a) for a in args]

        # Record the command for the completeness oracle using the ORIGINAL args
        # (captured before any http-or-www rewrite, as "<count>: <args>").
        self._trace.append("%d: %s" % (self._count, " ".join(args)))
        self._count += 1

        if http_or_www:
            args = self._maybe_www(args)

        # ufw.util.msg() writes stdout output to msg_output when it is set (and
        # its default 'output' arg still equals sys.stdout, so we must NOT
        # replace sys.stdout). error()/warn() write to sys.stderr, which we
        # point at the same buffer so both streams interleave in call order.
        buf = io.StringIO()
        self._ui = None
        old_msg_output = ufw.util.msg_output
        old_stderr = sys.stderr
        ufw.util.msg_output = buf
        sys.stderr = buf
        rc = 0
        try:
            rc = self._dispatch(["ufw"] + args)
        except SystemExit as e:
            rc = _norm_exit_code(e.code)
        except ufw.common.UFWError as e:
            ufw.util.error(e.value, do_exit=False)
            rc = 1
        except Exception:
            traceback.print_exc(file=buf)
            rc = 1
        finally:
            ufw.util.msg_output = old_msg_output
            sys.stderr = old_stderr
        return Result(rc, buf.getvalue())

    def _dispatch(self, argv):
        """Replicate main_ufw()'s dispatch (src/main.py) for one command."""
        app_action = False
        idx = 1
        if len(argv) > 1 and argv[1].lower() == "--dry-run":
            idx = 2
        if len(argv) > idx and argv[idx].lower() == "app":
            app_action = True

        try:
            pr = ufw.frontend.parse_command(list(argv))
        except ValueError:
            ufw.util.msg(ufw.frontend.get_command_help())
            return 1

        if pr.action in ("help", "--help", "-h"):
            ufw.util.msg(ufw.frontend.get_command_help())
            return 0
        if pr.action in ("version", "--version"):
            # Imported from src/, so the real #VERSION# is not substituted; the
            # in-process suite never asserts the version string.
            ufw.util.msg("%s (in-process)" % ufw.common.programName)
            return 0

        self._ui = ufw.frontend.UFWFrontend(pr.dryrun, backend_type=self.backend_name)

        if app_action and "type" in pr.data and pr.data["type"] == "app":
            res = self._ui.do_application_action(pr.action, pr.data["name"])
        elif (
            pr.action == "enable" and not pr.force and not self._ui.continue_under_ssh()
        ):
            res = "Aborted"
        elif "rule" in pr.data:
            res = self._ui.do_action(
                pr.action, pr.data["rule"], pr.data["iptype"], pr.force
            )
        else:
            res = self._ui.do_action(pr.action, "", "", pr.force)

        if res != "":
            ufw.util.msg(res)
        return 0

    # -- assertion helpers -------------------------------------------------

    def assert_ok(self, *args, **kwargs):
        r = self.ufw(*args, **kwargs)
        self.assertEqual(
            r.rc, 0, "expected rc 0 for %r, got %d:\n%s" % (list(args), r.rc, r.out)
        )
        return r.out

    def assert_fail(self, *args, **kwargs):
        r = self.ufw(*args, **kwargs)
        self.assertEqual(
            r.rc, 1, "expected rc 1 for %r, got %d:\n%s" % (list(args), r.rc, r.out)
        )
        return r.out

    def assert_rc(self, rc, *args, **kwargs):
        r = self.ufw(*args, **kwargs)
        self.assertEqual(
            r.rc,
            rc,
            "expected rc %d for %r, got %d:\n%s" % (rc, list(args), r.rc, r.out),
        )
        return r.out

    # -- file / config helpers --------------------------------------------

    def read(self, path):
        return _read(path)

    def set_default(self, key, value, conf=False):
        """Edit etc/default/ufw (or etc/ufw/ufw.conf) like the old sed calls."""
        _sed_default(self.ufw_conf if conf else self.default_ufw, key, value)

    def enable_ipv6(self):
        self.set_default("IPV6", "yes")

    def add_profile(self, name, body):
        """Write an application profile into applications.d."""
        with open(os.path.join(self.appsd, name), "w") as f:
            f.write(body)

    def stage_bad_profiles(self):
        """Overlay the malformed profiles (used by bad/apps)."""
        for f in glob.glob(os.path.join(DATA_DIR, "defaults", "profiles.bad", "*")):
            if os.path.isfile(f):
                shutil.copy(f, self.appsd)

    def app_profile_path(self, name):
        return os.path.join(self.appsd, name)

    def remove(self, path):
        if os.path.exists(path):
            os.remove(path)

    def chmod(self, path, mode):
        os.chmod(path, mode)

    def copy_file(self, src, dst):
        shutil.copy(src, dst)

    def makedirs(self, path):
        os.makedirs(path, exist_ok=True)

    def touch(self, path):
        open(path, "a").close()

    def write_file(self, path, content):
        with open(path, "w") as f:
            f.write(content)

    def tuple_count(self, path):
        """Number of user rules in a rules file (one '### tuple ###' each)."""
        return _read(path).count("### tuple ###")

    def _maybe_www(self, args):
        """Rewrite a trailing 'http' argument to 'www' when /etc/services lists
        'http' as 80/udp, so the expected output matches on such systems."""
        if not args or args[-1] != "http":
            return args
        try:
            with open("/etc/services") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "http" and parts[1] == "80/udp":
                        return args[:-1] + ["www"]
        except IOError:
            pass
        return args


class SubprocessTestCase(unittest.TestCase):
    """Standalone base for the subprocess smoke tests.

    Independent of FunctionalTestCase: it drives the *installed* usr/sbin/ufw
    binary as a real subprocess to validate the real CLI entry point and
    packaging end-to-end. The only things shared with the in-process suite are
    the sandbox install (run_setup) and the on-disk fixtures -- no test-scenario
    code is shared.
    """

    def setUp(self):
        self.sandbox = os.path.abspath(os.path.join(topdir, "ufw"))
        if os.path.exists(self.etc):
            recursive_rm(self.etc)
        shutil.copytree(_pristine_etc, self.etc)
        for f in glob.glob(os.path.join(DATA_DIR, "defaults", "profiles", "*")):
            if os.path.isfile(f):
                shutil.copy(f, self.appsd)
        self.set_default("IPV6", "no")

    @property
    def ufw_bin(self):
        return os.path.join(self.sandbox, "usr", "sbin", "ufw")

    @property
    def etc(self):
        return os.path.join(self.sandbox, "etc")

    @property
    def appsd(self):
        return os.path.join(self.etc, "ufw", "applications.d")

    @property
    def user_rules(self):
        return os.path.join(self.etc, "ufw", "user.rules")

    @property
    def user6_rules(self):
        return os.path.join(self.etc, "ufw", "user6.rules")

    @property
    def ufw_conf(self):
        return os.path.join(self.etc, "ufw", "ufw.conf")

    @property
    def default_ufw(self):
        return os.path.join(self.etc, "default", "ufw")

    def ufw(self, *args):
        """Run one ufw command as a subprocess; return Result(rc, combined out)."""
        env = os.environ.copy()
        env["LANG"] = "C"
        env["TESTSTATE"] = os.path.join(self.sandbox, "lib", "ufw")
        pp = os.path.join(self.sandbox, "usr", "lib", "python3", "dist-packages")
        if env.get("PYTHONPATH"):
            pp += os.pathsep + env["PYTHONPATH"]
        env["PYTHONPATH"] = pp
        p = subprocess.run(
            [sys.executable, self.ufw_bin] + [str(a) for a in args],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            env=env,
        )
        return Result(p.returncode, p.stdout)

    def assert_ok(self, *args):
        r = self.ufw(*args)
        self.assertEqual(
            r.rc, 0, "expected rc 0 for %r, got %d:\n%s" % (list(args), r.rc, r.out)
        )
        return r.out

    def assert_fail(self, *args):
        r = self.ufw(*args)
        self.assertEqual(
            r.rc, 1, "expected rc 1 for %r, got %d:\n%s" % (list(args), r.rc, r.out)
        )
        return r.out

    def read(self, path):
        return _read(path)

    def set_default(self, key, value, conf=False):
        _sed_default(self.ufw_conf if conf else self.default_ufw, key, value)

    def enable_ipv6(self):
        self.set_default("IPV6", "yes")
