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
# git-ignored ./tmp/ufw -> src symlink) and ufw.common globals are repointed
# at the sandbox.
# Each command is driven in-process through the real CLI entry point,
# main_ufw(argv), which constructs a fresh UFWFrontend per call, so no
# per-command state leaks between calls.

from __future__ import print_function

import difflib
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
import warnings

# ufw must be imported from src/ (not the installed copy) so coverage measures
# the source. Ensure a ./tmp/ufw -> src symlink exists (git-ignored, not the repo
# root) and ./tmp is on sys.path before importing, so this works whether driven
# via runner.py or `python -m unittest`.
_repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_tmp = os.path.join(_repo, "tmp")
_ufwlink = os.path.join(_tmp, "ufw")
_linktarget = os.path.join("..", "src")
if not os.path.isdir(_tmp):
    os.makedirs(_tmp)
# Relative target so the link stays valid if the checkout moves; recreate it
# when dangling or pointing elsewhere (islink() is true for a dangling link,
# and following a stale one would import some other tree's src/).
if os.path.islink(_ufwlink) and os.readlink(_ufwlink) != _linktarget:
    os.unlink(_ufwlink)
if os.path.exists(_ufwlink) and not os.path.islink(_ufwlink):
    # A real file/dir in the link's place would silently shadow src/.
    raise RuntimeError("%s exists and is not a symlink; remove it" % _ufwlink)
if not os.path.islink(_ufwlink):
    os.symlink(_linktarget, _ufwlink)
if _tmp not in sys.path:
    sys.path.insert(0, _tmp)

import ufw.common  # noqa: E402
import ufw.frontend  # noqa: E402
import ufw.main  # noqa: E402
import ufw.util  # noqa: E402

REPO_ROOT = _repo
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


def _rules_delta(prev, new, plus, minus):
    """The lines added/removed in a rules file vs its previous state (no
    context), so a transcript records each command's *effect* rather than a full
    dump."""
    out = []
    for line in difflib.unified_diff(prev.splitlines(), new.splitlines(), n=0):
        if line.startswith("+") and not line.startswith("+++"):
            out.append(plus + line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            out.append(minus + line[1:])
    return out


_help_tail = None


def _command_help_tail():
    """The command-help block (from its 'Usage:' line on) that ufw prints on a
    syntax error, cached. Factored out of transcripts and pinned once by the
    installation/check_help test."""
    global _help_tail
    if _help_tail is None:
        full = ufw.frontend.get_command_help().splitlines()
        try:
            _help_tail = full[full.index("Usage: ufw COMMAND") :]
        except ValueError:
            _help_tail = []
    return _help_tail


def _factor_output(out, collapse_help=True):
    """Factor a command's captured output for the transcript.

    A dry-run prints the full iptables-restore input, ~90% of which is a constant
    frame -- the ``*filter``/``COMMIT`` wrapper, the chain declarations, and the
    ``### LOGGING ###`` / ``### RATE LIMITING ###`` blocks -- that depends only on
    IPV6/LOGLEVEL and is verified once by test_render.BoilerplateTests. Keeping it
    per command is what ballooned the transcripts to ~1.6 MB. Likewise every syntax
    error reprints the whole command-help text.

    So inside an iptables dump we keep only the command-specific ``### RULES ###``
    bodies (as ``R`` lines) and drop the frame; outside the dump we keep the
    message lines (``Rule added``, ``Rules updated``, status/error text) as ``O``
    lines, collapsing the constant command-help dump to a single ``<<command
    help>>`` marker. The collapse would be self-referential as a regression
    gate (the marker is computed from the same get_command_help() that
    produced the output), so installation/check_help passes
    ``collapse_help=False`` to pin the full help text byte-exact in its
    transcript; every other transcript's marker then stands on that pin. The
    harness-only ``WARN: Checks disabled`` line (emitted because do_checks is
    off; never printed by the real CLI) is dropped."""
    lines = out.splitlines()
    help_tail = _command_help_tail()
    kept = []
    i = 0
    in_dump = in_rules = in_skip = False
    while i < len(lines):
        line = lines[i]
        if not in_dump:
            if line == "*filter":
                in_dump = True
            elif line == "WARN: Checks disabled":
                pass
            elif (
                collapse_help
                and line == "Usage: ufw COMMAND"
                and help_tail
                and lines[i : i + len(help_tail)] == help_tail
            ):
                kept.append("O <<command help>>")
                i += len(help_tail)
                continue
            else:
                kept.append("O " + line)
            i += 1
            continue
        # inside an iptables dump (between *filter and COMMIT)
        if line == "COMMIT":
            in_dump = False
        elif line == "### RULES ###":
            in_rules = True
        elif line == "### END RULES ###":
            in_rules = False
        elif line in ("### LOGGING ###", "### RATE LIMITING ###"):
            in_skip = True
        elif line in ("### END LOGGING ###", "### END RATE LIMITING ###"):
            in_skip = False
        elif in_rules and not in_skip and line != "":
            kept.append("R " + line)
        # else: chain declarations, blank lines, and the skipped LOGGING / RATE
        # LIMITING blocks are the constant frame -- dropped.
        i += 1
    return kept


def _transcript_blocks(text):
    """Split a transcript into per-command blocks keyed by their '## N: cmd'
    header, so a mismatch can be localized to the exact command."""
    blocks = []
    cur = None
    for line in text.splitlines():
        if re.match(r"^## \d+: ", line):
            if cur is not None:
                blocks.append("\n".join(cur))
            cur = [line]
        elif cur is not None:
            cur.append(line)
    if cur is not None:
        blocks.append("\n".join(cur))
    return blocks


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
        with open(proc) as fh:
            proc_lines = fh.readlines()
        for line in proc_lines:
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
        with open(proc) as fh:
            proc_lines = fh.readlines()
        for line in proc_lines:
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
        with open(proc) as fh:
            proc_lines = fh.readlines()
        for line in proc_lines:
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


def run_setup(iptables_dir=FAKE_BIN):
    """'make install' into the sandbox and copy a pristine etc/ tree.

    ``iptables_dir`` is baked into the installed binary (IPTABLES_DIR=); it
    defaults to the deterministic fakes. The e2e suite passes the real iptables
    dir (real_iptables_dir()) so commands actually apply via the real backend."""
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
            "IPTABLES_DIR=%s" % iptables_dir,
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
    # On-disk generation checks (RuleCommands.assert_rule_count etc.) run here;
    # the e2e driver sets this False since it applies for real (state differs).
    verify_on_disk = True

    # -- lifecycle ---------------------------------------------------------

    def _restore_pristine_config(self):
        """Reset the sandbox config to the pristine post-install state and stage
        the shared application profiles, so each test starts from a fresh
        install. IPv6 is left disabled; tests enable it when needed."""
        etc = ufw.common.config_dir
        if os.path.exists(etc):
            recursive_rm(etc)
        shutil.copytree(_pristine_etc, etc)
        for f in glob.glob(os.path.join(DATA_DIR, "defaults", "profiles", "*")):
            if os.path.isfile(f):
                shutil.copy(f, self.appsd)
        self.set_default("IPV6", "no")

    def setUp(self):
        # Refuse root: runner.py already does, but `python -m unittest` skips
        # the runner, and in-process main_ufw() as root would take the REAL
        # /run/ufw.lock -- main_ufw() only picks the sandbox lockfile when
        # non-root or when TESTSTATE is in the environment (the subprocess
        # path exports it; the in-process path does not). The uid-sensitive
        # cases (the chmod 0o444 permission errors in bugs/misc) also need
        # non-root.
        if os.getuid() == 0:
            raise Error("tests/functional must not run as root")

        # Restore the pristine sandbox config so each test starts clean.
        self._restore_pristine_config()

        ufw.common.do_checks = False
        ufw.util.msg_output = None
        # main_ufw() installs its warnings.showwarning hook (render warnings.warn()
        # as ufw's "WARN: ..." line). The real ufw runs each command as its own
        # process, so a repeated warning is emitted every time; force "always" so
        # Python's per-location cache doesn't dedup those repeats across our single
        # in-process run.
        warnings.simplefilter("always")
        # Warm up the on-disk firewall structure (v4 and v6) so per-command rule
        # deltas attribute only the rule each command adds -- not the one-time
        # chain/logging scaffolding ufw writes on the first persisting command
        # (that scaffolding is constant and pinned by test_render.BoilerplateTests).
        self._reset_recording()
        self._warm_up_rules_files()
        self._reset_recording()

    def _reset_recording(self):
        """(Re)initialize the per-command recording state and re-baseline the
        rule-file deltas to the current on-disk state."""
        self._count = 0
        self._trace = []
        self._transcript = []
        self._prev_ur = _read(self.user_rules)
        self._prev_u6 = _read(self.user6_rules)

    def _warm_up_rules_files(self):
        """Initialize the user.rules/user6.rules chain structure via a throwaway
        add+delete (both families, regardless of the test's IPV6 setting), so the
        first recorded command's delta isn't polluted by that one-time scaffolding.
        The IPV6 default is restored afterwards."""
        saved_default = _read(self.default_ufw)
        try:
            self.enable_ipv6()
            self.ufw("allow", "22")
            self.ufw("delete", "allow", "22")
        finally:
            with open(self.default_ufw, "w") as f:
                f.write(saved_default)

    def tearDown(self):
        if os.environ.get("UFW_TEST_VERIFY_PARITY") and self.class_name:
            self._check_parity()
        self._check_transcript()

    def _subname(self):
        sub = self._testMethodName
        return sub[len("test_") :] if sub.startswith("test_") else sub

    def _check_parity(self):
        # Completeness oracle: assert the exact ufw command sequence this test
        # issued matches the old shell test's golden "N: <args>" headers.
        sub = self._subname()
        golden = os.path.join(REPO_ROOT, "tests", self.class_name, sub, "result")
        if not os.path.exists(golden):
            self.fail("no old golden to verify parity: %s" % golden)
        # Compare the ufw argument sequences, not the leading "N:" counter: some
        # old goldens have stale/inconsistent counters (regenerated piecemeal),
        # but the command args + order are the real parity signal.
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

    def _check_transcript(self):
        """Compare (or, with UFW_TEST_UPDATE, regenerate) the per-command
        output+state transcript. Comprehensive regression gate; failures are
        localized to the offending command."""
        if not self.class_name:
            return
        sub = self._subname()
        # No file extension; each subtest's transcript lives at
        # data/transcripts/<class>/<sub>.
        path = os.path.join(DATA_DIR, "transcripts", self.class_name, sub)
        text = "\n".join(self._transcript) + "\n"
        if os.environ.get("UFW_TEST_UPDATE"):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(text)
            return
        if not os.path.exists(path):
            # A class_name-bearing functional test is a golden-replay test: its
            # transcript is mandatory. Missing one is a hard error (regenerate with
            # UFW_TEST_UPDATE), not a silent skip.
            self.fail(
                "no transcript for %s/%s at %s\n"
                "  run with UFW_TEST_UPDATE=1 to create it."
                % (self.class_name, sub, path)
            )
        expected = _read(path)
        if expected == text:
            return
        exp, act = _transcript_blocks(expected), _transcript_blocks(text)
        msgs = []
        for i in range(max(len(exp), len(act))):
            e = exp[i] if i < len(exp) else ""
            a = act[i] if i < len(act) else ""
            if e == a:
                continue
            header = (a or e).splitlines()[0]
            d = "\n".join(
                difflib.unified_diff(
                    e.splitlines(), a.splitlines(), "expected", "actual", lineterm=""
                )
            )
            msgs.append("%s\n%s" % (header, d))
            if len(msgs) >= 8:
                break
        self.fail(
            "transcript mismatch for %s/%s (%d differing command(s)):\n\n%s"
            % (self.class_name, sub, len(msgs), "\n\n".join(msgs))
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

    def ufw(self, *args, http_or_www=False, capture=True, collapse_help=True):
        """Run one ufw command in-process and return a Result(rc, out).

        Combined stdout+stderr are captured into one buffer. A fresh
        UFWFrontend is constructed for the command (no state carries over).
        """
        args = [str(a) for a in args]

        # Record the command for the completeness oracle using the ORIGINAL args
        # (captured before any http-or-www rewrite, as "<count>: <args>").
        self._trace.append("%d: %s" % (self._count, " ".join(args)))
        cmd = " ".join(args)
        self._count += 1

        if http_or_www:
            args = self._maybe_www(args)

        # ufw.util.msg() writes stdout output to msg_output when it is set (and
        # its default 'output' arg still equals sys.stdout, so we must NOT
        # replace sys.stdout). error()/warn() write to sys.stderr, which we
        # point at the same buffer so both streams interleave in call order.
        # Drive the real CLI entry point in-process: main_ufw(argv) takes our args
        # and exits via sys.exit(), so read the rc off the SystemExit.
        buf = io.StringIO()
        old_msg_output = ufw.util.msg_output
        old_stderr = sys.stderr
        ufw.util.msg_output = buf
        sys.stderr = buf
        rc = 0
        try:
            ufw.main.main_ufw(["ufw"] + args)
        except SystemExit as e:
            rc = _norm_exit_code(e.code)
        except Exception:
            traceback.print_exc(file=buf)
            rc = 1
        finally:
            ufw.util.msg_output = old_msg_output
            sys.stderr = old_stderr

        out = buf.getvalue()
        self._record_command(cmd, rc, out, capture, collapse_help)
        return Result(rc, out)

    def _record_command(self, cmd, rc, out, capture=True, collapse_help=True):
        """Append one per-command transcript block: the command, its output, and
        the delta it made to user.rules/user6.rules.

        ``capture=False`` records the command + rc + on-disk delta but drops the
        captured output, for commands whose output is environment-specific (a
        Python traceback, absolute paths) and where only the exit code matters."""
        new_ur = _read(self.user_rules)
        new_u6 = _read(self.user6_rules)
        lines = ["## %d: %s (rc=%d)" % (len(self._transcript), cmd, rc)]
        if capture:
            lines += _factor_output(out, collapse_help)
        lines += _rules_delta(self._prev_ur, new_ur, "+ ", "- ")
        lines += _rules_delta(self._prev_u6, new_u6, "+6 ", "-6 ")
        self._transcript.append("\n".join(lines))
        self._prev_ur = new_ur
        self._prev_u6 = new_u6

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

    # -- rendering (depth layer) ------------------------------------------
    #
    # Every dry-run renders the full iptables-restore input, ~90% of which is
    # constant chain scaffolding (the ufw[6]-user-limit / -limit-accept chains,
    # logging blocks) that repeats identically on every command. That boilerplate
    # is verified once by the dedicated *boilerplate* tests; the command-specific
    # rendering -- the only interesting part -- is exactly the -A/-I lines that
    # target the per-rule user chains below. assert_render() factors the
    # boilerplate out and compares just that, so each rendering test reads as the
    # handful of lines the command is *supposed* to produce.

    USER_CHAINS = (
        "ufw-user-input",
        "ufw-user-output",
        "ufw-user-forward",
        "ufw6-user-input",
        "ufw6-user-output",
        "ufw6-user-forward",
    )

    def rendered_rules(self, *args):
        """The command-specific rendered iptables lines for ``ufw --dry-run
        <args>``: the -A/-I lines targeting the ufw[6]-user-* rule chains, with
        the constant scaffolding factored out. Order is significant."""
        out = self.ufw("--dry-run", *args).out
        lines = []
        for line in out.splitlines():
            m = re.match(r"-[AI] (\S+)", line)
            if m and m.group(1) in self.USER_CHAINS:
                lines.append(line)
        return lines

    def assert_render(self, args, expected):
        """Assert the boilerplate-factored render of ``ufw --dry-run <args>``
        equals ``expected`` (a list of iptables lines, order-significant).

        This is the hand-curated *oracle*: a human asserts, from intent, exactly
        what a command should render -- the independent check that keeps the
        generated transcript honest (it cannot bless a wrong value the oracle
        pins). ``args`` may be a string ('allow 22') or a list."""
        argv = args.split() if isinstance(args, str) else list(args)
        got = self.rendered_rules(*argv)
        self.assertEqual(
            expected,
            got,
            "render mismatch for 'ufw %s':\n  expected:\n%s\n  got:\n%s"
            % (
                " ".join(argv),
                "\n".join("    " + line for line in expected),
                "\n".join("    " + line for line in got),
            ),
        )

    def scaffolding(self, *args):
        """The constant chain scaffolding (everything assert_render factors out)
        for ``ufw --dry-run <args>``: the -A/-I lines that do NOT target a
        per-rule user chain. Verified once by the boilerplate tests."""
        out = self.ufw("--dry-run", *args).out
        lines = []
        for line in out.splitlines():
            m = re.match(r"-[AI] (\S+)", line)
            if m and m.group(1) not in self.USER_CHAINS:
                lines.append(line)
        return lines

    def chain_decls(self, *args):
        """The ``:chain - [0:0]`` declarations a dry-run emits. Part of the
        constant frame the transcript factors out, so it is pinned once by the
        boilerplate tests (a renamed/added/removed chain is a real change)."""
        out = self.ufw("--dry-run", *args).out
        return [line for line in out.splitlines() if line.startswith(":")]

    def logging_block(self, *args):
        """The rendered ``### LOGGING ###`` section's -A/-I lines for a dry-run --
        the chain-setup LOG rules, which are parameterized by LOGLEVEL (and
        emitted for each enabled family). Pinned per level by the logging tests."""
        out = self.ufw("--dry-run", *args).out
        lines = []
        grab = False
        for line in out.splitlines():
            if line == "### LOGGING ###":
                grab = True
            elif line == "### END LOGGING ###":
                grab = False
            elif grab and line.startswith(("-A ", "-I ")):
                lines.append(line)
        return lines

    def rule_block(self, *args):
        """Every -A/-I line in the ``### RULES ###`` section of a dry-run, on any
        chain -- unlike rendered_rules(), which keeps only the user
        input/output/forward chains. Needed to pin per-rule logging, whose
        log / log-all difference lives in the ufw[6]-user-logging-* chain."""
        out = self.ufw("--dry-run", *args).out
        lines = []
        grab = False
        for line in out.splitlines():
            if line == "### RULES ###":
                grab = True
            elif line == "### END RULES ###":
                grab = False
            elif grab and line.startswith(("-A ", "-I ")):
                lines.append(line)
        return lines

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


# -- e2e (real iptables backend) harness ----------------------------------


def require_e2e_env():
    """Guard for the e2e suite: it modifies the real firewall, so demand an
    explicit opt-in (UFW_E2E=1) and root. Run only in a disposable VM."""
    if os.environ.get("UFW_E2E") != "1":
        sys.stderr.write(
            "ERROR: e2e tests require UFW_E2E=1 (they modify the real firewall; "
            "run in a disposable VM)\n"
        )
        sys.exit(1)
    if os.getuid() != 0:
        sys.stderr.write("ERROR: e2e tests must run as root\n")
        sys.exit(1)


def real_iptables_dir():
    """Locate the real iptables-restore directory (for the e2e suite)."""
    p = shutil.which("iptables-restore")
    if not p:
        raise Error("e2e: no real iptables-restore found on PATH")
    return os.path.dirname(p)


class E2ETestCase(unittest.TestCase):
    """Base for end-to-end tests: drive the installed ufw binary as a subprocess
    against the REAL iptables backend (root, in a disposable VM).

    Unlike FunctionalTestCase (in-process, fake iptables) this actually applies
    rules to the kernel, so it verifies that iptables/ip6tables-restore accept
    what ufw generates. It is agnostic to iptables-legacy vs iptables-nft -- it
    uses whatever iptables/iptables-restore is on PATH. ``--dry-run`` is stripped
    from each command so it applies, and the kernel is returned to a clean state
    with ``ufw-init flush-all`` around every test. Run only via tests/e2e/runner.py."""

    # Generation-state checks (RuleCommands.assert_rule_count etc.) are no-ops
    # here: e2e applies for real, so persisted state differs; exit codes are
    # the apply-acceptance check and the functest transcript covers generation.
    verify_on_disk = False

    # -- sandbox paths (mirror SubprocessTestCase) -------------------------
    @property
    def sandbox(self):
        return os.path.abspath(os.path.join(topdir, "ufw"))

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
    def default_ufw(self):
        return os.path.join(self.etc, "default", "ufw")

    @property
    def ufw_conf(self):
        return os.path.join(self.etc, "ufw", "ufw.conf")

    @property
    def user_rules(self):
        return os.path.join(self.etc, "ufw", "user.rules")

    @property
    def user6_rules(self):
        return os.path.join(self.etc, "ufw", "user6.rules")

    # -- lifecycle ---------------------------------------------------------
    def setUp(self):
        # Deliberate guard, not just runner.py's: a stray root invocation via
        # `sudo python -m unittest tests.e2e...` must refuse before anything
        # touches the real firewall.
        require_e2e_env()

        # Fresh on-disk config for each test.
        if os.path.exists(self.etc):
            recursive_rm(self.etc)
        shutil.copytree(_pristine_etc, self.etc)
        for f in glob.glob(os.path.join(DATA_DIR, "defaults", "profiles", "*")):
            if os.path.isfile(f):
                shutil.copy(f, self.appsd)
        self.set_default("IPV6", "no")
        # Start from a clean kernel (drop any leftover ufw chains).
        self._flush_all()

    def tearDown(self):
        # Return the kernel to a clean state regardless of test outcome.
        self._flush_all()

    # -- helpers -----------------------------------------------------------
    def _env(self):
        env = os.environ.copy()
        env["LANG"] = "C"
        env["TESTSTATE"] = os.path.join(self.sandbox, "lib", "ufw")
        pp = os.path.join(self.sandbox, "usr", "lib", "python3", "dist-packages")
        if env.get("PYTHONPATH"):
            pp += os.pathsep + env["PYTHONPATH"]
        env["PYTHONPATH"] = pp
        return env

    def ufw_init(self, *args):
        """Run the installed ufw-init script (start/stop/flush-all/force-reload/
        reset) as a subprocess -- the boot/runtime path, distinct from the ufw
        CLI. Returns Result(rc, combined out)."""
        init = os.path.join(self.sandbox, "lib", "ufw", "ufw-init")
        p = subprocess.run(
            [init] + [str(a) for a in args],
            cwd=REPO_ROOT,
            env=self._env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        return Result(p.returncode, p.stdout)

    def _flush_all(self):
        """Remove all ufw chains/hooks from the real kernel (ufw-init flush-all;
        plain disable leaves the chain skeleton behind), then assert it worked --
        no ufw chains may remain. Used to start and end every test clean."""
        self.ufw_init("flush-all")
        self.assert_no_ufw_chains()

    def _ufw_chain_lines(self, cmd):
        p = subprocess.run(
            [cmd, "-S"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        return [ln for ln in p.stdout.splitlines() if "ufw" in ln]

    def iptables_rules(self, v6=False):
        """The applied policy and rule lines from iptables-save -- the ':CHAIN
        POLICY' headers with their churning packet counters stripped, plus
        every '-A' rule line -- for comparing real kernel state across the CLI
        vs the init script, or before vs after a reapply. Policies matter:
        enable sets the DEFAULT_*_POLICY ones and disable/stop reset them, so
        an equivalence or idempotency check that skipped them would miss a
        path that loses the INPUT DROP. In a disposable VM these lines are
        entirely ufw's."""
        cmd = "ip6tables-save" if v6 else "iptables-save"
        p = subprocess.run(
            [cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        if p.returncode != 0:
            # Fail loudly: a silently-empty snapshot would make the
            # before/after equality assertions pass vacuously ([] == []).
            raise Error("%s failed (rc=%d):\n%s" % (cmd, p.returncode, p.stdout))
        lines = []
        for ln in p.stdout.splitlines():
            if ln.startswith(":"):
                # ':INPUT DROP [12:3456]' -> ':INPUT DROP'
                lines.append(" ".join(ln.split()[:2]))
            elif ln.startswith("-"):
                lines.append(ln)
        return lines

    def builtin_jumps(self, builtin, v6=False):
        """The chains a builtin (INPUT/OUTPUT/FORWARD) jumps or gotos to, from
        ``iptables -S <builtin>`` -- i.e. ufw's per-builtin sub-chains."""
        cmd = "ip6tables" if v6 else "iptables"
        p = subprocess.run(
            [cmd, "-S", builtin],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        targets = []
        for ln in p.stdout.splitlines():
            parts = ln.split()
            for flag in ("-j", "-g"):
                if flag in parts:
                    i = parts.index(flag)
                    if i + 1 < len(parts):
                        targets.append(parts[i + 1])
        return targets

    def chain_references(self, chain, v6=False):
        """Reference count for a chain (how many rules jump to it), parsed from
        the ``Chain <name> (N references)`` header of ``iptables -L``. Returns
        None if the chain does not exist."""
        cmd = "ip6tables" if v6 else "iptables"
        p = subprocess.run(
            [cmd, "-L", chain, "-n"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        m = re.search(r"\((\d+) references\)", p.stdout)
        return int(m.group(1)) if m else None

    def kernel_policy(self, builtin, v6=False):
        """The builtin chain's default policy (ACCEPT/DROP) from the ``-P``
        line of ``iptables -S <builtin>``. Returns None if not found."""
        cmd = "ip6tables" if v6 else "iptables"
        p = subprocess.run(
            [cmd, "-S", builtin],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        for ln in p.stdout.splitlines():
            parts = ln.split()
            if len(parts) >= 3 and parts[0] == "-P" and parts[1] == builtin:
                return parts[2]
        return None

    def raw_iptables(self, *args, v6=False):
        """Run a raw iptables/ip6tables command (to inspect or seed the builtin
        chains directly, e.g. to test MANAGE_BUILTINS). Returns Result(rc, out)."""
        cmd = "ip6tables" if v6 else "iptables"
        p = subprocess.run(
            [cmd] + [str(a) for a in args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        return Result(p.returncode, p.stdout)

    def ufw(self, *args):
        """Run one ufw command as a subprocess against the real iptables backend.

        ``--dry-run`` is stripped so the command actually applies (the whole
        point of e2e). Returns Result(rc, combined out)."""
        argv = [str(a) for a in args if str(a) != "--dry-run"]
        p = subprocess.run(
            [sys.executable, self.ufw_bin] + argv,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            env=self._env(),
        )
        return Result(p.returncode, p.stdout)

    # -- assertions --------------------------------------------------------
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

    def assert_init_ok(self, *args):
        """Run an ufw-init subcommand and assert it succeeded (rc 0)."""
        r = self.ufw_init(*args)
        self.assertEqual(
            r.rc,
            0,
            "expected rc 0 for ufw-init %r, got %d:\n%s" % (list(args), r.rc, r.out),
        )
        return r.out

    def assert_no_ufw_chains(self):
        """Assert the real kernel has no ufw chains (clean slate)."""
        for cmd, fam in (("iptables", "v4"), ("ip6tables", "v6")):
            lines = self._ufw_chain_lines(cmd)
            self.assertEqual(
                lines,
                [],
                "expected no ufw %s chains, found:\n%s" % (fam, "\n".join(lines)),
            )

    def assert_ufw_chains_present(self, v6=True):
        """Assert ufw's chains were applied to the real kernel: v4 always, v6
        only when IPv6 is enabled (ufw skips ip6tables when IPV6=no)."""
        families = [("iptables", "v4")]
        if v6:
            families.append(("ip6tables", "v6"))
        for cmd, fam in families:
            self.assertTrue(
                self._ufw_chain_lines(cmd),
                "expected ufw %s chains, found none" % fam,
            )

    def read(self, path):
        return _read(path)

    def set_default(self, key, value, conf=False):
        _sed_default(self.ufw_conf if conf else self.default_ufw, key, value)

    def enable_ipv6(self):
        self.set_default("IPV6", "yes")


def run_e2e(*classes):
    """Install with the REAL iptables backend and run the given e2e TestCase
    classes. Refuses to run without UFW_E2E=1 + root (it modifies the firewall)."""
    require_e2e_env()
    run_setup(iptables_dir=real_iptables_dir())

    suite = unittest.TestSuite()
    for cls in classes:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(cls))
    result = unittest.TextTestRunner(sys.stdout, verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise TestFailed("e2e tests failed")
