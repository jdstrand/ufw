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
# Concurrency and crash safety of the rules-file update, driving ufw the way
# fail2ban does (sequential insert/delete churn, concurrent invocations,
# SIGKILL mid-run):
#  - a concurrent reader never observes a torn (empty/partial) rules file
#  - SIGKILL at any point leaves a complete old or complete new file
#  - concurrent writers lose no rules, on disk or in the kernel

import subprocess
import sys
import threading
import time

import tests.functional.support
from tests.functional.support import E2ETestCase, REPO_ROOT

# the stock fail2ban banaction's comment (exercises hex comments)
F2B_COMMENT = "by Fail2Ban after 2 attempts against sshd"


class ConcurrencyE2E(E2ETestCase):
    def _spawn_ufw(self, *args):
        """Start one ufw command as a subprocess WITHOUT waiting for it."""
        return subprocess.Popen(
            [sys.executable, self.ufw_bin] + [str(a) for a in args],
            cwd=REPO_ROOT,
            env=self._env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )

    def test_churn_never_exposes_torn_rules_file(self):
        """A reader polling user.rules during fail2ban-style churn must only
        ever see a complete file (starts '*filter', ends 'COMMIT\\n')."""
        self.assert_ok("--force", "enable")
        self.assert_ok("allow", "80", "comment", "nginx")

        stop = threading.Event()
        sizes = set()
        torn = []

        # poll as fast as possible: the point is to catch a torn state
        def poll():
            while not stop.is_set():
                try:
                    with open(self.user_rules, "rb") as f:
                        head = f.read(8)
                        f.seek(0, 2)
                        size = f.tell()
                        f.seek(max(0, size - 8))
                        tail = f.read(8)
                except FileNotFoundError:
                    if len(torn) < 20:
                        torn.append("file missing")
                    continue
                sizes.add(size)
                if (
                    size == 0
                    or not head.startswith(b"*filter")
                    or not tail.endswith(b"COMMIT\n")
                ):
                    if len(torn) < 20:
                        torn.append("size=%d head=%r tail=%r" % (size, head, tail))

        reader = threading.Thread(target=poll)
        reader.start()
        try:
            # the actionban/actionunban cycle, one rule at a time
            for i in range(6):
                ip = "10.99.0.%d" % (i + 1)
                self.assert_ok(
                    "insert",
                    "1",
                    "reject",
                    "from",
                    ip,
                    "to",
                    "any",
                    "comment",
                    F2B_COMMENT,
                )
                self.assert_ok("delete", "reject", "from", ip, "to", "any")
        finally:
            stop.set()
            reader.join()

        self.assertEqual(
            torn, [], "reader observed torn user.rules states:\n%s" % "\n".join(torn)
        )
        # the reader must have actually raced the writes: the insert/delete
        # churn changes the file's size, and the reader saw that happen
        # (poll throughput varies with the scheduler, so don't assert on it)
        self.assertGreater(len(sizes), 1)

    def test_sigkill_mid_update_leaves_complete_file(self):
        """SIGKILL swept across an insert's lifetime must leave a complete
        old or complete new user.rules."""
        self.assert_ok("--force", "enable")
        self.assert_ok("allow", "80", "comment", "nginx")
        for i in range(1, 4):
            self.assert_ok(
                "insert",
                "1",
                "reject",
                "from",
                "10.98.0.%d" % i,
                "to",
                "any",
                "comment",
                F2B_COMMENT,
            )

        for i, delay in enumerate([0.05 * (n + 1) for n in range(8)]):
            p = self._spawn_ufw(
                "insert",
                "1",
                "reject",
                "from",
                "10.97.0.%d" % (i + 1),
                "to",
                "any",
                "comment",
                F2B_COMMENT,
            )
            time.sleep(delay)
            p.kill()
            p.wait()

            data = self.read(self.user_rules)
            self.assertTrue(
                data.startswith("*filter") and data.endswith("COMMIT\n"),
                "user.rules torn after SIGKILL at %.2fs: size=%d tail=%r"
                % (delay, len(data), data[-40:]),
            )

        # ufw agrees: no truncation warning, file still usable
        out = self.assert_ok("status")
        self.assertNotIn("looks truncated", out)
        self.assert_ok("allow", "443")

    def test_concurrent_writers_do_not_lose_rules(self):
        """Concurrent inserts (two fail2ban jails, or fail2ban plus an
        admin) must all survive, on disk and in the kernel."""
        self.assert_ok("--force", "enable")
        # 'insert 1' needs an existing rule to insert above
        self.assert_ok("allow", "80", "comment", "nginx")

        procs = []
        ips = []
        for base in ("10.70.7", "10.80.7"):
            for i in range(1, 6):
                ip = "%s.%d" % (base, i)
                ips.append(ip)
                procs.append(
                    (
                        ip,
                        self._spawn_ufw(
                            "insert",
                            "1",
                            "reject",
                            "from",
                            ip,
                            "to",
                            "any",
                            "comment",
                            F2B_COMMENT,
                        ),
                    )
                )

        for ip, p in procs:
            out, _ = p.communicate()
            self.assertEqual(
                p.returncode,
                0,
                "insert of %s failed (rc=%d):\n%s" % (ip, p.returncode, out),
            )

        # every rule an insert reported success for is in the file ...
        content = self.read(self.user_rules)
        missing = [ip for ip in ips if " %s " % ip not in content]
        self.assertEqual(missing, [], "rules lost from user.rules: %s" % missing)

        # ... and in the real kernel
        applied = self.raw_iptables("-S", "ufw-user-input").out
        missing = [ip for ip in ips if "%s/32" % ip not in applied]
        self.assertEqual(missing, [], "rules lost from iptables: %s" % missing)


def test_main():
    tests.functional.support.run_e2e(ConcurrencyE2E)
