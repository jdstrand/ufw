#
# Copyright 2012-2024 Canonical Ltd.
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
#

import io
import runpy
import sys
import unittest
import unittest.mock
import warnings
import tests.unit.support
import ufw.common
import ufw.frontend
import ufw.main
import ufw.util


class MainTestCase(unittest.TestCase):
    """Drive main_ufw(argv) for the paths the functional suite can't reach
    (it repoints ufw.common.* directly, so it never passes --rootdir or
    --datadir, and it never mocks the frontend out from under main)."""

    def _run_main(self, args):
        """Run main_ufw() in-process, returning (rc, output) with msg() and
        stderr captured (same technique as tests/functional/support.py)"""
        buf = io.StringIO()
        old_msg_output = ufw.util.msg_output
        old_stderr = sys.stderr
        ufw.util.msg_output = buf
        sys.stderr = buf
        rc = 0
        try:
            ufw.main.main_ufw(["ufw"] + args)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
        finally:
            ufw.util.msg_output = old_msg_output
            sys.stderr = old_stderr
        return (rc, buf.getvalue())

    def _fake_ui(self):
        ui = unittest.mock.MagicMock()
        ui.continue_under_ssh.return_value = True
        ui.do_action.return_value = ""
        return ui

    def test_argv_defaults_to_sys_argv(self):
        """Test main_ufw() - argv defaults to sys.argv"""
        with unittest.mock.patch.object(sys, "argv", ["ufw", "version"]):
            buf = io.StringIO()
            old_msg_output = ufw.util.msg_output
            ufw.util.msg_output = buf
            try:
                with self.assertRaises(SystemExit) as cm:
                    ufw.main.main_ufw()
            finally:
                ufw.util.msg_output = old_msg_output
        self.assertEqual(cm.exception.code, 0)
        self.assertTrue(ufw.common.programName in buf.getvalue())

    def test_rootdir_and_datadir_args(self):
        """Test main_ufw() - --rootdir/--datadir parsing"""
        # 'version' exits before the frontend is built, so the paths need
        # not exist; this exercises just the argument parsing
        (rc, out) = self._run_main(["--rootdir=/nonexistent", "version"])
        self.assertEqual(rc, 0)
        (rc, out) = self._run_main(["--datadir=/nonexistent", "version"])
        self.assertEqual(rc, 0)

        # a second '=' makes the split fail the length check
        (rc, out) = self._run_main(["--rootdir=a=b", "version"])
        self.assertEqual(rc, 1)
        self.assertTrue("--rootdir is empty" in out)
        (rc, out) = self._run_main(["--datadir=a=b", "version"])
        self.assertEqual(rc, 1)
        self.assertTrue("--datadir is empty" in out)

    def test_parse_command_ufwerror(self):
        """Test main_ufw() - UFWError from parse_command()"""
        with unittest.mock.patch.object(
            ufw.frontend,
            "parse_command",
            side_effect=ufw.common.UFWError("parse boom"),
        ):
            (rc, out) = self._run_main(["status"])
        self.assertEqual(rc, 1)
        self.assertTrue("parse boom" in out)

    def test_frontend_exception_reraised(self):
        """Test main_ufw() - non-UFWError from UFWFrontend is re-raised"""
        with unittest.mock.patch.object(
            ufw.frontend, "UFWFrontend", side_effect=RuntimeError("init boom")
        ):
            self.assertRaises(RuntimeError, ufw.main.main_ufw, ["ufw", "status"])

    def test_datadir_lockfile(self):
        """Test main_ufw() - lockfile is placed under --datadir"""
        ui = self._fake_ui()
        with unittest.mock.patch.object(ufw.frontend, "UFWFrontend", return_value=ui):
            (rc, out) = self._run_main(
                ["--dry-run", "--datadir=/nonexistent", "status"]
            )
        self.assertEqual(rc, 0)
        ui.do_action.assert_called_once_with("status", "", "", False)

    def test_enable_aborted_under_ssh(self):
        """Test main_ufw() - enable is aborted when under ssh"""
        ui = self._fake_ui()
        ui.continue_under_ssh.return_value = False
        with unittest.mock.patch.object(ufw.frontend, "UFWFrontend", return_value=ui):
            (rc, out) = self._run_main(["--dry-run", "enable"])
        self.assertEqual(rc, 0)
        self.assertTrue("Aborted" in out)
        self.assertFalse(ui.do_action.called)

    def test_do_action_exception_reraised(self):
        """Test main_ufw() - non-UFWError from do_action is re-raised"""
        ui = self._fake_ui()
        ui.do_action.side_effect = RuntimeError("action boom")
        with unittest.mock.patch.object(ufw.frontend, "UFWFrontend", return_value=ui):
            self.assertRaises(
                RuntimeError, ufw.main.main_ufw, ["ufw", "--dry-run", "status"]
            )

    def test_run_as_script(self):
        """Test main.py - __main__ invokes main_ufw()"""
        buf = io.StringIO()
        old_msg_output = ufw.util.msg_output
        ufw.util.msg_output = buf
        try:
            with unittest.mock.patch.object(sys, "argv", ["ufw", "version"]):
                with warnings.catch_warnings():
                    # runpy warns that ufw.main is already imported
                    warnings.simplefilter("ignore")
                    with self.assertRaises(SystemExit) as cm:
                        runpy.run_module("ufw.main", run_name="__main__")
        finally:
            ufw.util.msg_output = old_msg_output
        self.assertEqual(cm.exception.code, 0)
        self.assertTrue(ufw.common.programName in buf.getvalue())


def test_main():  # used by runner.py
    tests.unit.support.run_unittest(MainTestCase)


if __name__ == "__main__":  # used when standalone
    unittest.main()
