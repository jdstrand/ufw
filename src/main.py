#! /usr/bin/env python
#
# ufw: front-end for Linux firewalling (cli)
#
# Copyright 2008-2024 Canonical Ltd.
# Copyright 2025 Jamie Strandboge
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import print_function
import os
import sys
import warnings

import ufw.common
import ufw.frontend

# state_dir/trans_dir are deliberately NOT imported here: they're read as
# ufw.common.* at call time so a runtime repoint (the test sandbox) is honored.
from ufw.common import UFWError, programName
from ufw.util import error, warn, msg, _findpath, create_lock, release_lock

import gettext

kwargs = {}
gettext.install(programName, **kwargs)

version = "#VERSION#"


def clean_warning(message, category, filename, lineno, file=None, line=""):
    # these are for pyright
    _ = category  # unused
    _ = filename  # unused
    _ = lineno  # unused
    _ = file  # unused
    _ = line  # unused

    warn(message)


def main_ufw(argv=None):
    # argv defaults to sys.argv; the functional tests pass their own command
    # line to drive this entry point in-process without mutating sys.argv.
    if argv is None:
        argv = sys.argv

    # relocate root and data directories if specified
    args = []
    rootdir = None
    datadir = None
    for i in argv:
        if i.startswith("--rootdir="):
            if len(i.split("=")) == 2:
                rootdir = i.split("=")[1]
            else:
                error("--rootdir is empty")
        elif i.startswith("--datadir="):
            if len(i.split("=")) == 2:
                datadir = i.split("=")[1]
            else:
                error("--datadir is empty")
        else:
            args.append(i)

    # Internationalization
    gettext.bindtextdomain(
        programName,
        os.path.join(_findpath(ufw.common.trans_dir, rootdir), "messages"),
    )
    gettext.textdomain(programName)
    tr = gettext.gettext

    warnings.showwarning = clean_warning
    app_action = False
    pr = None

    # Remember, will have to take --force into account if we use it with 'app'
    idx = 1
    if len(args) > 1 and args[1].lower() == "--dry-run":
        idx += 1

    if len(args) > idx and args[idx].lower() == "app":
        app_action = True

    try:
        pr = ufw.frontend.parse_command(args)
    except ValueError:
        msg(ufw.frontend.get_command_help())
        sys.exit(1)
    except UFWError as e:
        error(e.value)
    except Exception:
        raise

    assert pr is not None

    if pr.action == "help" or pr.action == "--help" or pr.action == "-h":
        msg(ufw.frontend.get_command_help())
        sys.exit(0)
    elif pr.action == "version" or pr.action == "--version":
        msg(programName + " " + version)
        msg("Copyright 2008-2023 Canonical Ltd.")
        sys.exit(0)

    if datadir is None:
        lockfile = "/run/ufw.lock"
        if os.getuid() != 0 or "TESTSTATE" in os.environ:
            lockfile = os.path.join(ufw.common.state_dir, "ufw.lock")
    else:
        lockfile = os.path.join(_findpath(ufw.common.state_dir, datadir), "ufw.lock")

    # Take the lock before constructing the frontend: it reads the rules and
    # config files, and acting on -- worse, rewriting from -- a snapshot
    # taken during another process's update discards that process's changes
    # (LP: #2126805)
    try:
        lock = create_lock(lockfile=lockfile, dryrun=pr.dryrun)
    except OSError:
        if os.getuid() == 0:
            # root can modify state, so running unlocked would silently
            # reintroduce the race the lock exists to prevent
            error(tr("Couldn't create lock '%s'") % (lockfile))
        # not root: proceed unlocked and let the frontend's own permission
        # checks report the error
        lock = None

    res = ""
    try:
        ui = ufw.frontend.UFWFrontend(pr.dryrun, rootdir=rootdir, datadir=datadir)

        if app_action and "type" in pr.data and pr.data["type"] == "app":
            res = ui.do_application_action(pr.action, pr.data["name"])
        else:
            bailout = False
            if pr.action == "enable" and not pr.force and not ui.continue_under_ssh():
                res = tr("Aborted")
                bailout = True

            if not bailout:
                if "rule" in pr.data:
                    res = ui.do_action(
                        pr.action, pr.data["rule"], pr.data["iptype"], pr.force
                    )
                else:
                    res = ui.do_action(pr.action, "", "", pr.force)

        if res != "":
            msg(res)

    except UFWError as e:
        error(e.value)
    except Exception:
        raise
    finally:
        release_lock(lock)

    sys.exit(0)


if __name__ == "__main__":
    main_ufw()
