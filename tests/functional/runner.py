#!/usr/bin/python
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
# find_tests(), runtest() and main() inspired by tests/unit/runner.py


from __future__ import print_function
import os
import sys


def find_tests(testdir=None, testscripts=[]):
    """Find tests"""
    if not testdir:
        testdir = os.path.dirname(os.path.abspath(__file__))

    if len(testscripts) > 1:
        names = testscripts[1:]
    else:
        names = os.listdir(testdir)
    tests = []
    for name in names:
        if name[:5] == "test_" and name[-3:] == ".py":
            tests.append(name[:-3])
    tests.sort()
    return tests


def runtest(test):
    """Run test"""
    pkg = __import__("tests.functional." + test, globals(), locals(), [])
    functional_pkg = getattr(pkg, "functional")
    mod = getattr(functional_pkg, test)
    print(test)
    mod.test_main()


if __name__ == "__main__":
    # Resolve the repo root from runner.py's location.
    d = os.path.abspath(os.path.normpath(os.path.dirname(sys.argv[0])))
    testdir = os.path.dirname(os.path.dirname(d))

    # Create the ufw -> src symlink under ./tmp (git-ignored) so 'import ufw.*'
    # resolves to src/ without cluttering the repo root, and put ./tmp on
    # sys.path. Relative target, so the link stays valid if the checkout
    # moves; recreate it when dangling or pointing elsewhere (islink() is
    # true for a dangling link, and following a stale one would import some
    # other tree's src/).
    tmpdir = os.path.join(testdir, "tmp")
    ufwlink = os.path.join(tmpdir, "ufw")
    linktarget = os.path.join("..", "src")
    if not os.path.isdir(tmpdir):
        os.mkdir(tmpdir)
    if os.path.islink(ufwlink) and os.readlink(ufwlink) != linktarget:
        os.unlink(ufwlink)
    if os.path.exists(ufwlink) and not os.path.islink(ufwlink):
        # A real file/dir in the link's place would silently shadow src/.
        sys.stderr.write("ERROR: %s exists and is not a symlink; remove it\n" % ufwlink)
        sys.exit(1)
    if not os.path.islink(ufwlink):
        os.symlink(linktarget, ufwlink)
    sys.path.insert(0, tmpdir)

    # Replace runner.py's directory in sys.path with the repo root so our
    # modules namespace properly as tests.functional.*
    i = len(sys.path)
    while i >= 0:
        i -= 1
        if os.path.abspath(os.path.normpath(sys.path[i])) == d:
            sys.path[i] = testdir

    tests = find_tests(testscripts=sys.argv)

    # Import here so we are guaranteed to get ours from the repo root
    from tests.functional.support import TestFailed

    passed = []
    failed = []
    try:
        for test in tests:
            try:
                runtest(test)
                passed.append(test)
            except KeyboardInterrupt:
                print("")
                break
            except TestFailed:
                failed.append(test)
            except Exception:
                raise

            # cleanup imported test modules between runs
            for m in list(sys.modules.keys()):
                if (
                    m.startswith("tests.functional.")
                    and m != "tests.functional.support"
                ):
                    try:
                        del sys.modules[m]
                    except KeyError:
                        pass
    finally:
        # Cleanup our symlink, also when a test module dies on an unexpected
        # exception (a stale leftover link shadows the next run's recreate).
        if os.path.islink(ufwlink):
            os.unlink(ufwlink)

    print("")
    print("------------------------")
    print("Functional tests summary")
    print("------------------------")
    print(
        "Total=%d (Passed=%d, Failed=%d)"
        % (len(passed) + len(failed), len(passed), len(failed))
    )
    if len(failed) > 0:
        sys.exit(1)
