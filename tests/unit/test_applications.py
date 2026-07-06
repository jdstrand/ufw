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

import os
import shutil
import tempfile
import unittest
import unittest.mock
import tests.unit.support
import ufw.applications
import ufw.common


class ApplicationsTestCase(unittest.TestCase):
    def setUp(self):
        apps = os.path.join(ufw.common.config_dir, "ufw/applications.d")
        self.profiles = ufw.applications.get_profiles(apps)

    def tearDown(self):
        pass

    def test_get_profiles(self):
        """Test get_profiles()"""
        try:
            ufw.applications.get_profiles("foo")
            self.assertFalse(True)
        except ufw.common.UFWError:
            pass

        self.assertTrue("WWW" in self.profiles.keys(), "Could not find 'WWW'")
        self.assertEqual(self.profiles["WWW"]["ports"], "80/tcp")
        self.assertEqual(self.profiles["WWW"]["title"], "Web Server")
        self.assertEqual(self.profiles["WWW"]["description"], "Web server")

    def test_valid_profile_name(self):
        """Test valid_profile_name()"""
        self.assertTrue(ufw.applications.valid_profile_name("ABC"))
        self.assertFalse(ufw.applications.valid_profile_name("#ABC"))
        self.assertFalse(ufw.applications.valid_profile_name("all"))
        self.assertFalse(ufw.applications.valid_profile_name("123"))
        self.assertFalse(ufw.applications.valid_profile_name("AB*C"))

    def test_verify_profile(self):
        """Test verify_profile()"""
        profiles = [
            {"title": "test both", "description": "dns", "ports": "53"},
            {"title": "test tcp", "description": "desc", "ports": "22/tcp"},
            {"title": "test udp", "description": "desc", "ports": "123/udp"},
            {"title": "test multi comma", "description": "desc", "ports": "80,443/tcp"},
            {
                "title": "test multi range",
                "description": "desc",
                "ports": "60000:65000/udp",
            },
            {
                "title": "test different",
                "description": "desc",
                "ports": "123/udp|80/tcp",
            },
            {
                "title": "test man page",
                "description": "desc",
                "ports": "12/udp|34|56,78:90/tcp",
            },
        ]
        for p in profiles:
            self.assertTrue(ufw.applications.verify_profile("TESTPROFILE", p))

    def test_verify_profile_bad(self):
        """Test verify_profile() - bad"""
        profiles = [
            {"description": "missing title", "ports": "53"},
            {"title": "missing description", "ports": "22/tcp"},
            {"title": "missing ports", "description": "desc"},
            {"title": "", "description": "empty title", "ports": "80"},
            {"title": "empty description", "description": "", "ports": "80"},
            {"title": "empty ports", "description": "desc", "ports": ""},
            {
                "title": "bad missing proto - list",
                "description": "desc",
                "ports": "80,443",
            },
            {
                "title": "bad missing proto - range",
                "description": "desc",
                "ports": "80:443",
            },
            {
                "title": "bad range too big",
                "description": "desc",
                "ports": "80:70000/tcp",
            },
            {"title": "bad protocol - ah", "description": "desc", "ports": "80/ah"},
            {"title": "bad protocol - esp", "description": "desc", "ports": "80/esp"},
            {"title": "bad protocol - gre", "description": "desc", "ports": "80/gre"},
            {"title": "bad protocol - igmp", "description": "desc", "ports": "80/igmp"},
            {"title": "bad protocol - ipv6", "description": "desc", "ports": "80/ipv6"},
            {"title": "bad protocol - vrrp", "description": "desc", "ports": "80/vrrp"},
        ]
        for p in profiles:
            print(" %s" % p)
            tests.unit.support.check_for_exception(
                self,
                ufw.common.UFWError,
                ufw.applications.verify_profile,
                "TESTPROFILE",
                p,
            )

    def test_get_title(self):
        """Test get_title()"""
        self.assertEqual(ufw.applications.get_title(self.profiles["WWW"]), "Web Server")

    def test_get_description(self):
        """Test get_description()"""
        self.assertEqual(
            ufw.applications.get_description(self.profiles["WWW"]), "Web server"
        )

    def test_get_ports(self):
        """Test get_ports()"""
        expected_ports = ["80/tcp"]
        self.assertEqual(
            ufw.applications.get_ports(self.profiles["WWW"]), expected_ports
        )


class GetProfilesSkipsTestCase(unittest.TestCase):
    """get_profiles() validation/skip branches over a crafted profiles dir"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def _write(self, fn, contents):
        path = os.path.join(self.tmpdir, fn)
        with open(path, "w") as f:
            f.write(contents)
        return path

    def _valid_profile(self, name, ports="80/tcp"):
        return "[%s]\ntitle=t\ndescription=d\nports=%s\n" % (name, ports)

    def test_skips_file_that_cannot_be_stated(self):
        """Test get_profiles() - skips file that cannot be stat'd"""
        # simulate the file disappearing between listdir() and stat()
        path = self._write("gone", self._valid_profile("GoneProfile"))
        real_stat = os.stat

        def fake_stat(p, *args, **kwargs):
            if p == path:
                raise OSError("gone")
            return real_stat(p, *args, **kwargs)

        # isfile() consults os.stat() too, so pin it to keep the fake
        # failure scoped to get_profiles()'s own stat() call
        with unittest.mock.patch("os.path.isfile", return_value=True):
            with unittest.mock.patch("os.stat", side_effect=fake_stat):
                profiles = ufw.applications.get_profiles(self.tmpdir)
        self.assertEqual(profiles, {})

    def test_skips_too_big_file(self):
        """Test get_profiles() - skips file bigger than 10MB"""
        path = self._write("big", self._valid_profile("BigProfile"))
        with open(path, "a") as f:
            f.truncate(10 * 1024 * 1024 + 1)  # sparse; no real disk use
        profiles = ufw.applications.get_profiles(self.tmpdir)
        self.assertEqual(profiles, {})

    def test_skips_file_when_total_size_too_big(self):
        """Test get_profiles() - skips file once 10MB total is read"""
        # two 6MB files: each fits, together they exceed the 10MB total
        pad = "#" + "x" * (6 * 1024 * 1024) + "\n"
        self._write("aa", self._valid_profile("FirstProfile") + pad)
        self._write("bb", self._valid_profile("SecondProfile") + pad)
        profiles = ufw.applications.get_profiles(self.tmpdir)
        self.assertTrue("FirstProfile" in profiles)
        self.assertFalse("SecondProfile" in profiles)

    def test_skips_profile_name_too_long(self):
        """Test get_profiles() - skips profile name longer than 64"""
        contents = self._valid_profile("A" * 65) + self._valid_profile("KeptProfile")
        self._write("profiles", contents)
        profiles = ufw.applications.get_profiles(self.tmpdir)
        self.assertEqual(list(profiles.keys()), ["KeptProfile"])

    def test_skips_profile_field_too_long(self):
        """Test get_profiles() - skips profile with field longer than 64"""
        contents = self._valid_profile("BadProfile")[:-1] + "\n%s=v\n" % ("k" * 65)
        self._write("profiles", contents + self._valid_profile("KeptProfile"))
        profiles = ufw.applications.get_profiles(self.tmpdir)
        self.assertEqual(list(profiles.keys()), ["KeptProfile"])

    def test_skips_profile_value_too_long(self):
        """Test get_profiles() - skips profile with value longer than 1024"""
        contents = self._valid_profile("BadProfile")[:-1] + "\nextra=%s\n" % (
            "v" * 1025
        )
        self._write("profiles", contents + self._valid_profile("KeptProfile"))
        profiles = ufw.applications.get_profiles(self.tmpdir)
        self.assertEqual(list(profiles.keys()), ["KeptProfile"])

    def test_duplicate_profile_uses_last_found(self):
        """Test get_profiles() - duplicate profile uses last found"""
        self._write("aa", self._valid_profile("DupProfile", ports="80/tcp"))
        self._write("bb", self._valid_profile("DupProfile", ports="443/tcp"))
        profiles = ufw.applications.get_profiles(self.tmpdir)
        self.assertEqual(profiles["DupProfile"]["ports"], "443/tcp")


def test_main():  # used by runner.py
    tests.unit.support.run_unittest(
        ApplicationsTestCase,
        GetProfilesSkipsTestCase,
    )


if __name__ == "__main__":  # used when standalone
    unittest.main()
