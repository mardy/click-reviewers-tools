'''test_cr_lint.py: tests for the cr_lint module'''
#
# Copyright (C) 2013 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import StringIO

from mock import patch
from unittest import TestCase

from cr_lint import ClickReviewLint


TEST_CONTROL = """Package: net.launchpad.click-webapps.test-app
Version: 3
Click-Version: 0.2
Architecture: all
Maintainer: Test Dev <test@email.com>
Installed-Size: 111
Description: Test app"""

TEST_MANIFEST = """{
    "description": "A long description",
    "framework": "ubuntu-sdk-13.10",
    "maintainer": "Test Dev <test@email.com>",
    "name": "net.launchpad.click-webapps.test-app",
    "hooks": {
        "test-app": {
           "apparmor": "apparmor/test-app.json",
           "desktop": "test-app.desktop"
        }
    },
    "title": "My Test App",
    "version": "3"
}"""


def _mock_func(self):
    return


def _extract_control_file(self):
    return StringIO.StringIO(TEST_CONTROL)


def _extract_manifest_file(self):
    return StringIO.StringIO(TEST_MANIFEST)


class TestClickReviewLint(TestCase):
    """Tests for the lint review tool."""

    @patch('cr_common.ClickReview._check_path_exists', _mock_func)
    @patch('cr_common.ClickReview._extract_control_file', _extract_control_file)
    @patch('cr_common.ClickReview._extract_manifest_file', _extract_manifest_file)
    @patch('cr_common.unpack_click', _mock_func)
    @patch('cr_common.ClickReview.__del__', _mock_func)
    def test_check_package_filename(self):
        """Test that package names comply to the policies."""
        test_name = 'net.launchpad.click-webapps.test-app_3_all.click'
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        print(c.click_report)
        self.assertEqual(len(r['warn']), 0)
        self.assertEqual(len(r['error']), 0)
