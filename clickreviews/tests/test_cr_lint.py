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

from apt import apt_pkg
import io

from unittest.mock import patch
from unittest import TestCase

from clickreviews.cr_lint import ClickReviewLint
from clickreviews.cr_lint import MINIMUM_CLICK_FRAMEWORK
from clickreviews.cr_common import ClickReview


TEST_CONTROL = """Package: net.launchpad.click-webapps.test-app
Version: 3
Click-Version: %s
Architecture: all
Maintainer: Test Dev <test@email.com>
Installed-Size: 111
Description: My Test App""" % (MINIMUM_CLICK_FRAMEWORK)

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
    return io.StringIO(TEST_CONTROL)


def _extract_manifest_file(self):
    return io.StringIO(TEST_MANIFEST)


# Patch all methods that call out to disk
@patch('clickreviews.cr_common.ClickReview._check_path_exists', _mock_func)
@patch('clickreviews.cr_common.ClickReview._extract_control_file',
    _extract_control_file)
@patch('clickreviews.cr_common.ClickReview._extract_manifest_file',
    _extract_manifest_file)
@patch('clickreviews.cr_common.unpack_click', _mock_func)
@patch('clickreviews.cr_common.ClickReview.__del__', _mock_func)
@patch('clickreviews.cr_lint.ClickReviewLint._list_control_files', _mock_func)
@patch('clickreviews.cr_lint.ClickReviewLint._list_all_files', _mock_func)
class TestClickReviewLint(TestCase):
    """Tests for the lint review tool."""

    def test_check_package_filename_with_extra_click(self):
        """Test namespaces with the word "click" in them."""
        test_name = 'net.launchpad.click-webapps.test-app_3_all.click'
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        # We should end up with no warnings, no errors
        self.assertEqual(len(r['warn']), 0)
        self.assertEqual(len(r['error']), 0)

    def test_check_control(self):
        """A very basic test to make sure check_control can be tested."""
        test_name = 'net.launchpad.click-webapps.test-app_3_all.click'
        c = ClickReviewLint(test_name)
        c.check_control()
        r = c.click_report
        # We should end up with no warnings, no errors
        self.assertEqual(len(r['warn']), 0)
        self.assertEqual(len(r['error']), 0)

    @patch('clickreviews.cr_lint.MINIMUM_CLICK_FRAMEWORK',
        MINIMUM_CLICK_FRAMEWORK + '.1')
    def test_check_control_click_framework_version(self):
        """Test that enforcing click framework versions works."""
        test_name = 'net.launchpad.click-webapps.test-app_3_all.click'
        c = ClickReviewLint(test_name)
        c.check_control()
        r = c.click_report
        # We should end up with an error as the click version is out of date
        self.assertEqual(len(r['warn']), 0)
        self.assertEqual(len(r['error']), 1)
