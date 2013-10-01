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

from unittest.mock import patch

from clickreviews.cr_lint import ClickReviewLint
from clickreviews.cr_lint import MINIMUM_CLICK_FRAMEWORK_VERSION
import clickreviews.cr_tests as cr_tests

class TestClickReviewLint(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def test_check_package_filename_with_extra_click(self):
        """Test namespaces with the word "click" in them."""
        c = ClickReviewLint(self.test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_control(self):
        """A very basic test to make sure check_control can be tested."""
        c = ClickReviewLint(self.test_name)
        c.check_control()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    # Make the current MINIMUM_CLICK_FRAMEWORK_VERSION newer
    @patch('clickreviews.cr_lint.MINIMUM_CLICK_FRAMEWORK_VERSION',
        MINIMUM_CLICK_FRAMEWORK_VERSION + '.1')
    def test_check_control_click_framework_version(self):
        """Test that enforcing click framework versions works."""
        test_name = 'net.launchpad.click-webapps.test-app_3_all.click'
        c = ClickReviewLint(test_name)
        c.check_control()
        r = c.click_report
        # We should end up with an error as the click version is out of date
        expected_counts={'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
        # Lets check that the right error is triggering
        self.assertIn('Click-Version is too old',
            r['error']['lint_control_click_version_up_to_date'])
