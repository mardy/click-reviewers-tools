'''test_cr_bin_path.py: tests for the cr_bin_path module'''
#
# Copyright (C) 2014 Canonical Ltd.
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

from clickreviews.cr_bin_path import ClickReviewBinPath
import clickreviews.cr_tests as cr_tests


class TestClickReviewBinPath(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def test_check_path(self):
        '''Test check_path()'''
        self.set_test_bin_path(self.default_appname, "bin/foo.exe")
        c = ClickReviewBinPath(self.test_name)
        c.check_path()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_path_nonexecutable(self):
        '''Test check_path() - nonexecutable'''
        self.set_test_bin_path(self.default_appname, "bin/foo.nonexec")
        c = ClickReviewBinPath(self.test_name)
        c.check_path()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
