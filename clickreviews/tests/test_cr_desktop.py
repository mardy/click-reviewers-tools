'''test_cr_desktop.py: tests for the cr_desktop module'''
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

from clickreviews.cr_desktop import ClickReviewDesktop
import clickreviews.cr_tests as cr_tests


class TestClickReviewDesktop(cr_tests.TestClickReview):
    """Tests for the desktop review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def test_check_desktop_file(self):
        '''Test check_desktop_file()'''
        c = ClickReviewDesktop(self.test_name)
        c.check_desktop_file()
        r = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']['desktop_files_usable'] = "OK"
        expected['info']['desktop_files_available'] = "OK"
        self.check_results(r, expected=expected)

    def test_check_desktop_file_valid(self):
        '''Test check_desktop_file_valid()'''
        c = ClickReviewDesktop(self.test_name)
        c.check_desktop_file_valid()
        r = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']['desktop_validates (%s)' %
                         self.default_appname] = "OK"
        self.check_results(r, expected=expected)

    def test_check_desktop_file_valid_missing_exec(self):
        '''Test check_desktop_file_valid() - missing Exec'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec", None)
        c.check_desktop_file_valid()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_file_valid_empty_name(self):
        '''Test check_desktop_file_valid() - empty Name'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Name", "")
        c.check_desktop_file_valid()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_required_keys(self):
        '''Test check_desktop_required_keys()'''
        c = ClickReviewDesktop(self.test_name)
        c.check_desktop_required_keys()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_required_keys_missing(self):
        '''Test check_desktop_required_keys()'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Name", None)
        c.check_desktop_required_keys()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
