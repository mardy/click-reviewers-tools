'''test_cr_push_helper.py: tests for the cr_push_helper module'''
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

from clickreviews.cr_push_helper import ClickReviewPushHelper
import clickreviews.cr_tests as cr_tests


class TestClickReviewPushHelper(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def test_check_unknown_keys_none(self):
        '''Test check_unknown() - no unknown'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        c = ClickReviewPushHelper(self.test_name)
        c.check_unknown_keys()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_unknown_keys1(self):
        '''Test check_unknown() - one unknown'''
        self.set_test_push_helper(self.default_appname, "nonexistent", "foo")
        c = ClickReviewPushHelper(self.test_name)
        c.check_unknown_keys()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_unknown_keys2(self):
        '''Test check_unknown() - good with one unknown'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_push_helper(self.default_appname, "nonexistent", "foo")
        c = ClickReviewPushHelper(self.test_name)
        c.check_unknown_keys()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_valid_exec(self):
        '''Test check_valid() - exec'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        c = ClickReviewPushHelper(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_valid_missing_exec(self):
        '''Test check_valid() - missing exec'''
        self.set_test_push_helper(self.default_appname, "app_id", "foo_foo")
        c = ClickReviewPushHelper(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_valid_app_id(self):
        '''Test check_valid() - app_id'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_push_helper(self.default_appname, "app_id", "foo_foo")
        c = ClickReviewPushHelper(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_valid_bad_value(self):
        '''Test check_valid() - bad value'''
        self.set_test_push_helper(self.default_appname, "exec", [])
        c = ClickReviewPushHelper(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_valid_empty_value(self):
        '''Test check_valid() - empty value'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_push_helper(self.default_appname, "app_id", "")
        c = ClickReviewPushHelper(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_valid_empty_value2(self):
        '''Test check_valid() - empty value'''
        self.set_test_push_helper(self.default_appname, "exec", "")
        self.set_test_push_helper(self.default_appname, "app_id", "foo_foo")
        c = ClickReviewPushHelper(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_hooks(self):
        '''Test check_hooks()'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        c = ClickReviewPushHelper(self.test_name)

        # remove hooks that are added by the framework
        c.manifest['hooks'][self.default_appname].pop('desktop')
        c.manifest['hooks'][self.default_appname].pop('urls')

        c.check_hooks()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_hooks_bad(self):
        '''Test check_hooks() - bad'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        c = ClickReviewPushHelper(self.test_name)

        # The desktop and urls hooks are specified by default in the framework,
        # so just running this without other setup should generate an error
        c.check_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)