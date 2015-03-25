'''test_cr_framework.py: tests for the cr_framework module'''
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
import sys
from io import StringIO

from clickreviews.cr_framework import ClickReviewFramework
import clickreviews.cr_tests as cr_tests


class TestClickReviewFramework(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def test_single_framework(self):
        '''Test check_single_framework()'''
        self.set_test_framework(self.default_appname, "", "")
        c = ClickReviewFramework(self.test_name)

        c.check_single_framework()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_single_framework_multiple(self):
        '''Test check_single_framework() - multiple'''
        self.set_test_framework(self.default_appname, "", "")
        self.set_test_framework("test-alt", "", "")
        c = ClickReviewFramework(self.test_name)
        c.check_single_framework()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_framework_base_name(self):
        '''Test check_framework_base_name()'''
        self.set_test_framework(self.default_appname, "Base-Name",
                                self.test_manifest["name"])
        c = ClickReviewFramework(self.test_name)
        c.check_framework_base_name()
        r = c.click_report
        # We should end up with 2 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_framework_base_name_missing(self):
        '''Test check_framework_base_name() - missing'''
        self.set_test_framework(self.default_appname, "Base-Version", "")
        c = ClickReviewFramework(self.test_name)
        c.check_framework_base_name()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_framework_base_name_empty(self):
        '''Test check_framework_base_name() - empty'''
        self.set_test_framework(self.default_appname, "Base-Name", "")
        c = ClickReviewFramework(self.test_name)
        c.check_framework_base_name()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_framework_base_version(self):
        '''Test check_framework_base_version()'''
        self.set_test_framework(self.default_appname, "Base-Version", 0.1)
        c = ClickReviewFramework(self.test_name)
        c.check_framework_base_version()
        r = c.click_report
        # We should end up with 3 info
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_framework_base_version_missing(self):
        '''Test check_framework_base_version() - missing'''
        self.set_test_framework(self.default_appname, "Base-Name", "")
        c = ClickReviewFramework(self.test_name)
        c.check_framework_base_version()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_framework_base_version_empty(self):
        '''Test check_framework_base_version() - empty'''
        self.set_test_framework(self.default_appname, "Base-Version", "")
        c = ClickReviewFramework(self.test_name)
        c.check_framework_base_version()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_framework_base_version_str(self):
        '''Test check_framework_base_version() - str'''
        self.set_test_framework(self.default_appname, "Base-Version", "abc")
        c = ClickReviewFramework(self.test_name)
        c.check_framework_base_version()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_framework_base_version_negative(self):
        '''Test check_framework_base_version() - negative'''
        self.set_test_framework(self.default_appname, "Base-Version", -1)
        c = ClickReviewFramework(self.test_name)
        c.check_framework_base_version()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks(self):
        '''Test check_peer_hooks()'''
        self.set_test_framework(self.default_appname, "Base-Version", 0.1)
        c = ClickReviewFramework(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["framework"] = "foo.framework"

        # add any required peer hooks
        # FIXME:
        # tmp["apparmor-policy"] = "apparmor/"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        # We should end up with 2 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_disallowed(self):
        '''Test check_peer_hooks() - disallowed'''
        self.set_test_framework(self.default_appname, "Base-Version", 0.1)
        c = ClickReviewFramework(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["framework"] = "foo.framework"

        # add any required peer hooks
        # FIXME:
        # tmp["apparmor-policy"] = "apparmor/"

        # add disallowed framework
        tmp["nonexistent"] = "nonexistent-hook"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_required(self):
        '''Test check_peer_hooks() - required'''
        self.set_test_framework(self.default_appname, "Base-Version", 0.1)
        c = ClickReviewFramework(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["framework"] = "foo.framework"

        # skip adding required hooks

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        # FIXME: apparmor-policy is not defined yet, so no error, when it is
        # adjust to 'error': 1
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_framework_not_string_error(self):
        '''Test manifest framework is non-string.'''
        self.test_manifest['hooks'][self.default_appname]['framework'] = 1234
        self._update_test_manifest()

        error = ""
        stderr = sys.stderr
        try:
            sys.stderr = StringIO()
            with self.assertRaises(SystemExit):
                ClickReviewFramework(self.test_name)
            error = sys.stderr.getvalue()
        finally:
            sys.stderr = stderr

        self.assertEqual(
            error,
            "ERROR: manifest malformed: hooks/test-app/framework is not str\n")
