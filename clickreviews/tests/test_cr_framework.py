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
        # add our hook
        self.set_test_framework(self.default_appname, "Base-Version", 0.1)

        # strip out all the default hooks from the hooks database
        tmp = dict()
        for k in self.test_manifest["hooks"][self.default_appname]:
            if k == "framework":
                tmp[k] = self.test_manifest["hooks"][self.default_appname][k]
        self.test_manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        #  do the test
        c = ClickReviewFramework(self.test_name)

        c.check_peer_hooks()
        r = c.click_report
        # We should end up with 2 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_disallowed(self):
        '''Test check_peer_hooks() - disallowed'''
        # add our hook
        self.set_test_framework(self.default_appname, "Base-Version", 0.1)

        # strip out all the default hooks from the hooks database
        tmp = dict()
        for k in self.test_manifest["hooks"][self.default_appname]:
            if k == "framework":
                tmp[k] = self.test_manifest["hooks"][self.default_appname][k]
        tmp["nonexistent"] = "nonexistent-hook"
        self.test_manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        #  do the test
        c = ClickReviewFramework(self.test_name)

        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_required(self):
        '''Test check_peer_hooks() - required'''
        # add our hook
        self.set_test_framework(self.default_appname, "Base-Version", 0.1)

        # strip out all the default hooks from the hooks database
        tmp = dict()
        for k in self.test_manifest["hooks"][self.default_appname]:
            if k == "framework":
                tmp[k] = self.test_manifest["hooks"][self.default_appname][k]
        tmp["apparmor-policy"] = "apparmor/"
        self.test_manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        c = ClickReviewFramework(self.test_name)
        # FIXME: 'apparmor-policy' doesn't exist yet. When it does, adjust
        # ClickReviewFramework.__init__() to add it
        c.peer_hooks["framework"]["required"].append("apparmor-policy")
        c.peer_hooks["framework"]["allowed"].append("apparmor-policy")

        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)
