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

    def test_check_peer_hooks(self):
        '''Test check_peer_hooks()'''
        # add our hook
        self.set_test_bin_path(self.default_appname, "bin/foo.nonexec")

        # strip out all the default hooks from the hooks database
        tmp = dict()
        for k in self.test_manifest["hooks"][self.default_appname]:
            if k == "bin-path":
                tmp[k] = self.test_manifest["hooks"][self.default_appname][k]
        # add any required peer hooks
        tmp["systemd"] = "foo.systemd"
        tmp["apparmor"] = "foo.apparmor"

        self.test_manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        #  do the test
        c = ClickReviewBinPath(self.test_name)

        c.check_peer_hooks()
        r = c.click_report
        # We should end up with 2 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_disallowed(self):
        '''Test check_peer_hooks() - disallowed'''
        # add our hook
        self.set_test_bin_path(self.default_appname, "bin/foo.nonexec")

        # strip out all the default hooks from the hooks database
        tmp = dict()
        for k in self.test_manifest["hooks"][self.default_appname]:
            if k == "bin-path":
                tmp[k] = self.test_manifest["hooks"][self.default_appname][k]
        # add any required peer hooks
        tmp["systemd"] = "foo.systemd"
        tmp["apparmor"] = "foo.apparmor"

        # add something not allowed
        tmp["nonexistent"] = "nonexistent-hook"

        self.test_manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        #  do the test
        c = ClickReviewBinPath(self.test_name)

        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_required(self):
        '''Test check_peer_hooks() - required'''
        # add our hook
        self.set_test_bin_path(self.default_appname, "bin/foo.nonexec")

        # strip out all the default hooks from the hooks database
        tmp = dict()
        for k in self.test_manifest["hooks"][self.default_appname]:
            if k == "bin-path":
                tmp[k] = self.test_manifest["hooks"][self.default_appname][k]
        # skip adding required hooks

        self.test_manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        c = ClickReviewBinPath(self.test_name)

        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
