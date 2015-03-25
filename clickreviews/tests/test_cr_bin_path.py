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

    def _set_binary(self, entries, name=None):
        d = dict()
        if name is None:
            d['name'] = 'foo'
        else:
            d['name'] = name
        for (key, value) in entries:
            d[key] = value
        self.set_test_pkg_yaml("binaries", [d])

    def test_check_path(self):
        '''Test check_path()'''
        self.set_test_bin_path(self.default_appname,
                               key="exec",
                               value="bin/foo.exe")
        c = ClickReviewBinPath(self.test_name)
        c.check_path()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_path_nonexecutable(self):
        '''Test check_path() - nonexecutable'''
        self.set_test_bin_path(self.default_appname,
                               key="exec",
                               value="bin/foo.nonexec")
        c = ClickReviewBinPath(self.test_name)
        c.check_path()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks(self):
        '''Test check_peer_hooks()'''
        c = ClickReviewBinPath(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["bin-path"] = "usr/bin/foo"

        # add any required peer hooks
        tmp["apparmor"] = "foo.apparmor"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        #  do the test
        c.check_peer_hooks()
        r = c.click_report
        # We should end up with 2 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_disallowed(self):
        '''Test check_peer_hooks() - disallowed'''
        c = ClickReviewBinPath(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["bin-path"] = "usr/bin/foo"

        # add any required peer hooks
        tmp["snappy-systemd"] = "foo.systemd"
        tmp["apparmor"] = "foo.apparmor"

        # add something not allowed
        tmp["nonexistent"] = "nonexistent-hook"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_required(self):
        '''Test check_peer_hooks() - required'''
        c = ClickReviewBinPath(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["bin-path"] = "usr/bin/foo"

        # skip adding required hooks

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_required(self):
        '''Test check_snappy_required() - has exec'''
        self._set_binary([("exec", "bin/foo")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        # Only 'name' is required at this time
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_required_empty_value(self):
        '''Test check_snappy_required() - empty exec'''
        self._set_binary([("exec", "")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        # Only 'name' is required at this time
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_required_bad_value(self):
        '''Test check_snappy_required() - bad exec'''
        self._set_binary([("exec", [])])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        # Only 'name' is required at this time
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_required_multiple(self):
        '''Test check_snappy_required() - multiple'''
        self._set_binary([("exec", "bin/foo"),
                          ("description", "foo desc")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        # Only 'name' is required at this time
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_optional(self):
        '''Test check_snappy_optional()'''
        self._set_binary([("description", "some description")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_optional_empty_value(self):
        '''Test check_snappy_optional() - empty description'''
        self._set_binary([("description", "")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_optional_bad_value(self):
        '''Test check_snappy_optional() - bad description'''
        self._set_binary([("description", [])])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_unknown(self):
        '''Test check_snappy_unknown()'''
        self._set_binary([("nonexistent", "foo")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_unknown()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_unknown_multiple(self):
        '''Test check_snappy_unknown() - multiple'''
        self._set_binary([("exec", "bin/foo"),
                          ("nonexistent", "foo")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_unknown()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_binary_description(self):
        '''Test check_binary_description()'''
        self._set_binary([("description", "some description")])
        c = ClickReviewBinPath(self.test_name)
        c.check_binary_description()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_binary_description_unspecified(self):
        '''Test check_binary_description() - unspecified'''
        self._set_binary([("name", "foo")])
        c = ClickReviewBinPath(self.test_name)
        c.check_binary_description()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_binary_description_empty(self):
        '''Test check_binary_description() - empty'''
        self._set_binary([("description", "")])
        c = ClickReviewBinPath(self.test_name)
        c.check_binary_description()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
