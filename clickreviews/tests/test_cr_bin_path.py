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
    """Tests for the bin-path review tool."""
    def setUp(self):
        super().setUp()
        self.set_test_pkgfmt("snap", "15.04")

    def _set_binary(self, entries, name=None):
        d = dict()
        if name is None:
            d['name'] = self.default_appname
        else:
            d['name'] = name
        for (key, value) in entries:
            d[key] = value
        self.set_test_pkg_yaml("binaries", [d])

        if 'exec' in d:
            self.set_test_bin_path(d['name'], d['exec'])
        else:
            self.set_test_bin_path(d['name'], d['name'])

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
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_required(self):
        '''Test check_snappy_required()'''
        self._set_binary([("exec", "bin/foo")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        # Only 'name' is required at this time so 0s for all
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_required_empty_value(self):
        '''Test check_snappy_required() - empty exec'''
        self._set_binary([("exec", "")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        # Only 'name' is required at this time so 0s for all
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_required_bad_value(self):
        '''Test check_snappy_required() - bad exec'''
        self._set_binary([("exec", [])])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        # Only 'name' is required at this time so 0s for all
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_required_multiple(self):
        '''Test check_snappy_required() - multiple'''
        self._set_binary([("exec", "bin/foo"),
                          ("description", "foo desc")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        # Only 'name' is required at this time so 0s for all
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

    def test_check_snappy_optional_empty_value(self):
        '''Test check_snappy_optional() - empty description'''
        self._set_binary([("description", "")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_optional_bad_value(self):
        '''Test check_snappy_optional() - bad description'''
        self._set_binary([("description", [])])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_unknown(self):
        '''Test check_snappy_unknown()'''
        self._set_binary([("nonexistent", "foo")])
        c = ClickReviewBinPath(self.test_name)
        c.check_snappy_unknown()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_unknown_multiple(self):
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
        self._set_binary([("exec", "foo")])
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
