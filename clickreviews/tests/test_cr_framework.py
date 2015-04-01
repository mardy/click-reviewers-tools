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

    def test_framework_hook_obsolete(self):
        '''Test check_framework_hook_obsolete()'''
        self.set_test_framework(self.default_appname, "", "")
        c = ClickReviewFramework(self.test_name)

        c.check_framework_hook_obsolete()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_snappy_framework_file_obsolete(self):
        '''Test check_snappy_framework_file_obsolete()'''
        self.set_test_pkg_yaml("type", "framework")
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_file_obsolete()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_snappy_framework_depends(self):
        '''Test check_snappy_framework_depends)'''
        self.set_test_pkg_yaml("type", "framework")
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_depends()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_snappy_framework_depends(self):
        '''Test check_snappy_framework_depends)'''
        self.set_test_pkg_yaml("type", "framework")
        self.set_test_pkg_yaml("frameworks", ['foo'])
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_depends()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
