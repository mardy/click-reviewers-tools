'''test_cr_skeleton.py: tests for the cr_skeleton module'''
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

from clickreviews.cr_skeleton import ClickReviewSkeleton
import clickreviews.cr_tests as cr_tests


class TestClickReviewSkeleton(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def test_check_foo(self):
        '''Test check_foo()'''
        c = ClickReviewSkeleton(self.test_name)
        c.check_foo()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_bar(self):
        '''Test check_bar()'''
        c = ClickReviewSkeleton(self.test_name)
        c.check_bar()
        r = c.click_report
        # We should end up with 1 error
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_baz(self):
        '''Test check_baz()'''
        c = ClickReviewSkeleton(self.test_name)
        c.check_baz()
        r = c.click_report
        # We should end up with 1 warning
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

        # Check specific entries
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['warn']['skeleton_baz'] = {"text": "TODO",
                                            "link": "http://example.com"}
        expected['error'] = dict()
        self.check_results(r, expected=expected)

    def test_output(self):
        '''Test output'''
        # Update the control field and output the changes
        self.set_test_control('Package', "my.mock.app.name")
        self.set_test_manifest('name', "my.mock.app.name")
        self._update_test_name()

        import pprint
        import json
        print('''
= test output =
== Mock filename ==
%s

== Mock control ==
%s
== Mock manifest ==''' % (self.test_name, cr_tests.TEST_CONTROL))

        pprint.pprint(json.loads(cr_tests.TEST_MANIFEST))
