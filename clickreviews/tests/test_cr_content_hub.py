'''test_cr_content_hub.py: tests for the cr_content-hub module'''
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

from clickreviews.cr_content_hub import ClickReviewContentHub
import clickreviews.cr_tests as cr_tests


class TestClickReviewContentHub(cr_tests.TestClickReview):
    """Tests for the lint review tool."""

    def test_check_unknown_keys_none(self):
        '''Test check_unknown() - no unknown'''
        self.set_test_content_hub(self.default_appname, "source", "pictures")
        c = ClickReviewContentHub(self.test_name)
        c.check_unknown_keys()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_unknown_keys1(self):
        '''Test check_unknown() - one unknown'''
        self.set_test_content_hub(self.default_appname, "nonexistent", "foo")
        c = ClickReviewContentHub(self.test_name)
        c.check_unknown_keys()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_unknown_keys2(self):
        '''Test check_unknown() - good with one unknown'''
        self.set_test_content_hub(self.default_appname, "source", "pictures")
        self.set_test_content_hub(self.default_appname, "nonexistent", "foo")
        c = ClickReviewContentHub(self.test_name)
        c.check_unknown_keys()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_valid_source(self):
        '''Test check_valid() - source'''
        self.set_test_content_hub(self.default_appname, "source", "pictures")
        c = ClickReviewContentHub(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_valid_share(self):
        '''Test check_valid() - share'''
        self.set_test_content_hub(self.default_appname, "share", "pictures")
        c = ClickReviewContentHub(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_valid_destination(self):
        '''Test check_valid() - destination'''
        self.set_test_content_hub(self.default_appname,
                                  "destination", "pictures")
        c = ClickReviewContentHub(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_valid_all(self):
        '''Test check_valid() - all'''
        self.set_test_content_hub(self.default_appname,
                                  "destination", "pictures")
        self.set_test_content_hub(self.default_appname,
                                  "share", "pictures")
        self.set_test_content_hub(self.default_appname, "source", "pictures")
        c = ClickReviewContentHub(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': 6, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_valid_bad_value(self):
        '''Test check_valid() - bad value'''
        self.set_test_content_hub(self.default_appname, "destination", [])
        c = ClickReviewContentHub(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_valid_empty_value(self):
        '''Test check_valid() - empty value'''
        self.set_test_content_hub(self.default_appname, "source", "")
        c = ClickReviewContentHub(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks(self):
        '''Test check_peer_hooks()'''
        self.set_test_content_hub(self.default_appname,
                                  "destination", "pictures")
        self.set_test_content_hub(self.default_appname, "share", "pictures")
        self.set_test_content_hub(self.default_appname, "source", "pictures")

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["content-hub"] = \
            self.test_manifest["hooks"][self.default_appname]["content-hub"]

        self.test_manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        #  do the test
        c = ClickReviewContentHub(self.test_name)

        c.check_peer_hooks()
        r = c.click_report
        # We should end up with 2 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_disallowed(self):
        '''Test check_peer_hooks() - disallowed'''
        self.set_test_content_hub(self.default_appname,
                                  "destination", "pictures")
        self.set_test_content_hub(self.default_appname, "share", "pictures")
        self.set_test_content_hub(self.default_appname, "source", "pictures")
        c = ClickReviewContentHub(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["content-hub"] = \
            self.test_manifest["hooks"][self.default_appname]["content-hub"]

        # add something not allowed
        tmp["nonexistent"] = "nonexistent-hook"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        #  do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_valid_snappy_1504(self):
        '''Test check_valid() - snappy 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_content_hub(self.default_appname,
                                  "destination", "pictures")
        self.set_test_content_hub(self.default_appname, "share", "pictures")
        self.set_test_content_hub(self.default_appname, "source", "pictures")
        c = ClickReviewContentHub(self.test_name)
        c.check_valid()
        r = c.click_report
        expected_counts = {'info': 6, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)
