'''test_cr_lint.py: tests for the cr_lint module'''
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

from unittest.mock import patch

from clickreviews.cr_lint import ClickReviewLint
from clickreviews.cr_lint import MINIMUM_CLICK_FRAMEWORK_VERSION
import clickreviews.cr_tests as cr_tests

class TestClickReviewLint(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def test_check_architecture(self):
        '''Test check_architecture()'''
        c = ClickReviewLint(self.test_name)
        c.check_architecture()
        r = c.click_report
        expected_counts={'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architecture_all(self):
        '''TODO: Test check_architecture_all()'''
        # This needs a real click package rather than a mocked up one

    def test_check_architecture_nonexistent(self):
        '''Test check_architecture() - nonexistent'''
        self.set_test_control("Architecture", "nonexistent")
        c = ClickReviewLint(self.test_name)
        c.check_architecture()
        r = c.click_report
        expected_counts={'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_control_architecture(self):
        '''Test check_control() (architecture)'''
        c = ClickReviewLint(self.test_name)
        c.check_control()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_control_architecture_missing(self):
        '''Test check_control() (architecture missing)'''
        self.set_test_control("Architecture", None)
        try:
            ClickReviewLint(self.test_name)
        except KeyError:
            return
        raise Exception("Should have raised a KeyError")

    def test_check_control_matches_manifest_architecture(self):
        '''Test check_control() (architecture matches manifest)'''
        self.set_test_control("Architecture", "armhf")
        self.set_test_manifest("architecture", "armhf")
        c = ClickReviewLint(self.test_name)
        c.check_control()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_control_mismatches_manifest_architecture(self):
        '''Test check_control() (architecture mismatches manifest)'''
        self.set_test_control("Architecture", "armhf")
        self.set_test_manifest("architecture", "amd64")
        c = ClickReviewLint(self.test_name)
        c.check_control()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_control_manifest_architecture_missing(self):
        '''Test check_control() (manifest architecture)'''
        self.set_test_control("Architecture", "armhf")
        self.set_test_manifest("architecture", None)
        c = ClickReviewLint(self.test_name)
        c.check_control()
        r = c.click_report

        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']["lint_control_architecture_match"] = \
            "OK: architecture not specified in manifest"
        self.check_results(r, expected=expected)

    def test_check_package_filename(self):
        '''Test check_package_filename()'''
        c = ClickReviewLint(self.test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_package_filename_missing_version(self):
        '''Test check_package_filename() - missing version'''
        test_name = "%s_%s.click" % (self.test_control['Package'],
                                     self.test_control['Architecture'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 3, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_package_filename_missing_arch(self):
        '''Test check_package_filename() - missing arch'''
        test_name = "%s_%s.click" % (self.test_control['Package'],
                                     self.test_control['Version'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 3, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_package_filename_missing_package(self):
        '''Test check_package_filename() - missing package'''
        test_name = "%s_%s.click" % (self.test_control['Version'],
                                     self.test_control['Architecture'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 3, 'error': 3}
        self.check_results(r, expected_counts)

    def test_check_package_filename_extra_underscore(self):
        '''Test check_package_filename() - extra underscore'''
        test_name = "_%s_%s_%s.click" % (self.test_control['Package'],
                                         self.test_control['Version'],
                                         self.test_control['Architecture'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 2, 'error': 4}
        self.check_results(r, expected_counts)

    def test_check_package_filename_control_mismatches(self):
        '''Test check_package_filename() (control mismatches filename)'''
        self.set_test_control("Package", "test-match")
        c = ClickReviewLint(self.test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_package_filename_namespace_mismatches(self):
        '''Test check_package_filename() (control mismatches filename)'''
        test_name = "%s_%s_%s.click" % ("com.example.someuser",
                                        self.test_control['Version'],
                                        self.test_control['Architecture'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

    def test_check_package_filename_version_mismatches(self):
        '''Test check_package_filename() (version mismatches filename)'''
        self.set_test_control("Version", "100.1.1")
        c = ClickReviewLint(self.test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_package_filename_valid_arch(self):
        '''Test check_package_filename() (valid arch)'''
        arch = "armhf"
        self.set_test_control("Architecture", arch)
        test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                        self.test_control['Version'],
                                        self.test_control['Architecture'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_package_filename_valid_arch_multi(self):
        '''Test check_package_filename() (valid multi arch)'''
        arch = "multi"
        self.set_test_control("Architecture", arch)
        test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                        self.test_control['Version'],
                                        arch)
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_missing_arch(self):
        '''Test check_manifest_architecture() (missing)'''
        self.set_test_manifest("architecture", None)
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts={'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_all(self):
        '''Test check_manifest_architecture() (all)'''
        self.set_test_manifest("architecture", "all")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts={'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_single(self):
        '''Test check_manifest_architecture() (single arch)'''
        self.set_test_manifest("architecture", "armhf")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts={'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_single_nonexistent(self):
        '''Test check_manifest_architecture() (single nonexistent arch)'''
        self.set_test_manifest("architecture", "nonexistent")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts={'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_single_multi(self):
        '''Test check_manifest_architecture() (single arch: invalid multi)'''
        self.set_test_manifest("architecture", "multi")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts={'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_valid_arch_multi(self):
        '''Test check_manifest_architecture() (valid multi)'''
        arch = "multi"
        self.set_test_manifest("architecture", ["armhf"])
        self.set_test_control("Architecture", arch)
        test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                        self.test_control['Version'],
                                        arch)
        c = ClickReviewLint(test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts={'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_invalid_arch_multi_nonexistent(self):
        '''Test check_manifest_architecture() (invalid multi)'''
        arch = "multi"
        self.set_test_manifest("architecture", ["armhf", "nonexistent"])
        self.set_test_control("Architecture", arch)
        test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                        self.test_control['Version'],
                                        arch)
        c = ClickReviewLint(test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts={'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_invalid_arch_multi_all(self):
        '''Test check_manifest_architecture() (invalid all)'''
        arch = "multi"
        self.set_test_manifest("architecture", ["armhf", "all"])
        self.set_test_control("Architecture", arch)
        test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                        self.test_control['Version'],
                                        arch)
        c = ClickReviewLint(test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts={'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_invalid_arch_multi_multi(self):
        '''Test check_manifest_architecture() (invalid multi)'''
        arch = "multi"
        self.set_test_manifest("architecture", ["multi", "armhf"])
        self.set_test_control("Architecture", arch)
        test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                        self.test_control['Version'],
                                        arch)
        c = ClickReviewLint(test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts={'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)


    def test_check_package_filename_mismatch_arch(self):
        '''Test check_package_filename() (control mismatches arch)'''
        arch = "armhf"
        self.set_test_control("Architecture", "all")
        test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                        self.test_control['Version'],
                                        arch)
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_package_filename_with_extra_click(self):
        """Test namespaces with the word "click" in them."""
        c = ClickReviewLint(self.test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_control(self):
        """A very basic test to make sure check_control can be tested."""
        c = ClickReviewLint(self.test_name)
        c.check_control()
        r = c.click_report
        expected_counts={'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    # Make the current MINIMUM_CLICK_FRAMEWORK_VERSION newer
    @patch('clickreviews.cr_lint.MINIMUM_CLICK_FRAMEWORK_VERSION',
        MINIMUM_CLICK_FRAMEWORK_VERSION + '.1')
    def test_check_control_click_framework_version(self):
        """Test that enforcing click framework versions works."""
        test_name = 'net.launchpad.click-webapps.test-app_3_all.click'
        c = ClickReviewLint(test_name)
        c.check_control()
        r = c.click_report
        # We should end up with an error as the click version is out of date
        expected_counts={'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
        # Lets check that the right error is triggering
        self.assertIn('Click-Version is too old',
            r['error']['lint_control_click_version_up_to_date'])
