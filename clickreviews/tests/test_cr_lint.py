'''test_cr_lint.py: tests for the cr_lint module'''
#
# Copyright (C) 2013-2014 Canonical Ltd.
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
from clickreviews.frameworks import FRAMEWORKS_DATA_URL, USER_DATA_FILE
import clickreviews.cr_tests as cr_tests


class TestClickReviewLint(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def patch_frameworks(self):
        def _mock_frameworks(self, overrides=None):
            self.FRAMEWORKS = {
                'ubuntu-sdk-14.10-qml-dev2': 'available',
                'ubuntu-sdk-13.10': 'deprecated',
                'ubuntu-sdk-14.10-qml-dev1': 'obsolete',
            }
            self.AVAILABLE_FRAMEWORKS = ['ubuntu-sdk-14.10-qml-dev2']
            self.OBSOLETE_FRAMEWORKS = ['ubuntu-sdk-14.10-qml-dev1']
            self.DEPRECATED_FRAMEWORKS = ['ubuntu-sdk-13.10']
        p = patch('clickreviews.frameworks.Frameworks.__init__',
                  _mock_frameworks)
        p.start()
        self.addCleanup(p.stop)

    def test_check_architecture(self):
        '''Test check_architecture()'''
        c = ClickReviewLint(self.test_name)
        c.check_architecture()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architecture_all(self):
        '''Test check_architecture_all() - no binaries'''
        self.set_test_control("Architecture", "all")
        self.set_test_manifest("architecture", "all")
        c = ClickReviewLint(self.test_name)
        c.pkg_bin_files = []
        c.check_architecture_all()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architecture_all2(self):
        '''Test check_architecture_all() - binaries'''
        self.set_test_control("Architecture", "all")
        self.set_test_manifest("architecture", "all")
        c = ClickReviewLint(self.test_name)
        c.pkg_bin_files = ["path/to/some/compiled/binary"]
        c.check_architecture_all()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_architecture_armhf(self):
        '''Test check_architecture() - armhf'''
        self.set_test_control("Architecture", "armhf")
        c = ClickReviewLint(self.test_name)
        c.check_architecture()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architecture_i386(self):
        '''Test check_architecture() - i386'''
        self.set_test_control("Architecture", "i386")
        c = ClickReviewLint(self.test_name)
        c.check_architecture()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architecture_amd64(self):
        '''Test check_architecture() - amd64'''
        self.set_test_control("Architecture", "amd64")
        c = ClickReviewLint(self.test_name)
        c.check_architecture()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architecture_nonexistent(self):
        '''Test check_architecture() - nonexistent'''
        self.set_test_control("Architecture", "nonexistent")
        c = ClickReviewLint(self.test_name)
        c.check_architecture()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_control_architecture(self):
        '''Test check_control() (architecture)'''
        c = ClickReviewLint(self.test_name)
        c.check_control()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
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
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_control_mismatches_manifest_architecture(self):
        '''Test check_control() (architecture mismatches manifest)'''
        self.set_test_control("Architecture", "armhf")
        self.set_test_manifest("architecture", "amd64")
        c = ClickReviewLint(self.test_name)
        c.check_control()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
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
            {"text": "OK: architecture not specified in manifest"}
        self.check_results(r, expected=expected)

    def test_check_architecture_specified_needed(self):
        '''Test check_architecture_specified_needed() - no binaries'''
        self.set_test_control("Architecture", "armhf")
        self.set_test_manifest("architecture", "armhf")
        c = ClickReviewLint(self.test_name)
        c.pkg_bin_files = []
        c.check_architecture_specified_needed()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_architecture_specified_needed2(self):
        '''Test check_architecture_specified_needed2() - binaries'''
        self.set_test_control("Architecture", "armhf")
        self.set_test_manifest("architecture", "armhf")
        c = ClickReviewLint(self.test_name)
        c.pkg_bin_files = ["path/to/some/compiled/binary"]
        c.check_architecture_specified_needed()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_package_filename(self):
        '''Test check_package_filename()'''
        c = ClickReviewLint(self.test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_package_filename_missing_version(self):
        '''Test check_package_filename() - missing version'''
        test_name = "%s_%s.click" % (self.test_control['Package'],
                                     self.test_control['Architecture'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 3, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_package_filename_missing_arch(self):
        '''Test check_package_filename() - missing arch'''
        test_name = "%s_%s.click" % (self.test_control['Package'],
                                     self.test_control['Version'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 3, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_package_filename_missing_package(self):
        '''Test check_package_filename() - missing package'''
        test_name = "%s_%s.click" % (self.test_control['Version'],
                                     self.test_control['Architecture'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 3, 'error': 3}
        self.check_results(r, expected_counts)

    def test_check_package_filename_extra_underscore(self):
        '''Test check_package_filename() - extra underscore'''
        test_name = "_%s_%s_%s.click" % (self.test_control['Package'],
                                         self.test_control['Version'],
                                         self.test_control['Architecture'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 2, 'error': 4}
        self.check_results(r, expected_counts)

    def test_check_package_filename_control_mismatches(self):
        '''Test check_package_filename() (control mismatches filename)'''
        self.set_test_control("Package", "test-match")
        c = ClickReviewLint(self.test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_package_filename_namespace_mismatches(self):
        '''Test check_package_filename() (control mismatches filename)'''
        test_name = "%s_%s_%s.click" % ("com.example.someuser",
                                        self.test_control['Version'],
                                        self.test_control['Architecture'])
        c = ClickReviewLint(test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

    def test_check_package_filename_version_mismatches(self):
        '''Test check_package_filename() (version mismatches filename)'''
        self.set_test_control("Version", "100.1.1")
        c = ClickReviewLint(self.test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
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
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
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
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_missing_arch(self):
        '''Test check_manifest_architecture() (missing)'''
        self.set_test_manifest("architecture", None)
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_all(self):
        '''Test check_manifest_architecture() (all)'''
        self.set_test_manifest("architecture", "all")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_single_armhf(self):
        '''Test check_manifest_architecture() (single arch, armhf)'''
        self.set_test_manifest("architecture", "armhf")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_single_i386(self):
        '''Test check_manifest_architecture() (single arch, i386)'''
        self.set_test_manifest("architecture", "i386")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_single_amd64(self):
        '''Test check_manifest_architecture() (single arch, amd64)'''
        self.set_test_manifest("architecture", "amd64")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_single_nonexistent(self):
        '''Test check_manifest_architecture() (single nonexistent arch)'''
        self.set_test_manifest("architecture", "nonexistent")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_arch_single_multi(self):
        '''Test check_manifest_architecture() (single arch: invalid multi)'''
        self.set_test_manifest("architecture", "multi")
        c = ClickReviewLint(self.test_name)
        c.check_manifest_architecture()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
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
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
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
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
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
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
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
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
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
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_package_filename_with_extra_click(self):
        """Test namespaces with the word "click" in them."""
        c = ClickReviewLint(self.test_name)
        c.check_package_filename()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_control(self):
        """A very basic test to make sure check_control can be tested."""
        c = ClickReviewLint(self.test_name)
        c.check_control()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
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
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
        # Lets check that the right error is triggering
        m = r['error']['lint_control_click_version_up_to_date']['text']
        self.assertIn('Click-Version is too old', m)

    def test_check_maintainer(self):
        '''Test check_maintainer()'''
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_maintainer_non_default(self):
        '''Test check_maintainer() - non-default'''
        self.set_test_control("Package", "com.example.app")
        self.set_test_manifest("maintainer",
                               "Foo User <user@example.com>")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_maintainer_non_match(self):
        '''Test check_maintainer() - non-match'''
        self.set_test_control("Package", "com.example.app")
        self.set_test_manifest("maintainer",
                               "Foo User <user@foo.com>")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_maintainer_empty(self):
        '''Test check_maintainer() - empty'''
        self.set_test_manifest("maintainer", "")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_maintainer_missing(self):
        '''Test check_maintainer() - missing'''
        self.set_test_manifest("maintainer", None)
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_maintainer_badformat(self):
        '''Test check_maintainer() - badly formatted'''
        self.set_test_manifest("maintainer", "$%^@*")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_maintainer_bad_email_missing_name(self):
        '''Test check_maintainer() - bad email (missing name)'''
        self.set_test_manifest("name", "com.ubuntu.developer.user.app")
        self.set_test_manifest("maintainer",
                               "user@example.com")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_maintainer_bad_email_short_domain(self):
        '''Test check_maintainer() - bad email (short domain)'''
        self.set_test_control("Package", "com.example.app")
        self.set_test_manifest("maintainer",
                               "Foo User <user@com>")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
        self.check_manual_review(r, 'lint_maintainer_domain')

    def test_check_maintainer_bad_email_long_domain(self):
        '''Test check_maintainer() - bad email (long domain)'''
        self.set_test_control("Package", "com.example.app")
        self.set_test_manifest("maintainer",
                               "Foo User <user@foo.example.com>")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
        self.check_manual_review(r, 'lint_maintainer_domain')

    def test_check_maintainer_domain_appstore(self):
        '''Test check_maintainer() - appstore domain
           (com.ubuntu.developer)'''
        self.set_test_manifest("name", "com.ubuntu.developer.user.app")
        self.set_test_manifest("maintainer",
                               "Foo User <user@example.com>")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_maintainer_domain_special(self):
        '''Test check_maintainer() - special (com.facebook)'''
        self.set_test_control("Package", "com.facebook.app")
        self.set_test_manifest("maintainer",
                               "Foo User <user@facebook.com>")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_maintainer_email_special(self):
        '''Test check_maintainer() - ubuntu-devel-discuss@lists.ubuntu.com'''
        self.set_test_control("Package", "com.canonical.app")
        self.set_test_manifest("maintainer",
                               "Ubuntu Core Developers "
                               "<ubuntu-devel-discuss@lists.ubuntu.com>")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']['lint_maintainer_domain'] = \
            {"text": "OK (email 'ubuntu-devel-discuss@lists.ubuntu.com' long, "
             "but special case"}
        self.check_results(r, expected=expected)

    def test_check_maintainer_email_special2(self):
        '''Test check_maintainer() - ubuntu-devel-discuss@lists.ubuntu.com'''
        self.set_test_control("Package", "com.ubuntu.scopes.youtube")
        self.set_test_manifest("maintainer",
                               "Ubuntu Core Developers "
                               "<ubuntu-devel-discuss@lists.ubuntu.com>")
        c = ClickReviewLint(self.test_name)
        c.check_maintainer()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']['lint_maintainer_domain'] = \
            {"text": "OK ('com.ubuntu.scopes' uses "
             "'ubuntu-devel-discuss@lists.ubuntu.com' as email)"}
        self.check_results(r, expected=expected)

    def test_check_icon(self):
        '''Test check_icon()'''
        self.set_test_manifest("icon", "someicon")
        c = ClickReviewLint(self.test_name)
        c.check_icon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_icon_unspecified(self):
        '''Test check_icon()'''
        self.set_test_manifest("icon", None)
        c = ClickReviewLint(self.test_name)
        c.check_icon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_icon_empty(self):
        '''Test check_icon() - empty'''
        self.set_test_manifest("icon", "")
        c = ClickReviewLint(self.test_name)
        c.check_icon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_icon_absolute_path(self):
        '''Test check_icon() - absolute path'''
        self.set_test_manifest("icon", "/foo/bar/someicon")
        c = ClickReviewLint(self.test_name)
        c.check_icon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_click_local_extensions_missing(self):
        '''Testeck_click_local_extensions() - missing'''
        for k in self.test_manifest.keys():
            if k.startswith("x-"):
                self.set_test_manifest(k, None)
        c = ClickReviewLint(self.test_name)
        c.check_click_local_extensions()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_click_local_extensions_empty(self):
        '''Testeck_click_local_extensions() - empty'''
        for k in self.test_manifest.keys():
            if k.startswith("x-"):
                self.set_test_manifest(k, None)
        self.set_test_manifest("x-test", "")
        c = ClickReviewLint(self.test_name)
        c.check_click_local_extensions()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_click_local_extensions(self):
        '''Testeck_click_local_extensions()'''
        for k in self.test_manifest.keys():
            if k.startswith("x-"):
                self.set_test_manifest(k, None)
        self.set_test_manifest("x-source", {"vcs-bzr": "lp:notes-app",
                                            "vcs-bzr-revno": "209"})
        c = ClickReviewLint(self.test_name)
        c.check_click_local_extensions()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_click_local_extensions_coreapp(self):
        '''Testeck_click_local_extensions() - coreapp'''
        for k in self.test_manifest.keys():
            if k.startswith("x-"):
                self.set_test_manifest(k, None)
        self.set_test_manifest("x-source", "foo")
        c = ClickReviewLint(self.test_name)
        c.is_core_app = True
        c.check_click_local_extensions()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_framework(self):
        '''Test check_framework()'''
        self.patch_frameworks()
        self.set_test_manifest("framework", "ubuntu-sdk-14.10-qml-dev2")
        c = ClickReviewLint(self.test_name)
        c.check_framework()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    @patch('clickreviews.remote.read_cr_file')
    def test_check_framework_fetches_remote_data(self, mock_read_cr_file):
        '''Test check_framework()'''
        mock_read_cr_file.return_value = {
            'ubuntu-sdk-14.10-qml-dev2': 'available',
        }
        self.set_test_manifest("framework", "ubuntu-sdk-14.10-qml-dev2")
        c = ClickReviewLint(self.test_name)
        c.check_framework()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)
        # ensure no local fn is provided when reading frameworks
        mock_read_cr_file.assert_called_once_with(
            USER_DATA_FILE, FRAMEWORKS_DATA_URL)

    def test_check_framework_bad(self):
        '''Test check_framework() - bad'''
        self.patch_frameworks()
        self.set_test_manifest("framework", "nonexistent")
        c = ClickReviewLint(self.test_name)
        c.check_framework()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_framework_deprecated(self):
        '''Test check_framework() - deprecated'''
        self.patch_frameworks()
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        c.check_framework()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_framework_obsolete(self):
        '''Test check_framework() - obsolete'''
        self.patch_frameworks()
        self.set_test_manifest("framework", "ubuntu-sdk-14.10-qml-dev1")
        c = ClickReviewLint(self.test_name)
        c.check_framework()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    @patch('clickreviews.remote.read_cr_file')
    def test_check_framework_with_overrides(self, mock_read_cr_file):
        '''Test check_framework() - using overrides'''
        mock_read_cr_file.return_value = {
            'ubuntu-sdk-14.10-qml-dev2': 'available',
        }
        self.set_test_manifest("framework", "nonexistent")
        overrides = {'framework': {'nonexistent': {'state': 'available'}}}
        c = ClickReviewLint(self.test_name, overrides=overrides)
        c.check_framework()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_hooks(self):
        '''Test check_hooks()'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        c.check_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_hooks_multiple_desktop_apps(self):
        '''Test check_hooks() - multiple desktop apps'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        tmp = c.manifest['hooks'][self.default_appname]
        c.manifest['hooks']["another-app"] = tmp
        c.check_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_hooks_multiple_apps(self):
        '''Test check_hooks() - multiple non-desktop apps'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        tmp = dict()
        for k in c.manifest['hooks'][self.default_appname].keys():
            tmp[k] = c.manifest['hooks'][self.default_appname][k]
        tmp.pop('desktop')
        tmp['scope'] = "some-scope-exec"
        c.manifest['hooks']["some-scope"] = tmp
        tmp = dict()
        for k in c.manifest['hooks'][self.default_appname].keys():
            tmp[k] = c.manifest['hooks'][self.default_appname][k]
        tmp.pop('desktop')
        tmp['push-helper'] = "push.json"
        c.manifest['hooks']["some-push-helper"] = tmp

        c.check_hooks()
        r = c.click_report
        expected_counts = {'info': 13, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_hooks_security_extension(self):
        '''Test check_hooks() - security extension'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        tmp = dict()
        for k in c.manifest['hooks'][self.default_appname].keys():
            tmp[k] = c.manifest['hooks'][self.default_appname][k]
        tmp['apparmor'] = "%s.json" % self.default_appname
        c.manifest['hooks'][self.default_appname] = tmp

        c.check_hooks()
        r = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']['lint_sdk_security_extension_test-app'] = \
            {"text": "test-app.json does not end with .apparmor (ok if not "
                     "using sdk)"}
        self.check_results(r, expected=expected)

    def test_check_hooks_bad_appname(self):
        '''Test check_hooks() - bad appname'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        tmp = c.manifest['hooks'][self.default_appname]
        del c.manifest['hooks'][self.default_appname]
        c.manifest['hooks']["b@d@ppn@m#"] = tmp
        c.check_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_hooks_missing_apparmor(self):
        '''Test check_hooks() - missing apparmor'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        del c.manifest['hooks'][self.default_appname]['apparmor']
        c.check_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_hooks_has_desktop_and_scope(self):
        '''Test check_hooks() - desktop with scope'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        c.manifest['hooks'][self.default_appname]["scope"] = "some-binary"
        c.check_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_hooks_unknown_nonexistent(self):
        '''Test check_hooks_unknown() - nonexistent'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        c.manifest['hooks'][self.default_appname]["nonexistant"] = "foo"
        c.check_hooks_unknown()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_hooks_unknown_good(self):
        '''Test check_hooks_unknown()'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        c.check_hooks_unknown()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_hooks_redflagged(self):
        '''Test check_hooks_redflagged()'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        c = ClickReviewLint(self.test_name)
        c.manifest['hooks'][self.default_appname]["pay-ui"] = "foo"
        c.check_hooks_redflagged()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
        self.check_manual_review(r, 'lint_hooks_redflag_test-app')
