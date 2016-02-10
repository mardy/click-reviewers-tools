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
    """Tests for the framework review tool."""
    def setUp(self):
        super().setUp()
        self.set_test_pkgfmt("snap", "15.04")

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
        '''Test check_snappy_framework_depends()'''
        self.set_test_pkg_yaml("type", "framework")
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_depends()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_snappy_framework_depends_bad(self):
        '''Test check_snappy_framework_depends() - bad'''
        self.set_test_pkg_yaml("type", "framework")
        self.set_test_pkg_yaml("frameworks", ['foo'])
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_depends()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy(self):
        '''Test check_snappy_framework_policy()'''
        self.set_test_pkg_yaml("type", "framework")
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_missing(self):
        '''Test check_snappy_framework_policy() - missing'''
        self.set_test_pkg_yaml("type", "framework")
        self.set_test_framework_policy({})
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_unknown(self):
        '''Test check_snappy_framework_policy() - unknown'''
        self.set_test_pkg_yaml("type", "framework")
        self.set_test_framework_policy_unknown(['foo/bar/baz'])
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_metadata(self):
        '''Test check_snappy_framework_policy_metadata()'''
        self.set_test_pkg_yaml("type", "framework")
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy_metadata()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_metadata_template(self):
        '''Test check_snappy_framework_policy_metadata() - template missing
           data
        '''
        self.set_test_pkg_yaml("type", "framework")
        tmp = self.test_framework_policy
        tmp['apparmor']['templates']['template-common'] = 'missing data'
        self.set_test_framework_policy(tmp)
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy_metadata()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_metadata_policygroup(self):
        '''Test check_snappy_framework_policy_metadata() - policygroup missing
           data
        '''
        self.set_test_pkg_yaml("type", "framework")
        tmp = self.test_framework_policy
        tmp['seccomp']['policygroups']['policygroup-reserved'] = 'missing data'
        self.set_test_framework_policy(tmp)
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy_metadata()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_matching(self):
        '''Test check_snappy_framework_policy_matching()'''
        self.set_test_pkg_yaml("type", "framework")
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy_matching()
        r = c.click_report
        expected_counts = {'info': 8, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_matching_missing_aa_template(self):
        '''Test check_snappy_framework_policy_matching() - missing aa template
        '''
        self.set_test_pkg_yaml("type", "framework")
        tmp = self.test_framework_policy
        del tmp['apparmor']['templates']['template-common']
        self.set_test_framework_policy(tmp)
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy_matching()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_matching_missing_sc_policygroup(self):
        '''Test check_snappy_framework_policy_matching() - missing sc policy
           group
        '''
        self.set_test_pkg_yaml("type", "framework")
        tmp = self.test_framework_policy
        del tmp['seccomp']['policygroups']['policygroup-reserved']
        self.set_test_framework_policy(tmp)
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy_matching()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_filenames(self):
        '''Test check_snappy_framework_policy_filenames()'''
        self.set_test_pkg_yaml("type", "framework")
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy_filenames()
        r = c.click_report
        expected_counts = {'info': 8, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_filenames_bad(self):
        '''Test check_snappy_framework_policy_filenames() - bad name'''
        self.set_test_pkg_yaml("type", "framework")
        tmp = self.test_framework_policy
        tmp['seccomp']['policygroups']['policygroup-res_erved'] = "foo"
        self.set_test_framework_policy(tmp)
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy_filenames()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_snappy_framework_policy_filenames_bad2(self):
        '''Test check_snappy_framework_policy_filenames() - starts with
           package name
        '''
        self.set_test_pkg_yaml("type", "framework")
        tmp = self.test_framework_policy
        n = self.test_name.split('_')[0]
        tmp['seccomp']['policygroups']['%s-group' % n] = "foo"
        self.set_test_framework_policy(tmp)
        c = ClickReviewFramework(self.test_name)
        c.check_snappy_framework_policy_filenames()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)
