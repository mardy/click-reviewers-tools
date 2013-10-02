'''test_cr_security.py: tests for the cr_security module'''
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

from clickreviews.cr_security import ClickReviewSecurity
import clickreviews.cr_tests as cr_tests


class TestClickReviewSecurity(cr_tests.TestClickReview):
    """Tests for the security lint review tool."""
    def setUp(self):
        #  Monkey patch various file access classes. stop() is handled with
        #  addCleanup in super()
        cr_tests.mock_patch()
        super()

        self.default_security_json = "%s.json" % \
            self.default_appname

    def test_check_policy_version_vendor(self):
        '''Test check_policy_version() - valid'''
        for v in [1.0]:  # update when have more vendor policy
            c = ClickReviewSecurity(self.test_name)
            self.set_test_security_manifest(self.default_appname,
                                            "policy_version", v)
            c.check_policy_version()
            report = c.click_report
            expected_counts = {'info': 2, 'warn': 0, 'error': 0}
            self.check_results(report, expected_counts)

    def test_check_policy_version_highest(self):
        '''Test check_policy_version() - highest'''
        highest_version = 1.0  # system, adjust as needed
        version = 1.0
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", version)
        c.check_policy_version()
        report = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']["security_policy_version_is_%s (%s)" %
                         (highest_version, self.default_security_json)] = "OK"
        self.check_results(report, expected=expected)

    def test_check_policy_version_bad(self):
        '''Test check_policy_version() - bad version'''
        bad_version = 0.1
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", bad_version)
        c.check_policy_version()
        report = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['warn']["security_policy_version_is_1.0 (%s)" %
                         self.default_security_json] = "0.1 != 1.0"
        expected['error']["security_policy_version_exists (%s)" %
                          self.default_security_json] = \
            "could not find policy for ubuntu/%s" % str(bad_version)
        self.check_results(report, expected=expected)

    def test_check_policy_version_unspecified(self):
        '''Test check_policy_version() - bad version'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", None)
        c.check_policy_version()
        report = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['error']["security_policy_version_exists (%s)" %
                          self.default_security_json] = \
            "could not find policy_version in manifest"
        self.check_results(report, expected=expected)

    def test_check_policy_vendor_unspecified(self):
        '''Test check_policy_vendor() - unspecified'''
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_vendor()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_vendor_ubuntu(self):
        '''Test check_policy_vendor() - ubuntu'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu")
        c.check_policy_vendor()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_vendor_nonexistent(self):
        '''Test check_policy_vendor() - nonexistent'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "nonexistent")
        c.check_policy_vendor()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_template_unspecified(self):
        '''Test check_template() - unspecified'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", None)
        c.check_template()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_ubuntu_sdk(self):
        '''Test check_template() - ubuntu-sdk'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-sdk")
        c.check_template()
        report = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']["security_template_with_policy_version (%s)" %
                         self.default_security_json] = "OK"
        expected['info']["security_template_exists (%s)" %
                         self.default_security_json] = "OK"
        expected['warn']["security_template_valid (%s)" %
                         self.default_security_json] = \
            "No need to specify 'ubuntu-sdk' template"
        self.check_results(report, expected=expected)

    def test_check_template_webapp(self):
        '''Test check_template() - webapp'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        c.check_template()
        report = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_unconfined(self):
        '''Test check_template() - unconfined'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "unconfined")
        c.check_template()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_webapps(self):
        '''Test check_policy_groups_webapps()'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["audio",
                                         "location",
                                         "networking",
                                         "video"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_webapps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_webapps_ubuntu_sdk(self):
        '''Test check_policy_groups_webapps() - ubuntu-sdk template'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-sdk")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["audio",
                                         "location",
                                         "networking",
                                         "video"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_webapps()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_webapps_nonexistent(self):
        '''Test check_policy_groups_webapps() - nonexistent'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["networking", "nonexistent"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_webapps()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_webapps_missing(self):
        '''Test check_policy_groups_webapps() - missing'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        None)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_webapps()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_webapps_bad(self):
        '''Test check_policy_groups_webapps() - bad'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["video_files", "networking"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_webapps()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)




    def test_check_policy_groups(self):
        '''Test check_policy_groups()'''
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_multiple(self):
        '''Test check_policy_groups() - multiple'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ['networking',
                                         'audio',
                                         'video'])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_missing_policy_version(self):
        '''Test check_policy_groups() - missing policy_version'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", None)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_missing(self):
        '''Test check_policy_groups() - missing'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        None)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_bad_policy_version(self):
        '''Test check_policy_groups() - bad policy_version'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 0.1)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_bad_policy_vendor(self):
        '''Test check_policy_groups() - bad policy_vendor'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "nonexistent")
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_nonexistent(self):
        '''Test check_policy_groups_webapps() - nonexistent'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["networking", "nonexistent"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_reserved(self):
        '''Test check_policy_groups_webapps() - reserved'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["video_files", "networking"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_empty(self):
        '''Test check_policy_groups_webapps() - empty'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["", "networking"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)
