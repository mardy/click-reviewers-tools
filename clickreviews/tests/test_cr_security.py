'''test_cr_security.py: tests for the cr_security module'''
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

from __future__ import print_function
import sys

from clickreviews.cr_security import ClickReviewSecurity
import clickreviews.cr_tests as cr_tests


class TestClickReviewSecurity(cr_tests.TestClickReview):
    """Tests for the security lint review tool."""
    def setUp(self):
        #  Monkey patch various file access classes. stop() is handled with
        #  addCleanup in super()
        cr_tests.mock_patch()
        super()

        self.default_security_json = "%s.apparmor" % \
            self.default_appname

    def test_check_policy_version_vendor(self):
        '''Test check_policy_version() - valid'''
        for v in [1.0]:  # update when have more vendor policy
            c = ClickReviewSecurity(self.test_name)
            self.set_test_security_manifest(self.default_appname,
                                            "policy_version", v)
            c.check_policy_version()
            report = c.click_report
            expected_counts = {'info': 3, 'warn': 0, 'error': 0}
            self.check_results(report, expected_counts)

    def test_check_policy_version_highest(self):
        '''Test check_policy_version() - highest'''
        c = ClickReviewSecurity(self.test_name)
        highest_version = c._get_highest_policy_version("ubuntu")
        version = highest_version
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", version)
        c.check_policy_version()
        report = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']["security_policy_version_is_highest (%s, %s)" %
                         (highest_version, self.default_security_json)] = \
            {"text": "OK"}
        self.check_results(report, expected=expected)

    def test_check_policy_version_bad(self):
        '''Test check_policy_version() - bad version'''
        bad_version = 0.1
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", bad_version)

        highest = c._get_highest_policy_version("ubuntu")

        c.check_policy_version()
        report = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']["security_policy_version_is_highest (%s, %s)" % (
                         highest,
                         self.default_security_json)] = \
            {"text": "0.1 != %s" % highest}
        expected['error']["security_policy_version_exists (%s)" %
                          self.default_security_json] = \
            {"text": "could not find policy for ubuntu/%s" % str(bad_version)}
        self.check_results(report, expected=expected)

    def test_check_policy_version_low(self):
        '''Test check_policy_version() - low version'''
        c = ClickReviewSecurity(self.test_name)
        highest = c._get_highest_policy_version("ubuntu")
        version = 1.0
        if version == highest:
            print("SKIPPED-- test version '%s' is already highest" % version,
                  file=sys.stderr)
            return

        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", version)

        c.check_policy_version()
        report = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']["security_policy_version_is_highest (%s, %s)" % (
                         highest,
                         self.default_security_json)] = \
            {"text": "%s != %s" % (version, highest)}
        self.check_results(report, expected=expected)

    def test_check_policy_version_unspecified(self):
        '''Test check_policy_version() - unspecified'''
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
            {"text": "could not find policy_version in manifest"}
        self.check_results(report, expected=expected)

    def test_check_policy_version_framework(self):
        '''Test check_policy_version() - matching framework'''
        tmp = ClickReviewSecurity(self.test_name)
        # for each installed framework on the system, verify that the policy
        # matches the framework
        for f in tmp.valid_frameworks:
            self.set_test_manifest("framework", f)
            policy_version = 0
            for k in tmp.major_framework_policy.keys():
                if f.startswith(k):
                    policy_version = tmp.major_framework_policy[k]['policy_version']
            self.set_test_security_manifest(self.default_appname,
                                            "policy_version",
                                            policy_version)
            c = ClickReviewSecurity(self.test_name)
            c.check_policy_version()
            report = c.click_report
            expected_counts = {'info': 3, 'warn': 0, 'error': 0}
            self.check_results(report, expected_counts)

    def test_check_policy_version_framework_unmatch(self):
        '''Test check_policy_version() - unmatching framework (lower)'''
        self.set_test_manifest("framework", "ubuntu-sdk-14.04")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 1.0)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_version()
        report = c.click_report

        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['error']["security_policy_version_matches_framework (%s)" %
                          self.default_security_json] = \
            {"text": "1.0 != 1.1 (ubuntu-sdk-14.04)"}
        self.check_results(report, expected=expected)

    def test_check_policy_version_framework_unmatch2(self):
        '''Test check_policy_version() - unmatching framework (higher)'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 1.1)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_version()
        report = c.click_report

        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['error']["security_policy_version_matches_framework (%s)" %
                          self.default_security_json] = \
            {"text": "1.1 != 1.0 (ubuntu-sdk-13.10)"}
        self.check_results(report, expected=expected)

    def test_check_policy_version_framework_unmatch3(self):
        '''Test check_policy_version() - unmatching framework (nonexistent)'''
        self.set_test_manifest("framework", "nonexistent")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 1.1)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_version()
        report = c.click_report

        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['error']["security_policy_version_matches_framework (%s)" %
                          self.default_security_json] = \
            {"text": "Invalid framework 'nonexistent'"}
        self.check_results(report, expected=expected)

    def test_check_policy_version_framework_with_overrides(self):
        '''Test check_policy_version() - override framework (nonexistent)'''
        self.set_test_manifest("framework", "nonexistent")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 1.3)
        overrides = {'framework': {'nonexistent': {'state': 'available',
                                                   'policy_vendor': 'ubuntu',
                                                   'policy_version': 1.3}}}
        c = ClickReviewSecurity(self.test_name, overrides=overrides)
        c.check_policy_version()
        report = c.click_report

        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_version_framework_with_malformed_overrides(self):
        '''Test check_policy_version() - incorrectly override framework'''
        self.set_test_manifest("framework", "nonexistent")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 999999999.3)
        overrides = {'nonexistent': {'state': 'available',
                                     'policy_vendor': 'ubuntu',
                                     'policy_version': 999999999.3}}
        c = ClickReviewSecurity(self.test_name, overrides=overrides)
        c.check_policy_version()
        report = c.click_report

        expected_counts = {'info': 1, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)

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

    def test_check_policy_vendor_ubuntu_snappy(self):
        '''Test check_policy_vendor() - ubuntu-snappy'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu-snappy")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 1.3)
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
                         self.default_security_json] = {"text": "OK"}
        expected['info']["security_template_exists (%s)" %
                         self.default_security_json] = {"text": "OK"}
        expected['warn']["security_template_valid (%s)" %
                         self.default_security_json] = \
            {"text": "No need to specify 'ubuntu-sdk' template"}
        self.check_results(report, expected=expected)

    def test_check_template_default(self):
        '''Test check_template() - default specified with no vendor'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "default")
        c.check_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_default_with_ubuntu(self):
        '''Test check_template() - default specified with ubuntu vendor'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "default")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu")
        c.check_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_default_with_snappy(self):
        '''Test check_template() - default specified with ubuntu-snappy vendor'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "default")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu-snappy")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 1.3)
        c.check_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_nonexistent_with_snappy(self):
        '''Test check_template() - nonexistent with ubuntu-snappy vendor'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "nonexistent")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu-snappy")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 1.3)
        c.check_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

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
        check_name = "security_template_valid (%s.apparmor)" % self.default_appname
        self.check_manual_review(report, check_name)

    def test_check_policy_groups_webapps(self):
        '''Test check_policy_groups_webapps()'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["audio",
                                         "content_exchange",
                                         "location",
                                         "networking",
                                         "video",
                                         "webview"])
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
                                         "content_exchange",
                                         "location",
                                         "networking",
                                         "video",
                                         "webview"])
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
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
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

    def test_check_policy_groups_webapps_missing_webview(self):
        '''Test check_policy_groups_webapps() - missing webview'''
        self.set_test_manifest("framework", "ubuntu-sdk-14.04-qml-dev1")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["networking"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_webapps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_webapps_missing_webview_1310(self):
        '''Test check_policy_groups_webapps() - missing webview (13.10)'''
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["networking"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_webapps()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
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
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_scopes_network(self):
        '''Test check_policy_groups_scopes() - network'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-scope-network")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", [])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_scopes()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_scopes_network2(self):
        '''Test check_policy_groups_scopes() - network with networking'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-scope-network")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["networking"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_scopes()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_scopes_network3(self):
        '''Test check_policy_groups_scopes() - network with accounts'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-scope-network")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["accounts"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_scopes()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_scopes_network_missing(self):
        '''Test check_policy_groups_scopes() missing - network'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-scope-network")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", None)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_scopes()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_scopes_network_bad(self):
        '''Test check_policy_groups_scopes() bad - network'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-scope-network")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["location"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_scopes()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

# jdstrand, 2014-06-05: ubuntu-scope-local-content is no longer available
#     def test_check_policy_groups_scopes_localcontent(self):
#         '''Test check_policy_groups_scopes() - localcontent'''
#         self.set_test_security_manifest(self.default_appname,
#                                         "template",
#                                         "ubuntu-scope-local-content")
#         self.set_test_security_manifest(self.default_appname,
#                                         "policy_groups", [])
#         c = ClickReviewSecurity(self.test_name)
#         c.check_policy_groups_scopes()
#         report = c.click_report
#         expected_counts = {'info': None, 'warn': 0, 'error': 0}
#         self.check_results(report, expected_counts)

#     def test_check_policy_groups_scopes_localcontent_missing(self):
#         '''Test check_policy_groups_scopes() missing - localcontent'''
#         self.set_test_security_manifest(self.default_appname,
#                                         "template",
#                                         "ubuntu-scope-local-content")
#         self.set_test_security_manifest(self.default_appname,
#                                         "policy_groups", None)
#         c = ClickReviewSecurity(self.test_name)
#         c.check_policy_groups_scopes()
#         report = c.click_report
#         expected_counts = {'info': 0, 'warn': 0, 'error': 0}
#         self.check_results(report, expected_counts)

#     def test_check_policy_groups_scopes_localcontent_bad(self):
#         '''Test check_policy_groups_scopes() bad - localcontent'''
#         self.set_test_security_manifest(self.default_appname,
#                                         "template",
#                                         "ubuntu-scope-local-content")
#         self.set_test_security_manifest(self.default_appname,
#                                         "policy_groups", ["networking"])
#         c = ClickReviewSecurity(self.test_name)
#         c.check_policy_groups_scopes()
#         report = c.click_report
#         expected_counts = {'info': None, 'warn': 0, 'error': 1}
#         self.check_results(report, expected_counts)

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

    def test_check_policy_groups_duplicates(self):
        '''Test check_policy_groups() - duplicates'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ['networking',
                                         'camera',
                                         'microphone',
                                         'camera',
                                         'microphone',
                                         'video'])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
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
        '''Test check_policy_groups() - nonexistent'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["networking", "nonexistent"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_reserved(self):
        '''Test check_policy_groups() - reserved'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["video_files", "networking"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)
        check_name = "security_policy_groups_safe_%s (video_files)" % (
            self.default_appname,)
        self.check_manual_review(report, check_name)

    def test_check_policy_groups_debug(self):
        '''Test check_policy_groups() - debug'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["debug"])
        self.set_test_security_manifest(self.default_appname, "policy_version",
                                        1.2)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_empty(self):
        '''Test check_policy_groups() - empty'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["", "networking"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_pushhelper_no_hook(self):
        '''Test check_policy_groups_pushhelper() - no hook'''
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_push_helpers()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_pushhelper(self):
        '''Test check_policy_groups_pushhelper()'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["push-notification-client"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_push_helpers()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_pushhelper_missing(self):
        '''Test check_policy_groups_pushhelper - missing'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        None)
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_push_helpers()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_pushhelper_bad(self):
        '''Test check_policy_groups_pushhelper - bad'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["video_files",
                                         "networking",
                                         "push-notification-client"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_push_helpers()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_pushhelper_networking(self):
        '''Test check_policy_groups_pushhelper - networking'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["networking",
                                         "push-notification-client"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_push_helpers()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_template_pushhelper(self):
        '''Test check_template_pushhelper'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-push-helper")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["push-notification-client"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_push_helpers()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_pushhelper_no_hook(self):
        '''Test check_template_pushhelper'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-sdk")
        c = ClickReviewSecurity(self.test_name)
        c.check_template_push_helpers()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_pushhelper_wrong_template(self):
        '''Test check_template_pushhelper - wrong template'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["push-notification-client"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_push_helpers()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_template_pushhelper_wrong_template2(self):
        '''Test check_template_pushhelper - default template'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", None)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["push-notification-client"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_push_helpers()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_peer_hooks(self):
        '''Test check_peer_hooks()'''
        c = ClickReviewSecurity(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["apparmor"] = "foo.apparmor"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        # We should end up with 2 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_disallowed(self):
        '''Test check_peer_hooks() - disallowed'''
        c = ClickReviewSecurity(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["apparmor"] = "foo.apparmor"

        # add something not allowed
        tmp["framework"] = "foo.framework"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_redflag_policy_vendor_ubuntu(self):
        '''Test check_redflag() - policy_vendor - ubuntu'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu")
        c.check_redflag()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_redflag_policy_vendor_ubuntu_snappy(self):
        '''Test check_redflag() - policy_vendor - ubuntu-snappy'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu-snappy")
        c.check_redflag()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_redflag_policy_vendor_notubuntu(self):
        '''Test check_redflag() - policy_vendor - notubuntu'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "notubuntu")
        c.check_redflag()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_redflag_abstractions(self):
        '''Test check_redflag() - abstractions'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "abstractions", ["python"])
        c.check_redflag()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_redflag_binary(self):
        '''Test check_redflag() - binary'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "binary", "/bin/foo")
        c.check_redflag()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_redflag_read_path(self):
        '''Test check_redflag() - read_path'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "read_path", ["/"])
        c.check_redflag()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_redflag_template_variables(self):
        '''Test check_redflag() - template_variables'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template_variables", {"FOO": "bar"})
        c.check_redflag()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_redflag_write_path(self):
        '''Test check_redflag() - write_path'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "write_path", ["/"])
        c.check_redflag()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)
