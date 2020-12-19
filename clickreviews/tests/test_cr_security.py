'''test_cr_security.py: tests for the cr_security module'''
#
# Copyright (C) 2013-2015 Canonical Ltd.
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
        super().setUp()

        self.default_security_json = "%s.apparmor" % \
            self.default_appname

    def _set_yaml_binary(self, entries, name=None):
        d = dict()
        if name is None:
            d['name'] = self.default_appname
        else:
            d['name'] = name
        for (key, value) in entries:
            d[key] = value
        self.set_test_pkg_yaml("binaries", [d])

    def test_check_policy_version_vendor(self):
        '''Test check_policy_version() - valid'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 1.0)
        c.check_policy_version()
        report = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_version_vendor_snappy_1504(self):
        '''Test check_policy_version() - valid - snappy 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        n = "bin/%s" % self.default_appname
        self._set_yaml_binary([('caps', ['network-client'])], name=n)
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest("binaries/%s" % n,
                                        "policy_version", 1.0)
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
        name = c._get_check_name(
            'policy_version_is_highest',
            extra="(%s, %s)" % (highest_version, self.default_security_json))
        expected['info'][name] = {"text": "OK"}
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
        name = c._get_check_name(
            'policy_version_is_highest',
            extra="(%s, %s)" % (highest, self.default_security_json))
        expected['info'][name] = {"text": "0.1 != %s" % highest}
        name = c._get_check_name(
            'policy_version_exists',
            extra=self.default_security_json)
        expected['error'][name] = {
            "text": "could not find policy for ubuntu/%s" % str(bad_version)
        }
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
        name = c._get_check_name(
            'policy_version_is_highest',
            extra="(%s, %s)" % (highest, self.default_security_json))
        expected['info'][name] = {"text": "%s != %s" % (version, highest)}
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
        name = c._get_check_name('policy_version_exists',
                                 extra=self.default_security_json)
        expected['error'][name] = {
            "text": "could not find policy_version in manifest"
        }
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
                    policy_version = \
                        tmp.major_framework_policy[k]['policy_version']
            self.set_test_security_manifest(self.default_appname,
                                            "policy_version",
                                            policy_version)
            c = ClickReviewSecurity(self.test_name)
            c.check_policy_version()
            report = c.click_report
            expected_counts = {'info': 3, 'warn': 0, 'error': 0}
            self.check_results(report, expected_counts)

    def test_check_policy_version_framework_match_snappy_multiple(self):
        '''Test check_policy_version() - matching framework - multiple'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_manifest("framework", "foo,ubuntu-core-15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu-core")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 15.04)
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
        name = c._get_check_name(
            'policy_version_matches_framework',
            extra=self.default_security_json)
        expected['error'][name] = {"text": "1.0 != 1.1 (ubuntu-sdk-14.04)"}
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
        name = c._get_check_name(
            'policy_version_matches_framework',
            extra=self.default_security_json)
        expected['error'][name] = {"text": "1.1 != 1.0 (ubuntu-sdk-13.10)"}
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
        name = c._get_check_name(
            'policy_version_matches_framework',
            extra=self.default_security_json)
        expected['error'][name] = {"text": "Invalid framework 'nonexistent'"}
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
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_vendor_ubuntu_1504(self):
        '''Test check_policy_vendor() - ubuntu - 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        n = "bin/%s" % self.default_appname
        self._set_yaml_binary([('caps', ['network-client'])], name=n)
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest("binaries/%s" % n,
                                        "policy_vendor", "ubuntu")
        c.check_policy_vendor()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_vendor_ubuntu(self):
        '''Test check_policy_vendor() - ubuntu'''
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu")
        c.check_policy_vendor()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_vendor_ubuntu_snappy(self):
        '''Test check_policy_vendor() - ubuntu-core'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_manifest("framework", "ubuntu-core-15.04")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu-core")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 15.04)
        c.check_policy_vendor()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_vendor_nonexistent(self):
        '''Test check_policy_vendor() - nonexistent'''
        self.set_test_manifest("framework", "nonexistent")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu")
        c.check_policy_vendor()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_vendor_framework(self):
        '''Test check_policy_vendor() - matching framework'''
        tmp = ClickReviewSecurity(self.test_name)
        # for each installed framework on the system, verify that the policy
        # matches the framework
        for f in tmp.valid_frameworks:
            self.set_test_manifest("framework", f)
            policy_vendor = "ubuntu"
            for k in tmp.major_framework_policy.keys():
                if f.startswith(k):
                    if 'policy_vendor' not in tmp.major_framework_policy[k]:
                        policy_vendor = 'ubuntu'
                    else:
                        policy_vendor = \
                            tmp.major_framework_policy[k]['policy_vendor']
            self.set_test_security_manifest(self.default_appname,
                                            "policy_vendor",
                                            policy_vendor)
            c = ClickReviewSecurity(self.test_name)
            c.check_policy_vendor()
            report = c.click_report
            expected_counts = {'info': 2, 'warn': 0, 'error': 0}
            self.check_results(report, expected_counts)

    def test_check_policy_vendor_framwork_match_snappy_multiple(self):
        '''Test check_policy_vendor() - matching framework - multiple'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_manifest("framework", "foo,ubuntu-core-15.04")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu-core")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_version", 15.04)
        c.check_policy_vendor()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_vendor_framework_unmatch1(self):
        '''Test check_policy_vendor() - unmatching framework'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu-snappy")
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_vendor()
        report = c.click_report

        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        name = c._get_check_name(
            'policy_vendor_matches_framework',
            extra=self.default_security_json)
        expected['error'][name] = {
            "text": "ubuntu-snappy != ubuntu (ubuntu-sdk-13.10)"
        }
        self.check_results(report, expected=expected)

    def test_check_policy_vendor_framework_unmatch2(self):
        '''Test check_policy_vendor() - unmatching framework - nonexistent'''
        self.set_test_manifest("framework", "nonexistent")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu")
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_vendor()
        report = c.click_report

        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        name = c._get_check_name(
            'policy_vendor_matches_framework',
            extra=self.default_security_json)
        expected['error'][name] = {"text": "Invalid framework 'nonexistent'"}
        self.check_results(report, expected=expected)

    def test_check_policy_vendor_framework_with_overrides(self):
        '''Test check_policy_vendor() - override framework (nonexistent)'''
        self.set_test_manifest("framework", "nonexistent")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu")
        overrides = {'framework': {'nonexistent': {'state': 'available',
                                                   'policy_vendor': 'ubuntu',
                                                   'policy_version': 1.2}}}
        c = ClickReviewSecurity(self.test_name, overrides=overrides)
        c.check_policy_vendor()
        report = c.click_report

        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_vendor_framework_with_malformed_overrides(self):
        '''Test check_policy_vendor() - incorrectly override framework'''
        self.set_test_manifest("framework", "nonexistent")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu")
        overrides = {'nonexistent': {'state': 'available',
                                     'policy_vendor': 'ubuntu',
                                     'policy_version': 1.2}}
        c = ClickReviewSecurity(self.test_name, overrides=overrides)
        c.check_policy_vendor()
        report = c.click_report

        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
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
        name = c._get_check_name('template_with_policy_version',
                                 extra=self.default_security_json)
        expected['info'][name] = {"text": "OK"}
        name = c._get_check_name('template_exists',
                                 extra=self.default_security_json)
        expected['info'][name] = {"text": "OK"}
        name = c._get_check_name('template_valid',
                                 extra=self.default_security_json)
        expected['warn'][name] = {
            "text": "No need to specify 'ubuntu-sdk' template"
        }
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
        '''Test check_template() - default specified with ubuntu-snappy
        vendor'''
        self.set_test_pkgfmt("snap", "15.04")
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
        self.set_test_pkgfmt("snap", "15.04")
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

    def test_check_template_snappy_framework_deprecated(self):
        '''Test check_template() - in deprecated framework declaration'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_pkg_yaml("framework", "fwk")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "fwk_foo")
        c.check_template()
        report = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_snappy_framework_deprecated2(self):
        '''Test check_template() - in deprecated framework declaration list'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_pkg_yaml("framework", "fwk, somethingelse")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "fwk_foo")
        c.check_template()
        report = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_snappy_frameworks(self):
        '''Test check_template() - in frameworks declaration'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_pkg_yaml("frameworks", ["fwk"])
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "fwk_foo")
        c.check_template()
        report = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_snappy_framework_type(self):
        '''Test check_template() - type framework'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_pkg_yaml("type", "framework")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "template",
                                        "%s_foo" %
                                        self.test_name.split('_')[0])
        c.check_template()
        report = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
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
        check_name = c._get_check_name(
            'template_valid', app="%s.apparmor" % self.default_appname)
        self.check_manual_review(report, check_name)

    def test_check_policy_groups_webapps(self):
        '''Test check_policy_groups_webapps()'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["audio",
                                         "content_exchange",
                                         "keep-display-on",
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
                                         "keep-display-on",
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

    def test_check_policy_groups_multiple_kepp_display_on(self):
        '''Test check_policy_groups() - multiple with keep-display-on'''
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ['networking',
                                         'audio',
                                         'keep-display-on',
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
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
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
        check_name = c._get_check_name(
            'policy_groups_safe', app=self.default_appname,
            extra='video_files')
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

    def test_check_policy_groups_snappy_framework_deprecated(self):
        '''Test check_policy_groups() - in deprecated framework declaration'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_pkg_yaml("framework", "fwk")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["fwk_foo"])
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_snappy_framework_deprecated2(self):
        '''Test check_policy_groups() - in deprecated framework declaration
           list
        '''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_pkg_yaml("framework", "fwk, somethingelse")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["fwk_foo"])
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_snappy_frameworks(self):
        '''Test check_policy_groups() - in frameworks declaration'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_pkg_yaml("frameworks", ["fwk"])
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["fwk_foo"])
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_snappy_framework_type(self):
        '''Test check_policy_groups() - type framework'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_pkg_yaml("type", "framework")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["%s_foo" %
                                         self.test_name.split('_')[0]])
        c.check_policy_groups()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
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
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-push-helper")
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_push_helpers()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_pushhelper_wrong_template(self):
        '''Test check_policy_groups_pushhelper()'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["push-notification-client"])
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-sdk")
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_push_helpers()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_pushhelper_missing(self):
        '''Test check_policy_groups_pushhelper - missing'''
        self.set_test_push_helper(self.default_appname, "exec", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        None)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-push-helper")
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
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-push-helper")
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
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-push-helper")
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_push_helpers()
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
        # We should end up with 4 info
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
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

    def test_check_peer_hooks_disallowed_apparmor_profile(self):
        '''Test check_peer_hooks() - disallowed (apparmor-profile)'''
        c = ClickReviewSecurity(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["apparmor"] = "foo.apparmor"

        # add something not allowed
        tmp["apparmor-profile"] = "foo.profile"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_aa_profile(self):
        '''Test check_peer_hooks() - apparmor-profile'''
        c = ClickReviewSecurity(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["apparmor-profile"] = "foo.profile"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        # We should end up with 4 info
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_aa_profile_disallowed(self):
        '''Test check_peer_hooks() - disallowed - apparmor-profile'''
        c = ClickReviewSecurity(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["apparmor-profile"] = "foo.profile"

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
        self.set_test_pkgfmt("snap", "15.04")
        c = ClickReviewSecurity(self.test_name)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_vendor", "ubuntu-snappy")
        c.check_redflag()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
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

    def test_check_apparmor_profile(self):
        '''Test check_apparmor_profile()'''
        self.set_test_pkgfmt("snap", "15.04")
        policy = '''
###VAR###
###PROFILEATTACH### {
  #include <abstractions/base>
  # Read-only for the install directory
  @{CLICK_DIR}/@{APP_PKGNAME}/@{APP_VERSION}/**  mrklix,
}
'''
        self.set_test_security_profile(self.default_appname, policy)
        c = ClickReviewSecurity(self.test_name)
        c.check_apparmor_profile()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_missing_var(self):
        '''Test check_apparmor_profile() - missing ###VAR###'''
        self.set_test_pkgfmt("snap", "15.04")
        policy = '''
###PROFILEATTACH### {
  #include <abstractions/base>
  # Read-only for the install directory
  @{CLICK_DIR}/@{APP_PKGNAME}/@{APP_VERSION}/**  mrklix,
}
'''
        self.set_test_security_profile(self.default_appname, policy)
        c = ClickReviewSecurity(self.test_name)
        c.check_apparmor_profile()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_missing_app_pkgname(self):
        '''Test check_apparmor_profile() - missing @{APP_PKGNAME}'''
        self.set_test_pkgfmt("snap", "15.04")
        policy = '''
###VAR###
###PROFILEATTACH### {
  #include <abstractions/base>
  @{CLICK_DIR}/*/@{APP_VERSION}/**  mrklix,
}
'''
        self.set_test_security_profile(self.default_appname, policy)
        c = ClickReviewSecurity(self.test_name)
        c.check_apparmor_profile()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_missing_vars_unconfined(self):
        '''Test check_apparmor_profile() - missing vars with unconfined
           boilerplate (first test)
        '''
        self.set_test_pkgfmt("snap", "15.04")
        policy = '''
# Unrestricted AppArmor policy for fwk-name_svc
###VAR###
###PROFILEATTACH### {
  #include <abstractions/base>
}
'''
        self.set_test_security_profile(self.default_appname, policy)
        c = ClickReviewSecurity(self.test_name)
        c.check_apparmor_profile()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_missing_var_unconfined2(self):
        '''Test check_apparmor_profile() - missing vars with unconfined
           boilerplate (second test)
        '''
        self.set_test_pkgfmt("snap", "15.04")
        policy = '''
# This profile offers no protection
###VAR###
###PROFILEATTACH### {
  #include <abstractions/base>
}
'''
        self.set_test_security_profile(self.default_appname, policy)
        c = ClickReviewSecurity(self.test_name)
        c.check_apparmor_profile()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_default(self):
        '''Test check_security_template() - default'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname, "template", None)
        self._set_yaml_binary([])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_default_with_exec(self):
        '''Test check_security_template() - default with exec'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname, "template", None)
        self._set_yaml_binary([('exec', 'bin/%s' % self.default_appname)])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_nondefault(self):
        '''Test check_security_template() - nondefault'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "nondefault")
        self._set_yaml_binary([('security-template', 'nondefault')])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_nondefault_1504(self):
        '''Test check_security_template() - nondefault - 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "nondefault")
        self._set_yaml_binary([('security-template', 'nondefault')])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_bad(self):
        '''Test check_security_template() - {}'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', {})])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_default(self):
        '''Test check_security_caps() - default (networking)'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "caps", ['networking'])
        self._set_yaml_binary([('caps', ['networking'])])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_default2(self):
        '''Test check_security_caps() - default (network-client)'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "caps", ['network-client'])
        self._set_yaml_binary([('caps', ['network-client'])])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_default_with_exec(self):
        '''Test check_security_caps() - default with exec (networking)'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "caps", ['networking'])
        self._set_yaml_binary([('exec', 'bin/%s' % self.default_appname),
                               ('caps', ['networking'])])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_default_with_exec2(self):
        '''Test check_security_caps() - default with exec (network-client)'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "caps", ['network-client'])
        self._set_yaml_binary([('exec', 'bin/%s' % self.default_appname),
                               ('caps', ['network-client'])])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_nondefault(self):
        '''Test check_security_caps() - nondefault'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "caps", [])
        self._set_yaml_binary([('caps', [])])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_bad(self):
        '''Test check_security_caps() - {}'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', {})])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_name_relative(self):
        '''Test check_security_yaml_and_click() - relative path'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', ['networking'])],
                              name="bin/%s" % self.default_appname)
        c = ClickReviewSecurity(self.test_name)

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"

        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_snappy_1504(self):
        '''Test check_security_yaml_and_click() - snappy 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', ['networking'])],
                              name="bin/%s" % self.default_appname)
        c = ClickReviewSecurity(self.test_name)

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"

        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_name_exec(self):
        '''Test check_security_yaml_and_click() - uses exec'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', ['networking']),
                               ('exec', "bin/%s" % self.default_appname)],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"

        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 6, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_matching_template(self):
        '''Test check_security_yaml_and_click() - matching default template'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', ['networking'])])
        self.set_test_security_manifest(self.default_appname,
                                        "template", "default")
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        del c.pkg_yaml['binaries'][0]['security-template']
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 6, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_security_override(self):
        '''Test check_security_yaml_and_click() - security-override'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'default')])
        self._set_yaml_binary([('security-override', {})])
        self.set_test_security_manifest(self.default_appname,
                                        "template", "default")
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_security_policy(self):
        '''Test check_security_yaml_and_click() - security-policy'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'default')])
        self._set_yaml_binary([('security-policy', {})])
        self.set_test_security_manifest(self.default_appname,
                                        "template", "default")
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_matching_caps(self):
        '''Test check_security_yaml_and_click() - matching default caps'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', [])])
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ['networking'])
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        del c.pkg_yaml['binaries'][0]['caps']
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_matching_caps2(self):
        '''Test check_security_yaml_and_click() - matching default caps'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', [])])
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ['network-client'])
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        del c.pkg_yaml['binaries'][0]['caps']
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_matching_no_caps(self):
        '''Test check_security_yaml_and_click() - matching no caps'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', [])])
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", None)
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_matching_no_caps_template(self):
        '''Test check_security_yaml_and_click() - matching no caps with
           template
        '''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'nondefault')])
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", None)
        self.set_test_security_manifest(self.default_appname,
                                        "template", "nondefault")
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch0(self):
        '''Test check_security_yaml_and_click() - missing app in hooks'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([])
        self.set_test_security_manifest(self.default_appname,
                                        "template", None)
        c = ClickReviewSecurity(self.test_name)

        del c.manifest["hooks"][self.default_appname]
        self._update_test_manifest()
        c.security_apps.remove(self.default_appname)

        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch2(self):
        '''Test check_security_yaml_and_click() - missing apparmor in hooks'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([])
        c = ClickReviewSecurity(self.test_name)

        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        del c.manifest["hooks"][self.default_appname]['apparmor']
        c.security_apps.remove(self.default_appname)
        self._update_test_manifest()

        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch3(self):
        '''Test check_security_yaml_and_click() - missing security-template'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', ['networking'])])
        self.set_test_security_manifest(self.default_appname,
                                        "template", "nondefault")
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        del c.pkg_yaml['binaries'][0]['security-template']
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch4(self):
        '''Test check_security_yaml_and_click() - missing click template'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([("security-template", "nondefault"),
                               ('caps', ['networking'])],
                              name=self.default_appname)
        self.set_test_security_manifest(self.default_appname,
                                        "template", None)
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch5(self):
        '''Test check_security_yaml_and_click() - different templates'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "other")
        self._set_yaml_binary([("security-template", "nondefault"),
                               ('caps', ['networking'])],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch6(self):
        '''Test check_security_yaml_and_click() - missing caps in yaml'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', [])])
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["1", "2"])
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        del c.pkg_yaml['binaries'][0]['caps']
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch7(self):
        '''Test check_security_yaml_and_click() - missing policy_groups'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', ['networking'])],
                              name=self.default_appname)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", None)
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch8(self):
        '''Test check_security_yaml_and_click() - different caps/groups'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["1", "2"])
        self._set_yaml_binary([('caps', ["3"])],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch9(self):
        '''Test check_security_yaml_and_click() - unordered caps/groups'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["1", "2"])
        self._set_yaml_binary([('caps', ["2", "1"])],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch10(self):
        '''Test check_security_yaml_and_click() - missing caps in both'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', [])])
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", None)
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        del c.pkg_yaml['binaries'][0]['caps']
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch11(self):
        '''Test check_security_yaml_and_click() - default caps with template'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'nondefault')])
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ['networking'])
        self.set_test_security_manifest(self.default_appname,
                                        "template", "nondefault")
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        del c.pkg_yaml['binaries'][0]['caps']
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_mismatch12(self):
        '''Test check_security_yaml_and_click() - default caps with template'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'nondefault')])
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ['network-client'])
        self.set_test_security_manifest(self.default_appname,
                                        "template", "nondefault")
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        del c.pkg_yaml['binaries'][0]['caps']
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_invalid_template(self):
        '''Test check_security_yaml_and_click() - invalid template'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "other")
        self._set_yaml_binary([("security-template", None),
                               ('caps', ['networking'])],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_and_click_invalid_caps(self):
        '''Test check_security_yaml_and_click() - invalid caps'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "other")
        self._set_yaml_binary([("security-template", "nondefault"),
                               ('caps', None)],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.manifest["hooks"][self.default_appname]['bin-path'] = "bin/path"
        c.check_security_yaml_and_click()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations(self):
        '''Test check_security_yaml_combinations()'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([], name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations1(self):
        '''Test check_security_yaml_combinations() - template'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'foo')],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations2(self):
        '''Test check_security_yaml_combinations() - caps'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', ['networking'])],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations3(self):
        '''Test check_security_yaml_combinations() - template,caps'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'foo'),
                               ('caps', ['networking'])],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations4(self):
        '''Test check_security_yaml_combinations() - override'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-override', {'apparmor': 'foo.aa',
                                                      'seccomp': 'foo.sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations5(self):
        '''Test check_security_yaml_combinations() - override, template'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'foo'),
                               ('security-override', {'apparmor': 'foo.aa',
                                                      'seccomp': 'foo.sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations6(self):
        '''Test check_security_yaml_combinations() - override, caps'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', ['networking']),
                               ('security-override', {'apparmor': 'foo.aa',
                                                      'seccomp': 'foo.sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations7(self):
        '''Test check_security_yaml_combinations() - override, caps, template
        '''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'foo'),
                               ('caps', ['networking']),
                               ('security-override', {'apparmor': 'foo.aa',
                                                      'seccomp': 'foo.sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations8(self):
        '''Test check_security_yaml_combinations() - override, caps, template,
           policy
        '''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'foo'),
                               ('caps', ['networking']),
                               ('security-policy', {'apparmor': 'foo.aa',
                                                    'seccomp': 'foo.sc'}),
                               ('security-override', {'apparmor': 'foo.aa',
                                                      'seccomp': 'foo.sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations9(self):
        '''Test check_security_yaml_combinations() - policy'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-policy', {'apparmor': 'foo.aa',
                                                    'seccomp': 'foo.sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations10(self):
        '''Test check_security_yaml_combinations() - policy, template'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'foo'),
                               ('security-policy', {'apparmor': 'foo.aa',
                                                    'seccomp': 'foo.sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations11(self):
        '''Test check_security_yaml_combinations() - policy, caps'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('caps', ['networking']),
                               ('security-policy', {'apparmor': 'foo.aa',
                                                    'seccomp': 'foo.sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_combinations12(self):
        '''Test check_security_yaml_combinations() - policy, caps, template
        '''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-template', 'foo'),
                               ('caps', ['networking']),
                               ('security-policy', {'apparmor': 'foo.aa',
                                                    'seccomp': 'foo.sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_override_and_click(self):
        '''Test check_security_yaml_override_and_click()'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname, "template", None)
        self._set_yaml_binary([])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_override_and_click()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_override_and_click_1504(self):
        '''Test check_security_yaml_override_and_click() - 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname, "template", None)
        self._set_yaml_binary([])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_override_and_click()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_override_and_click_bad(self):
        '''Test check_security_yaml_override_and_click() - bad'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname, "template", None)
        self._set_yaml_binary([('security-override', {'apparmor':
                                                      'something.else'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_override_and_click()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_override(self):
        '''Test check_security_yaml_override()'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname, "template", None)
        self._set_yaml_binary([])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_override()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_override_1504(self):
        '''Test check_security_yaml_override() - 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname, "template", None)
        self._set_yaml_binary([])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_override()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_override2(self):
        '''Test check_security_yaml_override() - seccomp/apparmor specified'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-override', {'apparmor': 'aa',
                                                      'seccomp': 'sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_override()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_override4(self):
        '''Test check_security_yaml_override() - syscalls specified with
           15.04
        '''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-override', {'syscalls': 'foo'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_override_missing1(self):
        '''Test check_security_yaml_override() - missing apparmor'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-override', {'seccomp': 'sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_override_missing2(self):
        '''Test check_security_yaml_override() - missing seccomp'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-override', {'apparmor': 'aa'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_policy(self):
        '''Test check_security_yaml_policy()'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_security_manifest(self.default_appname, "template", None)
        self._set_yaml_binary([])
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_policy()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_yaml_policy2(self):
        '''Test check_security_yaml_policy() - seccomp/apparmor specified'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-policy', {'apparmor': 'aa',
                                                    'seccomp': 'sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_policy()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)
        name = c._get_check_name('yaml_policy_present')
        m = report['error'][name]['text']
        self.assertIn("(NEEDS REVIEW) 'security-policy' not allowed", m)

    def test_check_security_yaml_policy_missing1(self):
        '''Test check_security_yaml_policy() - missing apparmor'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-policy', {'seccomp': 'sc'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)
        name = c._get_check_name('yaml_policy_present')
        m = report['error'][name]['text']
        self.assertIn("(NEEDS REVIEW) 'security-policy' not allowed", m)
        name = c._get_check_name(
            'yaml_policy_format', app='test-app')
        m = report['error'][name]['text']
        self.assertIn("'apparmor' not specified in 'security-policy' " +
                      "for 'test-app'", m)

    def test_check_security_yaml_policy_missing2(self):
        '''Test check_security_yaml_policy() - missing seccomp'''
        self.set_test_pkgfmt("snap", "15.04")
        self._set_yaml_binary([('security-policy', {'apparmor': 'aa'})],
                              name=self.default_appname)
        c = ClickReviewSecurity(self.test_name)
        c.check_security_yaml_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)
        name = c._get_check_name('yaml_policy_present')
        m = report['error'][name]['text']
        self.assertIn("(NEEDS REVIEW) 'security-policy' not allowed", m)
        name = c._get_check_name(
            'yaml_policy_format', app='test-app')
        m = report['error'][name]['text']
        self.assertIn("'seccomp' not specified in 'security-policy' " +
                      "for 'test-app'", m)

    def test_check_template_online_account_provider(self):
        '''Test check_template_online_account_provider'''
        self.set_test_account(self.default_appname, "account-provider", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-account-plugin")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["accounts"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_provider()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_online_account_provider_1504(self):
        '''Test check_template_online_account_provider - 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_account(self.default_appname, "account-provider", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-account-plugin")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["accounts"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_provider()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_online_account_provider_no_hook(self):
        '''Test check_template_online_account_provider'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-account-plugin")
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_provider()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_online_account_provider_wrong_template(self):
        '''Test check_template_online_account_provider - wrong template'''
        self.set_test_account(self.default_appname, "account-provider", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["accounts"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_provider()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_template_online_account_provider_wrong_template2(self):
        '''Test check_template_online_account_provider - default template'''
        self.set_test_account(self.default_appname, "account-provider", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", None)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["accounts"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_provider()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_template_online_account_qml_plugin(self):
        '''Test check_template_online_account_qml_plugin'''
        self.set_test_account(self.default_appname,
                              "account-qml-plugin", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-account-plugin")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["accounts"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_qml_plugin()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_online_account_qml_plugin_1504(self):
        '''Test check_template_online_account_qml_plugin - 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        self.set_test_account(self.default_appname,
                              "account-qml-plugin", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-account-plugin")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["accounts"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_qml_plugin()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_online_account_qml_plugin_no_hook(self):
        '''Test check_template_online_account_qml_plugin'''
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-account-plugin")
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_qml_plugin()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_template_online_account_qml_plugin_wrong_template(self):
        '''Test check_template_online_account_qml_plugin - wrong template'''
        self.set_test_account(self.default_appname,
                              "account-qml-plugin", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-webapp")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["accounts"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_qml_plugin()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_template_online_account_qml_plugin_wrong_template2(self):
        '''Test check_template_online_account_qml_plugin - default template'''
        self.set_test_account(self.default_appname,
                              "account-qml-plugin", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", None)
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups", ["accounts"])
        c = ClickReviewSecurity(self.test_name)
        c.check_template_online_accounts_qml_plugin()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_ubuntu_account_plugin_no_hook(self):
        '''Test check_policy_groups_ubuntu_account_plugin() - no hook'''
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_ubuntu_account_plugin()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_ubuntu_account_plugin(self):
        '''Test check_policy_groups_ubuntu_account_plugin()'''
        self.set_test_account(self.default_appname,
                              "account-qml-plugin", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-account-plugin")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["accounts",
                                         "networking",
                                         "webview"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_ubuntu_account_plugin()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_ubuntu_account_plugin_missing(self):
        '''Test check_policy_groups_ubuntu_account_plugin - missing'''
        self.set_test_account(self.default_appname,
                              "account-qml-plugin", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-account-plugin")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["accounts", "webview"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_ubuntu_account_plugin()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_policy_groups_ubuntu_account_plugin_bad(self):
        '''Test check_policy_groups_ubuntu_account_plugin - bad'''
        self.set_test_account(self.default_appname,
                              "account-qml-plugin", "foo")
        self.set_test_security_manifest(self.default_appname,
                                        "template", "ubuntu-account-plugin")
        self.set_test_security_manifest(self.default_appname,
                                        "policy_groups",
                                        ["accounts",
                                         "networking",
                                         "push-notification-client"])
        c = ClickReviewSecurity(self.test_name)
        c.check_policy_groups_ubuntu_account_plugin()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length(self):
        '''Test check_apparmor_profile_name_length()'''
        c = ClickReviewSecurity(self.test_name)
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length_bad(self):
        '''Test check_apparmor_profile_name_length() - too long'''
        c = ClickReviewSecurity(self.test_name)
        c.click_pkgname += 'A' * 253
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length_bad2(self):
        '''Test check_apparmor_profile_name_length() - longer than advised'''
        c = ClickReviewSecurity(self.test_name)
        c.click_pkgname += 'A' * 100
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)
