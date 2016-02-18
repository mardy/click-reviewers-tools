'''test_sr_security.py: tests for the sr_security module'''
#
# Copyright (C) 2013-2016 Canonical Ltd.
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

from clickreviews.sr_security import SnapReviewSecurity
import clickreviews.sr_tests as sr_tests


class TestSnapReviewSecurity(sr_tests.TestSnapReview):
    """Tests for the security lint review tool."""
    def setUp(self):
        super().setUp()
        self.set_test_pkgfmt("snap", "16.04")

    def _create_top_uses(self):
        uses = {'skill-caps': {'type': 'migration-skill',
                               'caps': ['network-client']},
                'skill-override': {'type': 'migration-skill',
                                   'security-override': {"read_path": "/foo/",
                                                         "seccomp": "abc"}},
                'skill-policy': {'type': 'migration-skill',
                                 'security-policy': {"apparmor": "meta/aa",
                                                     "seccomp": "meta/sc"}},
                'skill-template': {'type': 'migration-skill',
                                   'security-template': "unconfined"}
                }
        return uses

    def _create_apps_uses(self):
        uses = {'app1': {'uses': ['skill-caps']},
                'app2': {'uses': ['skill-caps', 'skill-template']},
                'app3': {'uses': ['skill-template', 'skill-override']},
                'app4': {'uses': ['skill-policy']},
                }
        return uses

    def test_all_checks_as_v2(self):
        '''Test snap v2 has checks'''
        self.set_test_pkgfmt("snap", "16.04")
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.do_checks()
        sum = 0
        for i in c.click_report:
            sum += len(c.click_report[i])
        self.assertTrue(sum != 0)

    def test_all_checks_as_v1(self):
        '''Test snap v1 has no checks'''
        self.set_test_pkgfmt("snap", "15.04")
        c = SnapReviewSecurity(self.test_name)
        c.do_checks()
        sum = 0
        for i in c.click_report:
            sum += len(c.click_report[i])
        self.assertTrue(sum == 0)

    def test_all_checks_as_click(self):
        '''Test click format has no checks'''
        self.set_test_pkgfmt("click", "0.4")
        c = SnapReviewSecurity(self.test_name)
        c.do_checks()
        sum = 0
        for i in c.click_report:
            sum += len(c.click_report[i])
        self.assertTrue(sum == 0)

    def test_check_security_policy_vendor(self):
        '''Test check_security_policy_vendor()'''
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy_vendor()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_policy_vendor_missing(self):
        '''Test check_security_policy_vendor() - missing'''
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy.pop("ubuntu-core", None)
        c.check_security_policy_vendor()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_policy_version(self):
        '''Test check_security_policy_vesion()'''
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy_version()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_policy_version_missing(self):
        '''Test check_security_policy_vesion()'''
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"].pop("16.04", None)
        c.check_security_policy_version()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps(self):
        '''Test check_security_caps()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_with_nonmigration(self):
        '''Test check_security_caps() - with non-migration'''
        uses = self._create_top_uses()
        uses['bool'] = {'type': 'bool-file', 'path': '/sys/devices/gpio1'}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_with_apps(self):
        '''Test check_security_caps()'''
        uses = self._create_top_uses()
        apps = self._create_apps_uses()
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_with_frameworks(self):
        '''Test check_security_caps() - with framework'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        uses['myfwk'] = {'type': 'migration-skill', 'caps': ['fwk_1', 'fwk_2']}
        self.set_test_snap_yaml("frameworks", ["fwk"])
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        # the errors here are because we don't know the framework policy
        # 'type'. This needs support from the store
        expected_counts = {'info': 4, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:cap_safe:myfwk:fwk_1'
        expected['error'][name] = {"text": "unknown type 'None' for cap 'fwk_1'"}
        name = 'security-snap-v2:cap_safe:myfwk:fwk_2'
        expected['error'][name] = {"text": "unknown type 'None' for cap 'fwk_2'"}
        self.check_results(report, expected=expected)

    def test_check_security_caps_is_framework_with_framework_cap(self):
        '''Test check_security_caps() - is framework with framework cap'''
        pkgname = self.test_name.split('_')[0].split('.')[0]
        cap = '%s_1' % pkgname
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        uses['myfwk'] = {'type': 'migration-skill', 'caps': [cap]}
        self.set_test_snap_yaml("type", "framework")
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        # the errors here are because we don't know the framework policy
        # 'type'. This needs support from the store
        expected_counts = {'info': 3, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:cap_safe:myfwk:%s' % cap
        expected['error'][name] = {"text":
                                   "unknown type 'None' for cap '%s'" % cap}
        self.check_results(report, expected=expected)

    def test_check_security_caps_nonexistent(self):
        '''Test check_security_caps() - nonexistent'''
        uses = self._create_top_uses()
        uses['skill-caps']['caps'] = ['nonexistent']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_nonexistent2(self):
        '''Test check_security_caps() - nonexistent with others'''
        uses = self._create_top_uses()
        uses['skill-caps']['caps'] = ['network-client', 'nonexistent']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_repeated(self):
        '''Test check_security_caps() - repeated cap'''
        uses = self._create_top_uses()
        uses['skill-caps']['caps'] = ['network-client', 'network-client']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_common(self):
        '''Test check_security_caps() - common'''
        cap = "safe"
        uses = self._create_top_uses()
        uses['skill-caps']['caps'] = [cap]
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["common"].append(cap)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_debug(self):
        '''Test check_security_caps() - debug'''
        cap = "debug"
        uses = self._create_top_uses()
        uses['skill-caps']['caps'].append(cap)
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append(cap)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_reserved(self):
        '''Test check_security_caps() - reserved'''
        cap = "unsafe"
        uses = self._create_top_uses()
        uses['skill-caps']['caps'].append(cap)
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append(cap)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_unknown_type(self):
        '''Test check_security_caps() - unknown type'''
        cap = "bad-type"
        uses = self._create_top_uses()
        uses['skill-caps']['caps'].append(cap)
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["nonexistent"] = [cap]
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_uses_redflag(self):
        '''Test check_uses_redflag()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_uses_redflag()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)
