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
from unittest import TestCase
import os
import shutil
import tempfile

from clickreviews.common import cleanup_unpack
from clickreviews.common import check_results as common_check_results
from clickreviews.sr_security import SnapReviewSecurity
import clickreviews.sr_tests as sr_tests
from clickreviews.tests import utils


class TestSnapReviewSecurity(sr_tests.TestSnapReview):
    """Tests for the security lint review tool."""
    def setUp(self):
        super().setUp()
        self.set_test_pkgfmt("snap", "16.04")

    def _create_aa_raw(self):
        return '''
###VAR###
###PROFILEATTACH### (attach_disconnected) {
  @{INSTALL_DIR}/@{APP_PKGNAME}/@{APP_VERSION}/**  mrklix,
}
'''

    def _create_sc_raw(self):
        return '''
# test comment
 # test comment2
deny ptrace
deny add_key
alarm
usr32

_exit
'''

    def _create_top_plugs(self):
        self.set_test_security_profile('iface-policy', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('iface-policy', 'seccomp',
                                       self._create_sc_raw())

        plugs = {'iface-caps': {'interface': 'old-security',
                                'caps': ['network']},
                 'iface-override': {'interface': 'old-security',
                                    'security-override': {"read-paths": ["/a"],
                                                          "write-paths": ["/b"],
                                                          "abstractions": ["cd"],
                                                          "syscalls": ["ef"]}},
                 'iface-policy': {'interface': 'old-security',
                                  'security-policy': {"apparmor": "meta/aa",
                                                      "seccomp": "meta/sc"}},
                 'iface-template': {'interface': 'old-security',
                                    'security-template': "default"}
                 }
        return plugs

    def _create_apps_plugs(self):
        plugs = {'app1': {'plugs': ['iface-caps']},
                 'app2': {'plugs': ['iface-caps', 'iface-template']},
                 'app3': {'plugs': ['iface-template', 'iface-override']},
                 'app4': {'plugs': ['iface-policy']},
                 }
        return plugs

    def test_all_checks_as_v2(self):
        '''Test snap v2 has checks'''
        self.set_test_pkgfmt("snap", "16.04")
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
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
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_no_plugs(self):
        '''Test check_security_caps() - no plugs'''
        self.set_test_snap_yaml("plugs", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_with_non_oldsecurity(self):
        '''Test check_security_caps() - with non-old-security'''
        plugs = self._create_top_plugs()
        plugs['bool'] = {'interface': 'bool-file', 'path': '/sys/devices/gpio1'}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_with_apps(self):
        '''Test check_security_caps()'''
        plugs = self._create_top_plugs()
        apps = self._create_apps_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_nonexistent(self):
        '''Test check_security_caps() - nonexistent'''
        plugs = self._create_top_plugs()
        plugs['iface-caps']['caps'] = ['nonexistent']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_nonexistent2(self):
        '''Test check_security_caps() - nonexistent with others'''
        plugs = self._create_top_plugs()
        plugs['iface-caps']['caps'] = ['network', 'nonexistent']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_repeated(self):
        '''Test check_security_caps() - repeated cap'''
        plugs = self._create_top_plugs()
        plugs['iface-caps']['caps'] = ['network', 'network']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_common(self):
        '''Test check_security_caps() - common'''
        cap = "safe"
        plugs = self._create_top_plugs()
        plugs['iface-caps']['caps'] = [cap]
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["common"].append(cap)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_caps_debug(self):
        '''Test check_security_caps() - debug'''
        cap = "debug"
        plugs = self._create_top_plugs()
        plugs['iface-caps']['caps'].append(cap)
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append(cap)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_reserved(self):
        '''Test check_security_caps() - reserved'''
        cap = "unsafe"
        plugs = self._create_top_plugs()
        plugs['iface-caps']['caps'].append(cap)
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append(cap)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_caps_unknown_type(self):
        '''Test check_security_caps() - unknown type'''
        cap = "bad-type"
        plugs = self._create_top_plugs()
        plugs['iface-caps']['caps'].append(cap)
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["nonexistent"] = [cap]
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override(self):
        '''Test check_security_override()'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_override_no_plugs(self):
        '''Test check_security_override() - no plugs'''
        self.set_test_snap_yaml("plugs", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_override_empty(self):
        '''Test check_security_override() - empty'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_unknown(self):
        '''Test check_security_override() - unknown'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['nonexistent'] = ['foo']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_syscall_dict(self):
        '''Test check_security_override() - bad'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['syscalls'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_syscall(self):
        '''Test check_security_override() - bad syscall (illegal)'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['syscalls'] = ['BAD#%^']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_syscall_short(self):
        '''Test check_security_override() - bad syscall (short)'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['syscalls'] = ['a']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_syscall_long(self):
        '''Test check_security_override() - bad syscall (long)'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['syscalls'] = ['a' * 65]
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_abstraction_dict(self):
        '''Test check_security_override() - bad'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['abstractions'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_abstraction(self):
        '''Test check_security_override() - bad abstraction (illegal)'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['abstractions'] = ['BAD#%^']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_abstraction_short(self):
        '''Test check_security_override() - bad abstraction (short)'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['abstractions'] = ['a']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_abstraction_long(self):
        '''Test check_security_override() - bad abstraction (long)'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['abstractions'] = ['a' * 65]
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_read_path_var(self):
        '''Test check_security_override() - @{HOME}/foo'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['read-paths'] = \
            ["@{HOME}/foo"]
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_read_path_dict(self):
        '''Test check_security_override() - bad'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['read-paths'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_read_path(self):
        '''Test check_security_override() - bad (relative)'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['read-paths'] = \
            ['relative/path']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_write_path_var(self):
        '''Test check_security_override() - @{HOME}/foo'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['write-paths'] = \
            ["@{HOME}/foo"]
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_write_path_dict(self):
        '''Test check_security_override() - bad'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['write-paths'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_write_path(self):
        '''Test check_security_override() - bad (relative)'''
        plugs = self._create_top_plugs()
        plugs['iface-override']['security-override']['write-paths'] = \
            ['relative/path']
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_policy(self):
        '''Test check_security_policy()'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_policy_no_plugs(self):
        '''Test check_security_policy() - no plugs'''
        self.set_test_snap_yaml("plugs", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_policy_unknown(self):
        '''Test check_security_policy() - unknown'''
        self.set_test_security_profile('iface-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = {'iface-other': {'interface': 'old-security',
                                 'security-policy': {"apparmor": "meta/aa",
                                                     "seccomp": "meta/sc",
                                                     "nonexistent": "bad"},
                                 }
                 }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_policy_empty(self):
        '''Test check_security_policy() - empty'''
        self.set_test_security_profile('iface-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = {'iface-other': {'interface': 'old-security',
                                 'security-policy': {}}}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)

    def test_check_security_policy_bad(self):
        '''Test check_security_policy() - bad (list)'''
        self.set_test_security_profile('iface-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = {'iface-other': {'interface': 'old-security',
                                 'security-policy': {"apparmor": "meta/aa",
                                                     "seccomp": []}
                                 }
                 }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_policy_missing_apparmor(self):
        '''Test check_security_policy() - missing apparmor'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.raw_profiles['iface-policy'].pop('apparmor')
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_policy_missing_seccomp(self):
        '''Test check_security_policy() - missing seccomp'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.raw_profiles['iface-policy'].pop('seccomp')
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_policy_apparmor_boiler1(self):
        '''Test check_security_policy() - boilerplate text #1'''
        contents = '''
###VAR###
###PROFILEATTACH### (attach_disconnected) {}
# Unrestricted AppArmor policy
'''
        self.set_test_security_profile('iface-other', 'apparmor', contents)
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = {'iface-other': {'interface': 'old-security',
                                 'security-policy': {"apparmor": "meta/aa",
                                                     "seccomp": "meta/sc",
                                                     }
                                 }
                 }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:security-policy_apparmor_var:iface-other'
        expected['info'][name] = {"text": "SKIPPED for '@{INSTALL_DIR}' (boilerplate)"}
        self.check_results(report, expected=expected)

    def test_check_security_policy_apparmor_boiler2(self):
        '''Test check_security_policy() - boilerplate text #2'''
        contents = '''
###VAR###
###PROFILEATTACH### (attach_disconnected) {}
# This profile offers no protection
'''
        self.set_test_security_profile('iface-other', 'apparmor', contents)
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = {'iface-other': {'interface': 'old-security',
                                 'security-policy': {"apparmor": "meta/aa",
                                                     "seccomp": "meta/sc",
                                                     }
                                 }
                 }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:security-policy_apparmor_var:iface-other'
        expected['info'][name] = {"text": "SKIPPED for '@{INSTALL_DIR}' (boilerplate)"}
        self.check_results(report, expected=expected)

    def test_check_security_policy_missing_apparmor_var(self):
        '''Test check_security_policy() - missing apparmor var'''
        contents = '''
###PROFILEATTACH### (attach_disconnected) {
  @{INSTALL_DIR}/@{APP_PKGNAME}/@{APP_VERSION}/**  mrklix,
}
'''
        self.set_test_security_profile('iface-other', 'apparmor', contents)
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = {'iface-other': {'interface': 'old-security',
                                 'security-policy': {"apparmor": "meta/aa",
                                                     "seccomp": "meta/sc",
                                                     }
                                 }
                 }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        print(c.raw_profiles)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_policy_bad_seccomp(self):
        '''Test check_security_policy() - bad seccomp'''
        contents = self._create_sc_raw() + "\nBAD%$\n"
        self.set_test_security_profile('iface-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('iface-other', 'seccomp', contents)
        plugs = {'iface-other': {'interface': 'old-security',
                                 'security-policy': {"apparmor": "meta/aa",
                                                     "seccomp": "meta/sc",
                                                     }
                                 }
                 }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        print(c.raw_profiles)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_template(self):
        '''Test check_security_template()'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_no_plugs(self):
        '''Test check_security_template()'''
        self.set_test_snap_yaml("plugs", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_with_non_oldsecurity(self):
        '''Test check_security_template() - with non-old-security'''
        plugs = self._create_top_plugs()
        plugs['bool'] = {'interface': 'bool-file', 'path': '/sys/devices/gpio1'}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_with_apps(self):
        '''Test check_security_template()'''
        plugs = self._create_top_plugs()
        apps = self._create_apps_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_nonexistent(self):
        '''Test check_security_template() - nonexistent'''
        plugs = self._create_top_plugs()
        plugs['iface-template']['security-template'] = 'nonexistent'
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_template_common(self):
        '''Test check_security_template() - common'''
        template = "safe"
        plugs = self._create_top_plugs()
        plugs['iface-template']['security-template'] = template
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["templates"]["common"].append(
            template)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_reserved(self):
        '''Test check_security_template() - reserved'''
        template = "unsafe"
        plugs = self._create_top_plugs()
        plugs['iface-template']['security-template'] = template
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["templates"]["reserved"].append(
            template)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_template_unknown_type(self):
        '''Test check_security_template() - unknown type'''
        template = "bad-type"
        plugs = self._create_top_plugs()
        plugs['iface-template']['security-template'] = template
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["templates"]["nonexistent"] = \
            template
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations(self):
        '''Test check_security_combinations()'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_no_plugs(self):
        '''Test check_security_combinations() - no plugs'''
        self.set_test_snap_yaml("plugs", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_no_apps(self):
        '''Test check_security_combinations()'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        self.set_test_snap_yaml("apps", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps(self):
        '''Test check_security_combinations() - apps'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        apps = self._create_apps_plugs()
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 8, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_plugs_nonsecurity(self):
        '''Test check_security_combinations() - plugs non-security'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        apps = self._create_apps_plugs()
        apps = {'app5': {'plugs': ['other']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_caps_with_security_policy(self):
        '''Test check_security_combinations() - apps caps with security-policy'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        apps = self._create_apps_plugs()
        apps['app1'] = {'plugs': ['iface-caps', 'iface-policy']}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_template_with_security_policy(self):
        '''Test check_security_combinations() - apps security-template with security-policy'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        apps = self._create_apps_plugs()
        apps['app1'] = {'plugs': ['iface-template', 'iface-policy']}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_override_with_security_policy(self):
        '''Test check_security_combinations() - apps security-override with security-policy'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        apps = self._create_apps_plugs()
        apps['app1'] = {'plugs': ['iface-override', 'iface-policy']}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_all_with_security_policy(self):
        '''Test check_security_combinations() - apps all with security-policy'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        apps = self._create_apps_plugs()
        apps['app1'] = {'plugs': ['iface-override', 'iface-policy',
                                  'iface-caps', 'iface-template']}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_caps_with_security_policy(self):
        '''Test check_security_combinations() - caps with security-policy'''
        self.set_test_security_profile('iface-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = self._create_top_plugs()
        plugs['iface-other'] = {'interface': 'old-security',
                                'caps': ['network'],
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc"}
                                }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_template_with_security_policy(self):
        '''Test check_security_combinations() - template with security-policy'''
        self.set_test_security_profile('iface-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = self._create_top_plugs()
        plugs['iface-other'] = {'interface': 'old-security',
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc"},
                                'security-template': "default"
                                }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_override_with_security_policy(self):
        '''Test check_security_combinations() - override with security-policy'''
        self.set_test_security_profile('iface-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = self._create_top_plugs()
        plugs['iface-other'] = {'interface': 'old-security',
                                'security-override': {"read-paths": ["/a"],
                                                      "write-paths": ["/b"],
                                                      "abstractions": ["cd"],
                                                      "syscalls": ["ef"]},
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc"}
                                }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_all_with_security_policy(self):
        '''Test check_security_combinations() - all with security-policy'''
        self.set_test_security_profile('iface-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('iface-other', 'seccomp',
                                       self._create_sc_raw())
        plugs = self._create_top_plugs()
        plugs['iface-other'] = {'interface': 'old-security',
                                'caps': ['network'],
                                'security-override': {"read-paths": ["/a"],
                                                      "write-paths": ["/b"],
                                                      "abstractions": ["cd"],
                                                      "syscalls": ["ef"]},
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc"},
                                'security-template': "default"
                                }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_plugs_redflag_no_redflagged(self):
        '''Test check_plugs_redflag() - no redflaggede'''
        plugs = {'iface-caps': {'interface': 'old-security',
                                'caps': ['network']},
                 'iface-template': {'interface': 'old-security',
                                    'security-template': "default"}
                 }
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_plugs_redflag()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_plugs_redflag(self):
        '''Test check_plugs_redflag()'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_plugs_redflag()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)

    def test_check_plugs_redflag_no_plugs(self):
        '''Test check_plugs_redflag() - no plugs'''
        self.set_test_snap_yaml("plugs", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_plugs_redflag()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apps_plugs_mapped_oldsecurity(self):
        '''Test check_apps_plugs_mapped_oldsecurity()'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        apps = self._create_apps_plugs()
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apps_plugs_mapped_oldsecurity()
        report = c.click_report
        expected_counts = {'info': 6, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apps_plugs_mapped_oldsecurity_none(self):
        '''Test check_apps_plugs_mapped_oldsecurity() - no apps'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        self.set_test_snap_yaml("apps", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_apps_plugs_mapped_oldsecurity()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apps_plugs_mapped_oldsecurity_bad(self):
        '''Test check_apps_plugs_mapped_oldsecurity() - bad'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        apps = self._create_apps_plugs()
        apps = {'app1': {'plugs': [{}]}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apps_plugs_mapped_oldsecurity()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apps_plugs_mapped_oldsecurity_nonexistent(self):
        '''Test check_apps_plugs_mapped_oldsecurity() - nonexistent'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        apps = self._create_apps_plugs()
        apps = {'app1': {'plugs': ['nonexistent']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apps_plugs_mapped_oldsecurity()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length(self):
        '''Test check_apparmor_profile_name_length()'''
        apps = {'app1': {'plugs': ['iface-caps']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length_no_plugs(self):
        '''Test check_apparmor_profile_name_length()'''
        apps = {'app1': {}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length_bad(self):
        '''Test check_apparmor_profile_name_length() - too long'''
        self.set_test_snap_yaml('name', 'A' * 253)
        apps = {'app1': {'plugs': ['iface-caps']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length_bad2(self):
        '''Test check_apparmor_profile_name_length() - longer than advised'''
        self.set_test_snap_yaml('name', 'A' * 100)
        apps = {'app1': {'plugs': ['iface-caps']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)


class TestSnapReviewSecurityNoMock(TestCase):
    """Tests without mocks where they are not needed."""
    def setUp(self):
        # XXX cleanup_unpack() is required because global variables
        # UNPACK_DIR, RAW_UNPACK_DIR are initialised to None at module
        # load time, but updated when a real (non-Mock) test runs, such as
        # here. While, at the same time, two of the existing tests using
        # mocks depend on both global vars being None. Ideally, those
        # global vars should be refactored away.
        self.addCleanup(cleanup_unpack)
        super().setUp()

    def mkdtemp(self):
        """Create a temp dir which is cleaned up after test."""
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp_dir)
        return tmp_dir

    def check_results(self, report,
                      expected_counts={'info': 1, 'warn': 0, 'error': 0},
                      expected=None):
        common_check_results(self, report, expected_counts, expected)

    def test_check_security_policy_nomock(self):
        '''Test check_security_policy() - no mock'''
        output_dir = self.mkdtemp()

        aa_path = os.path.join(output_dir, 'aa')
        content = '''
###VAR###
###PROFILEATTACH### (attach_disconnected) {
  @{INSTALL_DIR}/@{APP_PKGNAME}/@{APP_VERSION}/**  mrklix,
}
'''

        with open(aa_path, 'w') as f:
            f.write(content)

        sc_path = os.path.join(output_dir, 'sc')
        content = '''
# test comment
 # test comment2
deny ptrace
deny add_key
alarm
usr32

_exit
'''
        with open(sc_path, 'w') as f:
            f.write(content)

        sy_path = os.path.join(output_dir, 'snap.yaml')
        content = '''
name: test
version: 0.1
summary: some thing
description: some desc
architectures: [ amd64 ]
plugs:
    iface-other:
        interface: old-security
        security-policy:
            apparmor: meta/aa
            seccomp: meta/sc
'''
        with open(sy_path, 'w') as f:
            f.write(content)

        package = utils.make_snap2(output_dir=output_dir,
                                   extra_files=['%s:meta/snap.yaml' % sy_path,
                                                '%s:meta/aa' % aa_path,
                                                '%s:meta/sc' % sc_path]
                                   )

        c = SnapReviewSecurity(package)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_squashfs_resquash(self):
        '''Test check_squashfs_resquash()'''
        package = utils.make_snap2(output_dir=self.mkdtemp())
        c = SnapReviewSecurity(package)
        c.check_squashfs_resquash()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_squashfs_resquash_no_fstime(self):
        '''Test check_squashfs_resquash() - no -fstime'''
        output_dir = self.mkdtemp()
        package = utils.make_snap2(output_dir=output_dir)
        c = SnapReviewSecurity(package)

        # fake unsquashfs
        unsquashfs = os.path.join(output_dir, 'unsquashfs')
        content = '''#!/bin/sh
echo test error: -fstime failure
exit 1
'''
        with open(unsquashfs, 'w') as f:
            f.write(content)
        os.chmod(unsquashfs, 0o775)

        old_path = os.environ['PATH']
        if old_path:
            os.environ['PATH'] = "%s:%s" % (output_dir, os.environ['PATH'])
        else:
            os.environ['PATH'] = output_dir  # pragma: nocover

        c.check_squashfs_resquash()
        os.environ['PATH'] = old_path
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_squashfs_resquash_unsquashfs_fail(self):
        '''Test check_squashfs_resquash() - unsquashfs failure'''
        output_dir = self.mkdtemp()
        package = utils.make_snap2(output_dir=output_dir)
        c = SnapReviewSecurity(package)

        # fake unsquashfs
        unsquashfs = os.path.join(output_dir, 'unsquashfs')
        content = '''#!/bin/sh
if [ "$1" = "-fstime" ]; then
    exit 0
fi
echo test error: unsquashfs failure
exit 1
'''
        with open(unsquashfs, 'w') as f:
            f.write(content)
        os.chmod(unsquashfs, 0o775)

        old_path = os.environ['PATH']
        if old_path:
            os.environ['PATH'] = "%s:%s" % (output_dir, os.environ['PATH'])
        else:
            os.environ['PATH'] = output_dir  # pragma: nocover

        c.check_squashfs_resquash()
        os.environ['PATH'] = old_path
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_squashfs_resquash_mksquashfs_fail(self):
        '''Test check_squashfs_resquash() - mksquashfs failure'''
        output_dir = self.mkdtemp()
        package = utils.make_snap2(output_dir=output_dir)
        c = SnapReviewSecurity(package)

        # fake mksquashfs
        mksquashfs = os.path.join(output_dir, 'mksquashfs')
        content = '''#!/bin/sh
echo test error: mksquashfs failure
exit 1
'''
        with open(mksquashfs, 'w') as f:
            f.write(content)
        os.chmod(mksquashfs, 0o775)

        old_path = os.environ['PATH']
        if old_path:
            os.environ['PATH'] = "%s:%s" % (output_dir, os.environ['PATH'])
        else:
            os.environ['PATH'] = output_dir  # pragma: nocover

        c.check_squashfs_resquash()
        os.environ['PATH'] = old_path
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_squashfs_resquash_sha512sum_fail(self):
        '''Test check_squashfs_resquash() - sha512sum failure'''
        output_dir = self.mkdtemp()
        package = utils.make_snap2(output_dir=output_dir)
        c = SnapReviewSecurity(package)

        # fake sha512sum
        sha512sum = os.path.join(output_dir, 'sha512sum')
        content = '''#!/bin/sh
bn=`basename "$1"`
if [ "$bn" = "test_1.0_all.snap" ]; then
    echo test error: sha512sum failure
    exit 1
fi
exit 0
'''
        with open(sha512sum, 'w') as f:
            f.write(content)
        os.chmod(sha512sum, 0o775)

        old_path = os.environ['PATH']
        if old_path:
            os.environ['PATH'] = "%s:%s" % (output_dir, os.environ['PATH'])
        else:
            os.environ['PATH'] = output_dir  # pragma: nocover

        c.check_squashfs_resquash()
        os.environ['PATH'] = old_path
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_squashfs_resquash_sha512sum_fail_repacked(self):
        '''Test check_squashfs_resquash() - sha512sum failure (repacked)'''
        output_dir = self.mkdtemp()
        package = utils.make_snap2(output_dir=output_dir)
        c = SnapReviewSecurity(package)

        # fake sha512sum
        sha512sum = os.path.join(output_dir, 'sha512sum')
        content = '''#!/bin/sh
bn=`basename "$1"`
if [ "$bn" != "test_1.0_all.snap" ]; then
    echo test error: sha512sum failure
    exit 1
fi
echo deadbeef $1
exit 0
'''
        with open(sha512sum, 'w') as f:
            f.write(content)
        os.chmod(sha512sum, 0o775)

        old_path = os.environ['PATH']
        if old_path:
            os.environ['PATH'] = "%s:%s" % (output_dir, os.environ['PATH'])
        else:
            os.environ['PATH'] = output_dir  # pragma: nocover

        c.check_squashfs_resquash()
        os.environ['PATH'] = old_path
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_squashfs_resquash_sha512sum_mismatch(self):
        '''Test check_squashfs_resquash() - sha512sum mismatch'''
        output_dir = self.mkdtemp()
        package = utils.make_snap2(output_dir=output_dir)
        c = SnapReviewSecurity(package)

        # fake sha512sum
        sha512sum = os.path.join(output_dir, 'sha512sum')
        content = '''#!/bin/sh
bn=`basename "$1"`
if [ "$bn" = "test_1.0_all.snap" ]; then
    echo beefeeee $1
else
    echo deadbeef $1
fi
exit 0
'''
        with open(sha512sum, 'w') as f:
            f.write(content)
        os.chmod(sha512sum, 0o775)

        old_path = os.environ['PATH']
        if old_path:
            os.environ['PATH'] = "%s:%s" % (output_dir, os.environ['PATH'])
        else:
            os.environ['PATH'] = output_dir  # pragma: nocover

        c.check_squashfs_resquash()
        os.environ['PATH'] = old_path
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_squashfs_resquash_sha512sum_mismatch_os(self):
        '''Test check_squashfs_resquash() - sha512sum mismatch - os snap'''
        output_dir = self.mkdtemp()
        package = utils.make_snap2(output_dir=output_dir)

        sy_path = os.path.join(output_dir, 'snap.yaml')
        content = '''
name: test
version: 0.1
summary: some thing
description: some desc
architectures: [ amd64 ]
type: os
'''
        with open(sy_path, 'w') as f:
            f.write(content)

        package = utils.make_snap2(output_dir=output_dir,
                                   extra_files=['%s:meta/snap.yaml' % sy_path]
                                   )

        c = SnapReviewSecurity(package)

        # fake sha512sum
        sha512sum = os.path.join(output_dir, 'sha512sum')
        content = '''#!/bin/sh
bn=`basename "$1"`
if [ "$bn" = "test_1.0_all.snap" ]; then
    echo beefeeee $1
else
    echo deadbeef $1
fi
exit 0
'''
        with open(sha512sum, 'w') as f:
            f.write(content)
        os.chmod(sha512sum, 0o775)

        old_path = os.environ['PATH']
        if old_path:
            os.environ['PATH'] = "%s:%s" % (output_dir, os.environ['PATH'])
        else:
            os.environ['PATH'] = output_dir  # pragma: nocover

        c.check_squashfs_resquash()
        os.environ['PATH'] = old_path
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)
