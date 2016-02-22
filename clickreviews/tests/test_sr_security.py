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

    def _create_top_uses(self):
        self.set_test_security_profile('skill-policy', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-policy', 'seccomp',
                                       self._create_sc_raw())

        uses = {'skill-caps': {'type': 'migration-skill',
                               'caps': ['network-client']},
                'skill-override': {'type': 'migration-skill',
                                   'security-override': {"read-paths": ["/a"],
                                                         "write-paths": ["/b"],
                                                         "abstractions": ["cd"],
                                                         "syscalls": ["ef"]}},
                'skill-policy': {'type': 'migration-skill',
                                 'security-policy': {"apparmor": "meta/aa",
                                                     "seccomp": "meta/sc"}},
                'skill-template': {'type': 'migration-skill',
                                   'security-template': "default"}
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

    def test_check_security_caps_no_uses(self):
        '''Test check_security_caps() - no uses'''
        self.set_test_snap_yaml("uses", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_caps()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
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

    def test_check_security_override(self):
        '''Test check_security_override()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_override_no_uses(self):
        '''Test check_security_override() - no uses'''
        self.set_test_snap_yaml("uses", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_override_empty(self):
        '''Test check_security_override() - empty'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override'] = {}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_unknown(self):
        '''Test check_security_override() - unknown'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['nonexistent'] = ['foo']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_syscall_dict(self):
        '''Test check_security_override() - bad'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['syscalls'] = {}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_syscall(self):
        '''Test check_security_override() - bad syscall (illegal)'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['syscalls'] = ['BAD#%^']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_syscall_short(self):
        '''Test check_security_override() - bad syscall (short)'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['syscalls'] = ['a']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_syscall_long(self):
        '''Test check_security_override() - bad syscall (long)'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['syscalls'] = ['a' * 65]
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_abstraction_dict(self):
        '''Test check_security_override() - bad'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['abstractions'] = {}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_abstraction(self):
        '''Test check_security_override() - bad abstraction (illegal)'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['abstractions'] = ['BAD#%^']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_abstraction_short(self):
        '''Test check_security_override() - bad abstraction (short)'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['abstractions'] = ['a']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_abstraction_long(self):
        '''Test check_security_override() - bad abstraction (long)'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['abstractions'] = ['a' * 65]
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_read_path_var(self):
        '''Test check_security_override() - @{HOME}/foo'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['read-paths'] = \
            ["@{HOME}/foo"]
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_read_path_dict(self):
        '''Test check_security_override() - bad'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['read-paths'] = {}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_read_path(self):
        '''Test check_security_override() - bad (relative)'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['read-paths'] = \
            ['relative/path']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_write_path_var(self):
        '''Test check_security_override() - @{HOME}/foo'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['write-paths'] = \
            ["@{HOME}/foo"]
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_write_path_dict(self):
        '''Test check_security_override() - bad'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['write-paths'] = {}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_override_bad_write_path(self):
        '''Test check_security_override() - bad (relative)'''
        uses = self._create_top_uses()
        uses['skill-override']['security-override']['write-paths'] = \
            ['relative/path']
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_override()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_policy(self):
        '''Test check_security_policy()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_policy_no_uses(self):
        '''Test check_security_policy() - no uses'''
        self.set_test_snap_yaml("uses", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_policy_unknown(self):
        '''Test check_security_policy() - unknown'''
        self.set_test_security_profile('skill-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = {'skill-other': {'type': 'migration-skill',
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc",
                                                    "nonexistent": "bad"},
                                }
                }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_policy_empty(self):
        '''Test check_security_policy() - empty'''
        self.set_test_security_profile('skill-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = {'skill-other': {'type': 'migration-skill',
                                'security-policy': {}}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)

    def test_check_security_policy_bad(self):
        '''Test check_security_policy() - bad (list)'''
        self.set_test_security_profile('skill-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = {'skill-other': {'type': 'migration-skill',
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": []}
                                }
                }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def _test_check_security_policy_tmpl(self):
        '''Test check_security_policy() - tmpl'''
        self.set_test_security_profile('skill-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = {'skill-other': {'type': 'migration-skill',
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc",
                                                    }
                                }
                }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': -1}
        self.check_results(report, expected_counts)

    def test_check_security_policy_missing_apparmor(self):
        '''Test check_security_policy() - missing apparmor'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.raw_profiles['skill-policy'].pop('apparmor')
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_policy_missing_seccomp(self):
        '''Test check_security_policy() - missing seccomp'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.raw_profiles['skill-policy'].pop('seccomp')
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
        self.set_test_security_profile('skill-other', 'apparmor', contents)
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = {'skill-other': {'type': 'migration-skill',
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc",
                                                    }
                                }
                }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:security-policy_apparmor_var:skill-other'
        expected['info'][name] = {"text": "SKIPPED for '@{INSTALL_DIR}' (boilerplate)"}
        self.check_results(report, expected=expected)

    def test_check_security_policy_apparmor_boiler2(self):
        '''Test check_security_policy() - boilerplate text #2'''
        contents = '''
###VAR###
###PROFILEATTACH### (attach_disconnected) {}
# This profile offers no protection
'''
        self.set_test_security_profile('skill-other', 'apparmor', contents)
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = {'skill-other': {'type': 'migration-skill',
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc",
                                                    }
                                }
                }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:security-policy_apparmor_var:skill-other'
        expected['info'][name] = {"text": "SKIPPED for '@{INSTALL_DIR}' (boilerplate)"}
        self.check_results(report, expected=expected)

    def test_check_security_policy_missing_apparmor_var(self):
        '''Test check_security_policy() - missing apparmor var'''
        contents = '''
###PROFILEATTACH### (attach_disconnected) {
  @{INSTALL_DIR}/@{APP_PKGNAME}/@{APP_VERSION}/**  mrklix,
}
'''
        self.set_test_security_profile('skill-other', 'apparmor', contents)
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = {'skill-other': {'type': 'migration-skill',
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc",
                                                    }
                                }
                }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        print(c.raw_profiles)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_policy_bad_seccomp(self):
        '''Test check_security_policy() - bad seccomp'''
        contents = self._create_sc_raw() + "\nBAD%$\n"
        self.set_test_security_profile('skill-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-other', 'seccomp', contents)
        uses = {'skill-other': {'type': 'migration-skill',
                                'security-policy': {"apparmor": "meta/aa",
                                                    "seccomp": "meta/sc",
                                                    }
                                }
                }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        print(c.raw_profiles)
        c.check_security_policy()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_template(self):
        '''Test check_security_template()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_no_uses(self):
        '''Test check_security_template()'''
        self.set_test_snap_yaml("uses", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_with_nonmigration(self):
        '''Test check_security_template() - with non-migration'''
        uses = self._create_top_uses()
        uses['bool'] = {'type': 'bool-file', 'path': '/sys/devices/gpio1'}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_with_apps(self):
        '''Test check_security_template()'''
        uses = self._create_top_uses()
        apps = self._create_apps_uses()
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_template_with_frameworks(self):
        '''Test check_security_template() - with framework'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        uses['myfwk'] = {'type': 'migration-skill',
                         'security-template': 'fwk_1'}
        self.set_test_snap_yaml("frameworks", ["fwk"])
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        # the errors here are because we don't know the framework policy
        # 'type'. This needs support from the store
        expected_counts = {'info': 3, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:template_safe:myfwk:fwk_1'
        expected['error'][name] = {"text": "unknown type 'None' for template 'fwk_1'"}
        self.check_results(report, expected=expected)

    def test_check_security_template_is_framework_with_framework_template(self):
        '''Test check_security_template() - is framework with framework template'''
        pkgname = self.test_name.split('_')[0].split('.')[0]
        template = '%s_1' % pkgname
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        uses['myfwk'] = {'type': 'migration-skill',
                         'security-template': template}
        self.set_test_snap_yaml("type", "framework")
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        # the errors here are because we don't know the framework policy
        # 'type'. This needs support from the store
        expected_counts = {'info': 3, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:template_safe:myfwk:%s' % template
        expected['error'][name] = {"text":
                                   "unknown type 'None' for template '%s'" % template}
        self.check_results(report, expected=expected)

    def test_check_security_template_nonexistent(self):
        '''Test check_security_template() - nonexistent'''
        uses = self._create_top_uses()
        uses['skill-template']['security-template'] = 'nonexistent'
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_template_common(self):
        '''Test check_security_template() - common'''
        template = "safe"
        uses = self._create_top_uses()
        uses['skill-template']['security-template'] = template
        self.set_test_snap_yaml("uses", uses)
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
        uses = self._create_top_uses()
        uses['skill-template']['security-template'] = template
        self.set_test_snap_yaml("uses", uses)
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
        uses = self._create_top_uses()
        uses['skill-template']['security-template'] = template
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["templates"]["nonexistent"] = \
            template
        c.check_security_template()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations(self):
        '''Test check_security_combinations()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_no_uses(self):
        '''Test check_security_combinations() - no uses'''
        self.set_test_snap_yaml("uses", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_no_apps(self):
        '''Test check_security_combinations()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps(self):
        '''Test check_security_combinations() - apps'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        apps = self._create_apps_uses()
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 8, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_uses_nonsecurity(self):
        '''Test check_security_combinations() - uses non-security'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        apps = self._create_apps_uses()
        apps = {'app5': {'uses': ['other']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_caps_with_security_policy(self):
        '''Test check_security_combinations() - apps caps with security-policy'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        apps = self._create_apps_uses()
        apps['app1'] = {'uses': ['skill-caps', 'skill-policy']}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_template_with_security_policy(self):
        '''Test check_security_combinations() - apps security-template with security-policy'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        apps = self._create_apps_uses()
        apps['app1'] = {'uses': ['skill-template', 'skill-policy']}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_override_with_security_policy(self):
        '''Test check_security_combinations() - apps security-override with security-policy'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        apps = self._create_apps_uses()
        apps['app1'] = {'uses': ['skill-override', 'skill-policy']}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_apps_all_with_security_policy(self):
        '''Test check_security_combinations() - apps all with security-policy'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        apps = self._create_apps_uses()
        apps['app1'] = {'uses': ['skill-override', 'skill-policy',
                                 'skill-caps', 'skill-template']}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_caps_with_security_policy(self):
        '''Test check_security_combinations() - caps with security-policy'''
        self.set_test_security_profile('skill-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = self._create_top_uses()
        uses['skill-other'] = {'type': 'migration-skill',
                               'caps': ['network-client'],
                               'security-policy': {"apparmor": "meta/aa",
                                                   "seccomp": "meta/sc"}
                               }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_template_with_security_policy(self):
        '''Test check_security_combinations() - template with security-policy'''
        self.set_test_security_profile('skill-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = self._create_top_uses()
        uses['skill-other'] = {'type': 'migration-skill',
                               'security-policy': {"apparmor": "meta/aa",
                                                   "seccomp": "meta/sc"},
                               'security-template': "default"
                               }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_override_with_security_policy(self):
        '''Test check_security_combinations() - override with security-policy'''
        self.set_test_security_profile('skill-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = self._create_top_uses()
        uses['skill-other'] = {'type': 'migration-skill',
                               'security-override': {"read-paths": ["/a"],
                                                     "write-paths": ["/b"],
                                                     "abstractions": ["cd"],
                                                     "syscalls": ["ef"]},
                               'security-policy': {"apparmor": "meta/aa",
                                                   "seccomp": "meta/sc"}
                               }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_combinations_all_with_security_policy(self):
        '''Test check_security_combinations() - all with security-policy'''
        self.set_test_security_profile('skill-other', 'apparmor',
                                       self._create_aa_raw())
        self.set_test_security_profile('skill-other', 'seccomp',
                                       self._create_sc_raw())
        uses = self._create_top_uses()
        uses['skill-other'] = {'type': 'migration-skill',
                               'caps': ['network-client'],
                               'security-override': {"read-paths": ["/a"],
                                                     "write-paths": ["/b"],
                                                     "abstractions": ["cd"],
                                                     "syscalls": ["ef"]},
                               'security-policy': {"apparmor": "meta/aa",
                                                   "seccomp": "meta/sc"},
                               'security-template': "default"
                               }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_combinations()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_uses_redflag_no_redflagged(self):
        '''Test check_uses_redflag() - no redflaggede'''
        uses = {'skill-caps': {'type': 'migration-skill',
                               'caps': ['network-client']},
                'skill-template': {'type': 'migration-skill',
                                   'security-template': "default"}
                }
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_uses_redflag()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
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

    def test_check_uses_redflag_no_uses(self):
        '''Test check_uses_redflag() - no uses'''
        self.set_test_snap_yaml("uses", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_uses_redflag()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apps_uses_mapped_migration(self):
        '''Test check_apps_uses_mapped_migration()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        apps = self._create_apps_uses()
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apps_uses_mapped_migration()
        report = c.click_report
        expected_counts = {'info': 6, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apps_uses_mapped_migration_none(self):
        '''Test check_apps_uses_mapped_migration() - no apps'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_apps_uses_mapped_migration()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apps_uses_mapped_migration_bad(self):
        '''Test check_apps_uses_mapped_migration() - bad'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        apps = self._create_apps_uses()
        apps = {'app1': {'uses': [{}]}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apps_uses_mapped_migration()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apps_uses_mapped_migration_nonexistent(self):
        '''Test check_apps_uses_mapped_migration() - nonexistent'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        apps = self._create_apps_uses()
        apps = {'app1': {'uses': ['nonexistent']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apps_uses_mapped_migration()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length(self):
        '''Test check_apparmor_profile_name_length()'''
        apps = {'app1': {'uses': ['skill-caps']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length_no_uses(self):
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
        apps = {'app1': {'uses': ['skill-caps']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_apparmor_profile_name_length_bad2(self):
        '''Test check_apparmor_profile_name_length() - longer than advised'''
        self.set_test_snap_yaml('name', 'A' * 100)
        apps = {'app1': {'uses': ['skill-caps']}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_apparmor_profile_name_length()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)
