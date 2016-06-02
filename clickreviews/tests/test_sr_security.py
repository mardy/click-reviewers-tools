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

    def _create_top_plugs(self):
        plugs = {'iface-network': {'interface': 'network'},
                 'network-bind': {},
                 }
        return plugs

    def _create_apps_plugs(self):
        plugs = {'app1': {'plugs': ['iface-network']},
                 'app2': {'plugs': ['network-bind']},
                 'app3': {'plugs': ['iface-network', 'network-bind']},
                 }
        return plugs

    def _create_top_slots(self):
        slots = {'iface-slot1': {'interface': 'network'},
                 'network-bind': {},
                 }
        return slots

    def _create_apps_slots(self):
        slots = {'app1': {'slots': ['iface-slot1']},
                 'app2': {'slots': ['network-bind']},
                 }
        return slots

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

    def test_check_security_plugs(self):
        ''' Test check_security_plugs()'''
        plugs = self._create_top_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_none(self):
        ''' Test check_security_plugs() - None'''
        self.set_test_snap_yaml("plugs", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_empty(self):
        ''' Test check_security_plugs() - empty'''
        self.set_test_snap_yaml("plugs", {})
        c = SnapReviewSecurity(self.test_name)
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_debug(self):
        ''' Test check_security_plugs() - debug'''
        plugs = self._create_top_plugs()
        plugs['debug'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append("debug")
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_reserved(self):
        ''' Test check_security_plugs() - reserved'''
        plugs = self._create_top_plugs()
        plugs['rsrved'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append("rsrved")
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_reserved_strict(self):
        ''' Test check_security_plugs() - reserved (strict)'''
        plugs = self._create_top_plugs()
        plugs['rsrved'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        self.set_test_snap_yaml("confinement", "strict")
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append("rsrved")
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_reserved_devmode(self):
        ''' Test check_security_plugs() - reserved (devmode)'''
        plugs = self._create_top_plugs()
        plugs['rsrved'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        self.set_test_snap_yaml("confinement", "devmode")
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append("rsrved")
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:plug_safe:rsrved:rsrved'
        expected['info'][name] = {"text": "[ERROR] reserved interface "
                                          "'rsrved' for vetted applications "
                                          "only",
                                  "manual_review": False}
        self.check_results(report, expected=expected)

    def test_check_security_plugs_reserved_home(self):
        ''' Test check_security_plugs() - reserved (home)'''
        plugs = self._create_top_plugs()
        plugs['home'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_reserved_home_unity7_override(self):
        ''' Test check_security_plugs() - reserved overriden (home/unity7)'''
        plugs = self._create_top_plugs()
        plugs['home'] = {}
        plugs['unity7'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_reserved_home_x11_override(self):
        ''' Test check_security_plugs() - reserved overriden (home/x11)'''
        plugs = self._create_top_plugs()
        plugs['home'] = {}
        plugs['x11'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_unknown_type(self):
        ''' Test check_security_plugs() - unknown type'''
        plugs = self._create_top_plugs()
        plugs['bad-type'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["nonexistent"] = ["bad-type"]
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_plugs_nonexistent(self):
        ''' Test check_security_plugs() - nonexistent'''
        plugs = dict()
        plugs['nonexistent'] = {}
        self.set_test_snap_yaml("plugs", plugs)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_plugs()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_apps_plugs(self):
        ''' Test check_security_apps_plugs()'''
        plugs = self._create_top_plugs()
        apps = self._create_apps_plugs()
        self.set_test_snap_yaml("plugs", plugs)
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_apps_plugs()
        report = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

        # Note: c.check_security_apps_plugs() only checks plugs that are not
        # referenced in the toplevel plugs so while self._create_apps_plugs()
        # has four apps, only two of the apps reference plugs not in the
        # toplevel plugs.
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:app_plug_safe:app2:network-bind'
        expected['info'][name] = {"text": "OK"}
        name = 'security-snap-v2:app_plug_safe:app3:network-bind'
        expected['info'][name] = {"text": "OK"}
        self.check_results(report, expected=expected)

    def test_check_security_apps_plugs_none(self):
        ''' Test check_security_apps_plugs() - None'''
        self.set_test_snap_yaml("apps", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_apps_plugs()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_apps_plugs_bad(self):
        ''' Test check_security_apps_plugs() - bad'''
        apps = {'app1': {'plugs': [{}]}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_apps_plugs()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_apps_plugs_empty(self):
        ''' Test check_security_apps_plugs() - empty'''
        apps = {'app1': {'plugs': []}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_apps_plugs()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_slots(self):
        ''' Test check_security_slots()'''
        slots = self._create_top_slots()
        self.set_test_snap_yaml("slots", slots)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_slots()
        report = c.click_report
        # specifying slots currently requires manual review
        expected_counts = {'info': 2, 'warn': 2, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_slots_none(self):
        ''' Test check_security_slots() - None'''
        self.set_test_snap_yaml("slots", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_slots()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_slots_empty(self):
        ''' Test check_security_slots() - empty'''
        self.set_test_snap_yaml("slots", {})
        c = SnapReviewSecurity(self.test_name)
        c.check_security_slots()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_slots_debug(self):
        ''' Test check_security_slots() - debug'''
        slots = self._create_top_slots()
        slots['debug'] = {}
        self.set_test_snap_yaml("slots", slots)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append("debug")
        c.check_security_slots()
        report = c.click_report
        expected_counts = {'info': None, 'warn': None, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_slots_reserved(self):
        ''' Test check_security_slots() - reserved'''
        slots = self._create_top_slots()
        slots['rsrved'] = {}
        self.set_test_snap_yaml("slots", slots)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append("rsrved")
        c.check_security_slots()
        report = c.click_report
        expected_counts = {'info': None, 'warn': None, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_slots_reserved_strict(self):
        ''' Test check_security_slots() - reserved (strict)'''
        slots = self._create_top_slots()
        slots['rsrved'] = {}
        self.set_test_snap_yaml("slots", slots)
        self.set_test_snap_yaml("confinement", "strict")
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append("rsrved")
        c.check_security_slots()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 3, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_slots_reserved_devmode(self):
        ''' Test check_security_plugs() - reserved (devmode)'''
        slots = self._create_top_slots()
        slots['rsrved'] = {}
        self.set_test_snap_yaml("slots", slots)
        self.set_test_snap_yaml("confinement", "devmode")
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["reserved"].append("rsrved")
        c.check_security_slots()
        report = c.click_report
        expected_counts = {'info': 6, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:slot_safe:rsrved:rsrved'
        expected['info'][name] = {"text": "[ERROR] reserved interface "
                                          "'rsrved' for vetted applications "
                                          "only",
                                  "manual_review": False}
        name = 'security-snap-v2:is_slot:rsrved:rsrved'
        expected['info'][name] = {"text": "[WARN] (NEEDS REVIEW) slots "
                                          "requires approval",
                                  "manual_review": False}
        self.check_results(report, expected=expected)

    def test_check_security_slots_unknown_type(self):
        ''' Test check_security_slots() - unknown type'''
        slots = self._create_top_slots()
        slots['bad-type'] = {}
        self.set_test_snap_yaml("slots", slots)
        c = SnapReviewSecurity(self.test_name)
        c.aa_policy["ubuntu-core"]["16.04"]["policy_groups"]["nonexistent"] = ["bad-type"]
        c.check_security_slots()
        report = c.click_report
        expected_counts = {'info': None, 'warn': None, 'error': 1}
        self.check_results(report, expected_counts)

    def test_check_security_slots_nonexistent(self):
        ''' Test check_security_slots() - nonexistent'''
        slots = dict()
        slots['nonexistent'] = {}
        self.set_test_snap_yaml("slots", slots)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_slots()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_apps_slots(self):
        ''' Test check_security_apps_slots()'''
        slots = self._create_top_slots()
        apps = self._create_apps_slots()
        self.set_test_snap_yaml("slots", slots)
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_apps_slots()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 1, 'error': 0}
        self.check_results(report, expected_counts)

        # Note: c.check_security_apps_slots() only checks slots that are not
        # referenced in the toplevel slots so while self._create_apps_slots()
        # has two apps, only one of the apps reference slots not in the
        # toplevel slots.
        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:app_slot_safe:app2:network-bind'
        expected['info'][name] = {"text": "OK"}
        self.check_results(report, expected=expected)

    def test_check_security_apps_slots_none(self):
        ''' Test check_security_apps_slots() - None'''
        self.set_test_snap_yaml("apps", None)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_apps_slots()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_apps_slots_bad(self):
        ''' Test check_security_apps_slots() - bad'''
        apps = {'app1': {'slots': [{}]}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_apps_slots()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

    def test_check_security_apps_slots_empty(self):
        ''' Test check_security_apps_slots() - empty'''
        apps = {'app1': {'slots': []}}
        self.set_test_snap_yaml("apps", apps)
        c = SnapReviewSecurity(self.test_name)
        c.check_security_apps_slots()
        report = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
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
        # FIXME: this should error but we've turned it into an info until the
        # squashfs-tools bugs can be fixed
        # expected_counts = {'info': None, 'warn': 0, 'error': 1}
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
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

    def test_check_squashfs_resquash_1555305(self):
        '''Test check_squashfs_resquash()'''
        package = utils.make_snap2(output_dir=self.mkdtemp(),
                                   extra_files=['/some/where,outside'])
        c = SnapReviewSecurity(package)
        c.check_squashfs_resquash()
        report = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(report, expected_counts)

        expected = dict()
        expected['error'] = dict()
        expected['warn'] = dict()
        expected['info'] = dict()
        name = 'security-snap-v2:squashfs_resquash_1555305'
        expected['info'][name] = {"link": "https://launchpad.net/bugs/1555305"}
        self.check_results(report, expected=expected)

    def test_check_squashfs_resquash_unsquashfs_fail_1555305(self):
        '''Test check_squashfs_resquash() - unsquashfs failure'''
        output_dir = self.mkdtemp()
        package = utils.make_snap2(output_dir=output_dir)
        c = SnapReviewSecurity(package)

        # fake unsquashfs
        unsquashfs = os.path.join(output_dir, 'unsquashfs')
        content = '''#!/bin/sh
if [ "$1" = "-fstime" ] || [ "$1" = "-lls" ]; then
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
