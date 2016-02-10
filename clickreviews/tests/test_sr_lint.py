'''test_sr_lint.py: tests for the sr_lint module'''
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

from unittest.mock import patch
from clickreviews.sr_lint import SnapReviewLint
import clickreviews.sr_tests as sr_tests
import os


class TestSnapReviewLint(sr_tests.TestSnapReview):
    """Tests for the lint review tool."""
    def setUp(self):
        '''Make sure we are snap v2'''
        super().setUp()
        self.set_test_pkgfmt("snap", "16.04")

    def _create_ports(self):
        ports = {'internal': {'int1': {"port": '8081/tcp', "negotiable": True}},
                 'external': {'ext1': {"port": '80/tcp', "negotiable": False},
                              'ext2': {"port": '88/udp'}
                              }
                 }
        return ports

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

    def patch_frameworks(self):
        def _mock_frameworks(self, overrides=None):
            self.FRAMEWORKS = {
                'docker-1.3': 'obsolete',
                'docker': 'available',
                'hello-dbus-fwk': 'available',
                'some-fwk': 'deprecated',
            }
            self.AVAILABLE_FRAMEWORKS = ['docker', 'hello-dbus-fwk']
            self.OBSOLETE_FRAMEWORKS = ['docker-1.3']
            self.DEPRECATED_FRAMEWORKS = ['some-fwk']
        p = patch('clickreviews.frameworks.Frameworks.__init__',
                  _mock_frameworks)
        p.start()
        self.addCleanup(p.stop)

    def test_all_checks_as_v2(self):
        '''Test snap v2 has checks'''
        self.set_test_pkgfmt("snap", "16.04")
        c = SnapReviewLint(self.test_name)
        c.do_checks()
        sum = 0
        for i in c.click_report:
            sum += len(c.click_report[i])
        self.assertTrue(sum != 0)

    def test_all_checks_as_v1(self):
        '''Test snap v1 has no checks'''
        self.set_test_pkgfmt("snap", "15.04")
        c = SnapReviewLint(self.test_name)
        c.do_checks()
        sum = 0
        for i in c.click_report:
            sum += len(c.click_report[i])
        self.assertTrue(sum == 0)

    def test_all_checks_as_click(self):
        '''Test click format has no checks'''
        self.set_test_pkgfmt("click", "0.4")
        c = SnapReviewLint(self.test_name)
        c.do_checks()
        sum = 0
        for i in c.click_report:
            sum += len(c.click_report[i])
        self.assertTrue(sum == 0)

    def test_check_frameworks_none(self):
        '''Test check_frameworks() - none'''
        self.patch_frameworks()
        self.set_test_snap_yaml("frameworks", None)
        c = SnapReviewLint(self.test_name)
        c.check_frameworks()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_frameworks_empty(self):
        '''Test check_frameworks() - empty'''
        self.patch_frameworks()
        self.set_test_snap_yaml("frameworks", [])
        c = SnapReviewLint(self.test_name)
        c.check_frameworks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_frameworks_multiple(self):
        '''Test check_frameworks() - multiple'''
        self.patch_frameworks()
        self.set_test_snap_yaml("frameworks", ['docker', 'hello-dbus-fwk'])
        c = SnapReviewLint(self.test_name)
        c.check_frameworks()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_frameworks_bad(self):
        '''Test check_frameworks() - bad'''
        self.patch_frameworks()
        self.set_test_snap_yaml("frameworks", "bad")
        c = SnapReviewLint(self.test_name)
        c.check_frameworks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_frameworks_nonexistent(self):
        '''Test check_frameworks() - nonexistent'''
        self.patch_frameworks()
        self.set_test_snap_yaml("frameworks", ["nonexistent"])
        c = SnapReviewLint(self.test_name)
        c.check_frameworks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_frameworks_deprecated(self):
        '''Test check_frameworks() - deprecated'''
        self.patch_frameworks()
        self.set_test_snap_yaml("frameworks", ["some-fwk"])
        c = SnapReviewLint(self.test_name)
        c.check_frameworks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_frameworks_obsolete(self):
        '''Test check_frameworks() - obsolete'''
        self.patch_frameworks()
        self.set_test_snap_yaml("frameworks", ["docker-1.3"])
        c = SnapReviewLint(self.test_name)
        c.check_frameworks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_name_toplevel(self):
        '''Test check_name - toplevel'''
        self.set_test_snap_yaml("name", "foo")
        c = SnapReviewLint(self.test_name)
        c.check_name()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_name_flat(self):
        '''Test check_name - obsoleted flat'''
        self.set_test_snap_yaml("name", "foo.bar")
        c = SnapReviewLint(self.test_name)
        c.check_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_name_reverse_domain(self):
        '''Test check_name - obsoleted reverse domain'''
        self.set_test_snap_yaml("name", "com.ubuntu.develeper.baz.foo")
        c = SnapReviewLint(self.test_name)
        c.check_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_name_bad(self):
        '''Test check_name - bad'''
        self.set_test_snap_yaml("name", "foo?bar")
        c = SnapReviewLint(self.test_name)
        c.check_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_name_bad2(self):
        '''Test check_name - empty'''
        self.set_test_snap_yaml("name", "")
        c = SnapReviewLint(self.test_name)
        c.check_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_name_bad3(self):
        '''Test check_name - list'''
        self.set_test_snap_yaml("name", [])
        c = SnapReviewLint(self.test_name)
        c.check_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_name_bad4(self):
        '''Test check_name - dict'''
        self.set_test_snap_yaml("name", {})
        c = SnapReviewLint(self.test_name)
        c.check_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_version(self):
        '''Test check_version'''
        self.set_test_snap_yaml("version", 1)
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_version1(self):
        '''Test check_version - integer'''
        self.set_test_snap_yaml("version", 1)
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_version2(self):
        '''Test check_version - float'''
        self.set_test_snap_yaml("version", 1.0)
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_version3(self):
        '''Test check_version - MAJOR.MINOR.MICRO'''
        self.set_test_snap_yaml("version", "1.0.1")
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_version4(self):
        '''Test check_version - str'''
        self.set_test_snap_yaml("version", "1.0a")
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_version5(self):
        '''Test check_version - alpha'''
        self.set_test_snap_yaml("version", "a.b")
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_version_bad(self):
        '''Test check_version - bad'''
        self.set_test_snap_yaml("version", "foo?bar")
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_version_bad2(self):
        '''Test check_version - empty'''
        self.set_test_snap_yaml("version", "")
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_version_bad3(self):
        '''Test check_version - list'''
        self.set_test_snap_yaml("version", [])
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_version_bad4(self):
        '''Test check_version - dict'''
        self.set_test_snap_yaml("version", {})
        c = SnapReviewLint(self.test_name)
        c.check_version()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_type(self):
        '''Test check_type - unspecified'''
        self.set_test_snap_yaml("type", None)
        c = SnapReviewLint(self.test_name)
        c.check_type()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_type_app(self):
        '''Test check_type - app'''
        self.set_test_snap_yaml("type", "app")
        c = SnapReviewLint(self.test_name)
        c.check_type()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_type_framework(self):
        '''Test check_type - framework'''
        self.set_test_snap_yaml("type", "framework")
        c = SnapReviewLint(self.test_name)
        c.check_type()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_type_redflagged(self):
        '''Test check_type_redflagged - unspecified'''
        self.set_test_snap_yaml("type", None)
        c = SnapReviewLint(self.test_name)
        c.check_type_redflagged()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_type_redflagged_app(self):
        '''Test check_type_redflagged - app'''
        self.set_test_snap_yaml("type", "app")
        c = SnapReviewLint(self.test_name)
        c.check_type_redflagged()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_type_redflagged_framework(self):
        '''Test check_type_redflagged - framework'''
        self.set_test_snap_yaml("type", "framework")
        c = SnapReviewLint(self.test_name)
        c.check_type_redflagged()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_type_redflagged_gadget(self):
        '''Test check_type_redflagged - gadget'''
        self.set_test_snap_yaml("type", "gadget")
        c = SnapReviewLint(self.test_name)
        c.check_type_redflagged()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_type_redflagged_kernel(self):
        '''Test check_type_redflagged - kernel'''
        self.set_test_snap_yaml("type", "kernel")
        c = SnapReviewLint(self.test_name)
        c.check_type_redflagged()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_type_redflagged_os(self):
        '''Test check_type_redflagged - os'''
        self.set_test_snap_yaml("type", "os")
        c = SnapReviewLint(self.test_name)
        c.check_type_redflagged()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_icon(self):
        '''Test check_icon()'''
        self.set_test_snap_yaml("icon", "someicon")
        self.set_test_snap_yaml("type", "gadget")
        c = SnapReviewLint(self.test_name)
        c.pkg_files.append('/fake/someicon')
        c.check_icon()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_icon_no_gadget(self):
        '''Test check_icon() - no gadget'''
        self.set_test_snap_yaml("icon", "someicon")
        c = SnapReviewLint(self.test_name)
        c.check_icon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_icon_unspecified(self):
        '''Test check_icon() - unspecified'''
        self.set_test_snap_yaml("icon", None)
        self.set_test_snap_yaml("type", "gadget")
        c = SnapReviewLint(self.test_name)
        c.unpack_dir = "/nonexistent"
        c.check_icon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_icon_empty(self):
        '''Test check_icon() - empty'''
        self.set_test_snap_yaml("icon", "")
        self.set_test_snap_yaml("type", "gadget")
        c = SnapReviewLint(self.test_name)
        c.unpack_dir = "/nonexistent"
        c.check_icon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_icon_absolute_path(self):
        '''Test check_icon() - absolute path'''
        self.set_test_snap_yaml("icon", "/foo/bar/someicon")
        self.set_test_snap_yaml("type", "gadget")
        c = SnapReviewLint(self.test_name)
        c.pkg_files.append('/foo/bar/someicon')
        c.check_icon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_architectures_missing(self):
        '''Test check_architectures() (missing)'''
        self.set_test_snap_yaml("architectures", None)
        c = SnapReviewLint(self.test_name)
        c.check_architectures()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architectures_all(self):
        '''Test check_architectures() (all)'''
        self.set_test_snap_yaml("architectures", ["all"])
        c = SnapReviewLint(self.test_name)
        c.check_architectures()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architectures_single_armhf(self):
        '''Test check_architectures() (single arch, armhf)'''
        self.set_test_snap_yaml("architectures", ["armhf"])
        c = SnapReviewLint(self.test_name)
        c.check_architectures()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architectures_single_arm64(self):
        '''Test check_architectures() (single arch, arm64)'''
        self.set_test_snap_yaml("architectures", ["arm64"])
        c = SnapReviewLint(self.test_name)
        c.check_architectures()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architectures_single_i386(self):
        '''Test check_architectures() (single arch, i386)'''
        self.set_test_snap_yaml("architectures", ["i386"])
        c = SnapReviewLint(self.test_name)
        c.check_architectures()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architectures_single_amd64(self):
        '''Test check_architectures() (single arch, amd64)'''
        self.set_test_snap_yaml("architectures", ["amd64"])
        c = SnapReviewLint(self.test_name)
        c.check_architectures()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_architectures_single_nonexistent(self):
        '''Test check_architectures() (single nonexistent arch)'''
        self.set_test_snap_yaml("architectures", ["nonexistent"])
        c = SnapReviewLint(self.test_name)
        c.check_architectures()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_valid_arch_multi(self):
        '''Test check_architectures() (valid multi)'''
        self.set_test_snap_yaml("architectures", ["amd64", "armhf"])
        c = SnapReviewLint(self.test_name)
        c.check_architectures()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_valid_arch_multi2(self):
        '''Test check_architectures() (valid multi2)'''
        self.set_test_snap_yaml("architectures", ["armhf", "arm64", "i386"])
        c = SnapReviewLint(self.test_name)
        c.check_architectures()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_unknown_entries(self):
        '''Test check_unknown_entries - none'''
        c = SnapReviewLint(self.test_name)
        c.check_unknown_entries()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_unknown_entries2(self):
        '''Test check_unknown_entries - one'''
        self.set_test_snap_yaml("nonexistent", "bar")
        c = SnapReviewLint(self.test_name)
        c.check_unknown_entries()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_config(self):
        '''Test check_config()'''
        c = SnapReviewLint(self.test_name)
        self.set_test_unpack_dir("/nonexistent")
        c.pkg_files.append(os.path.join(c._get_unpack_dir(),
                           'meta/hooks/config'))
        c.check_config()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_config_nonexecutable(self):
        '''Test check_config() - not executable'''
        c = SnapReviewLint(self.test_name)
        self.set_test_unpack_dir("/nonexistent.nonexec")
        c.pkg_files.append(os.path.join(c._get_unpack_dir(),
                           'meta/hooks/config'))
        c.check_config()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_description(self):
        '''Test check_description'''
        self.set_test_snap_yaml("description", "This is a test description")
        c = SnapReviewLint(self.test_name)
        c.check_description()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_description_missing(self):
        '''Test check_description - not present'''
        self.set_test_snap_yaml("description", None)
        c = SnapReviewLint(self.test_name)
        c.check_description()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_description_bad(self):
        '''Test check_description - short'''
        self.set_test_snap_yaml("description", "a")
        c = SnapReviewLint(self.test_name)
        c.check_description()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_description_bad2(self):
        '''Test check_description - empty'''
        self.set_test_snap_yaml("description", "")
        c = SnapReviewLint(self.test_name)
        c.check_description()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_description_bad3(self):
        '''Test check_description - list'''
        self.set_test_snap_yaml("description", [])
        c = SnapReviewLint(self.test_name)
        c.check_description()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_license_agreement(self):
        '''Test check_license_agreement'''
        self.set_test_snap_yaml("license-agreement",
                                "This is a test license_agreement")
        c = SnapReviewLint(self.test_name)
        c.check_license_agreement()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_license_agreement_missing(self):
        '''Test check_license_agreement - not present'''
        self.set_test_snap_yaml("license-agreement", None)
        c = SnapReviewLint(self.test_name)
        c.check_license_agreement()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_license_agreement_bad(self):
        '''Test check_license_agreement - empty'''
        self.set_test_snap_yaml("license-agreement", "")
        c = SnapReviewLint(self.test_name)
        c.check_license_agreement()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_license_agreement_bad2(self):
        '''Test check_license_agreement - list'''
        self.set_test_snap_yaml("license-agreement", [])
        c = SnapReviewLint(self.test_name)
        c.check_license_agreement()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_license_version(self):
        '''Test check_license_version'''
        self.set_test_snap_yaml("license-version",
                                "This is a test license_version")
        c = SnapReviewLint(self.test_name)
        c.check_license_version()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_license_version_missing(self):
        '''Test check_license_version - not present'''
        self.set_test_snap_yaml("license-version", None)
        c = SnapReviewLint(self.test_name)
        c.check_license_version()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_license_version_bad(self):
        '''Test check_license_version - empty'''
        self.set_test_snap_yaml("license-version", "")
        c = SnapReviewLint(self.test_name)
        c.check_license_version()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_license_version_bad2(self):
        '''Test check_license_version - list'''
        self.set_test_snap_yaml("license-version", [])
        c = SnapReviewLint(self.test_name)
        c.check_license_version()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_summary(self):
        '''Test check_summary'''
        self.set_test_snap_yaml("summary", "This is a test summary")
        c = SnapReviewLint(self.test_name)
        c.check_summary()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_summary_missing(self):
        '''Test check_summary - not present'''
        self.set_test_snap_yaml("summary", None)
        c = SnapReviewLint(self.test_name)
        c.check_summary()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_summary_bad(self):
        '''Test check_summary - short'''
        self.set_test_snap_yaml("summary", "a")
        c = SnapReviewLint(self.test_name)
        c.check_summary()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_summary_bad2(self):
        '''Test check_summary - empty'''
        self.set_test_snap_yaml("summary", "")
        c = SnapReviewLint(self.test_name)
        c.check_summary()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_summary_bad3(self):
        '''Test check_summary - list'''
        self.set_test_snap_yaml("summary", [])
        c = SnapReviewLint(self.test_name)
        c.check_summary()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_one_command(self):
        '''Test check_apps() - one command'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/foo"},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_one_daemon(self):
        '''Test check_apps() - one daemon'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/foo",
                                                 "daemon": "single"},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_two_commands(self):
        '''Test check_apps() - two commands'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/foo"},
                                         "bar": {"command": "bin/bar"},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': 8, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_command_plus_daemon(self):
        '''Test check_apps() - command and daemon'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/foo"},
                                         "bar": {"command": "bin/bar",
                                                 "daemon": "single"},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': 8, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_two_daemons(self):
        '''Test check_apps() - command and daemon'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/foo",
                                                 "daemon": "single"},
                                         "bar": {"command": "bin/bar",
                                                 "daemon": "single"},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': 8, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_missing(self):
        '''Test check_apps() - missing'''
        self.set_test_snap_yaml("apps", None)
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_bad(self):
        '''Test check_apps() - bad'''
        self.set_test_snap_yaml("apps", [])
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_bad2(self):
        '''Test check_apps() - empty'''
        self.set_test_snap_yaml("apps", {})
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_bad3(self):
        '''Test check_apps() - missing command'''
        self.set_test_snap_yaml("apps", {"foo": {"daemon": "single"},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_bad4(self):
        '''Test check_apps() - unknown field'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/foo",
                                                 "nonexistent": "abc"},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_bad5(self):
        '''Test check_apps() - invalid field'''
        self.set_test_snap_yaml("apps", {"foo": []})
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_bad6(self):
        '''Test check_apps() - empty fields'''
        self.set_test_snap_yaml("apps", {"foo": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_command(self):
        '''Test check_apps_command()'''
        cmd = "bin/foo"
        self.set_test_snap_yaml("apps", {"foo": {"command": cmd},
                                         })
        c = SnapReviewLint(self.test_name)
        c.pkg_files.append(os.path.join('/fake', cmd))
        c.check_apps_command()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_command_missing(self):
        '''Test check_apps_command() - missing'''
        self.set_test_snap_yaml("apps", {"foo": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_command()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_command_empty(self):
        '''Test check_apps_command() - empty'''
        self.set_test_snap_yaml("apps", {"foo": {"command": ""},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_command()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_command_invalid(self):
        '''Test check_apps_command() - list'''
        self.set_test_snap_yaml("apps", {"foo": {"command": []},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_command()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_command_nonexistent(self):
        '''Test check_apps_command() - nonexistent'''
        cmd = "bin/foo"
        self.set_test_snap_yaml("apps", {"foo": {"command": cmd},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_command()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_stop(self):
        '''Test check_apps_stop()'''
        cmd = "bin/foo"
        self.set_test_snap_yaml("apps", {"foo": {"stop": cmd},
                                         })
        c = SnapReviewLint(self.test_name)
        c.pkg_files.append(os.path.join('/fake', cmd))
        c.check_apps_stop()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_missing(self):
        '''Test check_apps_stop() - missing'''
        self.set_test_snap_yaml("apps", {"foo": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_empty(self):
        '''Test check_apps_stop() - empty'''
        self.set_test_snap_yaml("apps", {"foo": {"stop": ""},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_invalid(self):
        '''Test check_apps_stop() - list'''
        self.set_test_snap_yaml("apps", {"foo": {"stop": []},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_nonexistent(self):
        '''Test check_apps_stop() - nonexistent'''
        cmd = "bin/foo"
        self.set_test_snap_yaml("apps", {"foo": {"stop": cmd},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_poststop(self):
        '''Test check_apps_poststop()'''
        cmd = "bin/foo"
        self.set_test_snap_yaml("apps", {"foo": {"poststop": cmd},
                                         })
        c = SnapReviewLint(self.test_name)
        c.pkg_files.append(os.path.join('/fake', cmd))
        c.check_apps_poststop()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_poststop_missing(self):
        '''Test check_apps_poststop() - missing'''
        self.set_test_snap_yaml("apps", {"foo": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_poststop()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_poststop_empty(self):
        '''Test check_apps_poststop() - empty'''
        self.set_test_snap_yaml("apps", {"foo": {"poststop": ""},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_poststop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_poststop_invalid(self):
        '''Test check_apps_poststop() - list'''
        self.set_test_snap_yaml("apps", {"foo": {"poststop": []},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_poststop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_poststop_nonexistent(self):
        '''Test check_apps_poststop() - nonexistent'''
        cmd = "bin/foo"
        self.set_test_snap_yaml("apps", {"foo": {"poststop": cmd},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_poststop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_daemon_simple(self):
        '''Test check_apps_daemon() - simple'''
        entry = "simple"
        self.set_test_snap_yaml("apps", {"foo": {"daemon": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_daemon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_daemon_forking(self):
        '''Test check_apps_daemon() - forking'''
        entry = "forking"
        self.set_test_snap_yaml("apps", {"foo": {"daemon": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_daemon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_daemon_oneshot(self):
        '''Test check_apps_daemon() - oneshot'''
        entry = "oneshot"
        self.set_test_snap_yaml("apps", {"foo": {"daemon": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_daemon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_daemon_dbus(self):
        '''Test check_apps_daemon() - dbus'''
        entry = "dbus"
        self.set_test_snap_yaml("apps", {"foo": {"daemon": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_daemon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_daemon_missing(self):
        '''Test check_apps_daemon() - missing'''
        self.set_test_snap_yaml("apps", {"foo": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_daemon()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_daemon_empty(self):
        '''Test check_apps_daemon() - empty'''
        self.set_test_snap_yaml("apps", {"foo": {"daemon": ""},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_daemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_daemon_invalid(self):
        '''Test check_apps_daemon() - list'''
        self.set_test_snap_yaml("apps", {"foo": {"daemon": []},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_daemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_daemon_nonexistent(self):
        '''Test check_apps_daemon() - nonexistent'''
        entry = "nonexistent"
        self.set_test_snap_yaml("apps", {"foo": {"daemon": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_daemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon(self):
        '''Test check_apps_nondaemon()'''
        entry = "simple"
        self.set_test_snap_yaml("apps", {"foo": {"daemon": entry,
                                                 "stop": "bin/bar"}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_command(self):
        '''Test check_apps_nondaemon() - command'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar"}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_uses(self):
        '''Test check_apps_nondaemon() - uses'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "uses": {}}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_stop(self):
        '''Test check_apps_nondaemon() - stop'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "stop": "bin/bar"}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_stop_timeout(self):
        '''Test check_apps_nondaemon() - stop-timeout'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "stop-timeout": 60}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_restart_condition(self):
        '''Test check_apps_nondaemon() - restart-condition'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "restart-condition":
                                                 "never"}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_poststop(self):
        '''Test check_apps_nondaemon() - poststop'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "poststop": "bin/bar"}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_ports(self):
        '''Test check_apps_nondaemon() - ports'''
        ports = self._create_ports()
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_bus_name(self):
        '''Test check_apps_nondaemon() - bus-name'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "bus-name": "tld.foo"}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_socket(self):
        '''Test check_apps_nondaemon() - socket'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "socket": True}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_listen_stream(self):
        '''Test check_apps_nondaemon() - listen-stream'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "listen-stream": "@bar"}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_socket_user(self):
        '''Test check_apps_nondaemon() - socket-user'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "socket-user": "docker"}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_nondaemon_socket_group(self):
        '''Test check_apps_nondaemon() - socket-group'''
        self.set_test_snap_yaml("apps", {"foo": {"command": "bin/bar",
                                                 "socket-group": "docker"}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_nondaemon()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_always(self):
        '''Test check_apps_restart-condition() - always'''
        entry = "always"
        self.set_test_snap_yaml("apps", {"foo": {"restart-condition": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_never(self):
        '''Test check_apps_restart-condition() - never'''
        entry = "never"
        self.set_test_snap_yaml("apps", {"foo": {"restart-condition": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_on_abnormal(self):
        '''Test check_apps_restart-condition() - on-abnormal'''
        entry = "on-abnormal"
        self.set_test_snap_yaml("apps", {"foo": {"restart-condition": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_on_abort(self):
        '''Test check_apps_restart-condition() - on-abort'''
        entry = "on-abort"
        self.set_test_snap_yaml("apps", {"foo": {"restart-condition": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_on_failure(self):
        '''Test check_apps_restart-condition() - on-failure'''
        entry = "on-failure"
        self.set_test_snap_yaml("apps", {"foo": {"restart-condition": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_on_success(self):
        '''Test check_apps_restart-condition() - on-success'''
        entry = "on-success"
        self.set_test_snap_yaml("apps", {"foo": {"restart-condition": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_missing(self):
        '''Test check_apps_restart-condition() - missing'''
        self.set_test_snap_yaml("apps", {"foo": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_empty(self):
        '''Test check_apps_restart-condition() - empty'''
        self.set_test_snap_yaml("apps", {"foo": {"restart-condition": ""},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_invalid(self):
        '''Test check_apps_restart-condition() - list'''
        self.set_test_snap_yaml("apps", {"foo": {"restart-condition": []},
                                         })
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_restart_condition_nonexistent(self):
        '''Test check_apps_restart-condition() - nonexistent'''
        entry = "nonexistent"
        self.set_test_snap_yaml("apps", {"foo": {"restart-condition": entry}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_restart_condition()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_pkgname(self):
        '''Test check_apps_busname() - pkgname'''
        name = "tld.%s" % self.test_name.split('_')[0].split('.')[0]
        self.set_test_snap_yaml("apps", {"bar": {"bus-name": name}})
        self.set_test_snap_yaml("type", 'framework')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_appname(self):
        '''Test check_apps_busname() - appname'''
        name = "tld.%s" % self.test_name.split('_')[0].split('.')[0]
        self.set_test_snap_yaml("apps", {"bar": {"bus-name": "%s.bar" % name}})
        self.set_test_snap_yaml("type", 'framework')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_missing_framework_app(self):
        '''Test check_apps_busname() - missing framework (app)'''
        name = "tld.%s" % self.test_name.split('_')[0].split('.')[0]
        self.set_test_snap_yaml("apps", {"bar": {"bus-name": "%s.bar" % name}})
        self.set_test_snap_yaml("type", 'app')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_missing_framework_gadget(self):
        '''Test check_apps_busname() - missing framework (gadget)'''
        name = "tld.%s" % self.test_name.split('_')[0].split('.')[0]
        self.set_test_snap_yaml("apps", {"bar": {"bus-name": "%s.bar" % name}})
        self.set_test_snap_yaml("type", 'gadget')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_missing_framework_kernel(self):
        '''Test check_apps_busname() - missing framework (kernel)'''
        name = "tld.%s" % self.test_name.split('_')[0].split('.')[0]
        self.set_test_snap_yaml("apps", {"bar": {"bus-name": name}})
        self.set_test_snap_yaml("type", 'kernel')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_pkgname_bad(self):
        '''Test check_apps_busname() - bad pkgname'''
        name = "tld.%s" % self.test_name.split('_')[0].split('.')[0]
        self.set_test_snap_yaml("apps", {"bar": {"bus-name": "%s-bad" % name}})
        self.set_test_snap_yaml("type", 'framework')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_appname_bad(self):
        '''Test check_apps_busname() - bad appname'''
        name = "tld.%s" % self.test_name.split('_')[0].split('.')[0]
        self.set_test_snap_yaml("apps", {"bar": {"bus-name":
                                "%s.bar-bad" % name}})
        self.set_test_snap_yaml("type", 'framework')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_empty(self):
        '''Test check_apps_busname() - bad (empty)'''
        self.set_test_snap_yaml("apps", {"bar": {"bus-name": ""}})
        self.set_test_snap_yaml("type", 'framework')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_invalid(self):
        '''Test check_apps_busname() - bad (invalid)'''
        self.set_test_snap_yaml("apps", {"bar": {"bus-name": []}})
        self.set_test_snap_yaml("type", 'framework')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_busname_bad_regex(self):
        '''Test check_apps_busname() - bad (regex)'''
        self.set_test_snap_yaml("apps", {"bar": {"bus-name": "name$"}})
        self.set_test_snap_yaml("type", 'framework')
        c = SnapReviewLint(self.test_name)
        c.check_apps_busname()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports(self):
        '''Test check_apps_ports()'''
        ports = self._create_ports()
        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': 7, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_internal(self):
        '''Test check_apps_ports() - internal'''
        ports = self._create_ports()
        del ports['external']
        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_external(self):
        '''Test check_apps_ports() - external'''
        ports = self._create_ports()
        del ports['internal']
        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_empty(self):
        '''Test check_apps_ports() - empty'''
        self.set_test_snap_yaml("apps", {"bar": {"ports": {}}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_invalid(self):
        '''Test check_apps_ports() - invalid'''
        self.set_test_snap_yaml("apps", {"bar": {"ports": []}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_bad_key(self):
        '''Test check_apps_ports() - bad key'''
        ports = self._create_ports()
        ports['xternal'] = ports['external']
        del ports['external']

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_missing_internal(self):
        '''Test check_apps_ports() - missing internal'''
        ports = self._create_ports()
        del ports['internal']['int1']

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_missing_external(self):
        '''Test check_apps_ports() - missing external'''
        ports = self._create_ports()
        del ports['external']['ext1']
        del ports['external']['ext2']

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_missing_external_subkey(self):
        '''Test check_apps_ports() - missing external subkey'''
        ports = self._create_ports()
        del ports['external']['ext2']['port']

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_missing_internal_subkey(self):
        '''Test check_apps_ports() - missing internal subkey'''
        ports = self._create_ports()
        del ports['internal']['int1']['port']
        del ports['internal']['int1']['negotiable']

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_invalid_internal_subkey(self):
        '''Test check_apps_ports() - invalid internal subkey'''
        ports = self._create_ports()
        ports['internal']['int1']['prt'] = ports['internal']['int1']['port']

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_invalid_internal_port(self):
        '''Test check_apps_ports() - invalid internal port'''
        ports = self._create_ports()
        ports['internal']['int1']['port'] = "bad/8080"

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_invalid_external_port(self):
        '''Test check_apps_ports() - invalid external port'''
        ports = self._create_ports()
        ports['external']['ext2']['port'] = []

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_invalid_internal_low_port(self):
        '''Test check_apps_ports() - invalid internal low port'''
        ports = self._create_ports()
        ports['internal']['int1']['port'] = "0/tcp"

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_invalid_internal_high_port(self):
        '''Test check_apps_ports() - invalid internal high port'''
        ports = self._create_ports()
        ports['internal']['int1']['port'] = "65536/tcp"

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_invalid_internal_negotiable(self):
        '''Test check_apps_ports() - invalid internal negotiable'''
        ports = self._create_ports()
        ports['internal']['int1']['negotiable'] = -99999999

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_ports_invalid_internal_negotiable2(self):
        '''Test check_apps_ports() - invalid internal negotiable'''
        ports = self._create_ports()
        ports['internal']['int1']['negotiable'] = []

        self.set_test_snap_yaml("apps", {"bar": {"ports": ports}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_timeout(self):
        '''Test check_apps_stop_timeout()'''
        self.set_test_snap_yaml("apps", {"bar": {"stop-timeout": 30}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop_timeout()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_timeout_nonexistent(self):
        '''Test check_apps_stop_timeout_nonexistent()'''
        self.set_test_snap_yaml("apps", {"bar": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop_timeout()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_timeout_granularity(self):
        '''Test check_apps_stop_timeout()'''
        self.set_test_snap_yaml("apps", {"bar": {"stop-timeout": '30s'}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop_timeout()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_timeout_empty(self):
        '''Test check_apps_stop_timeout() - empty'''
        self.set_test_snap_yaml("apps", {"bar": {"stop-timeout": ''}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_timeout_bad(self):
        '''Test check_apps_stop_timeout() - bad'''
        self.set_test_snap_yaml("apps", {"bar": {"stop-timeout": 'a'}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_timeout_bad2(self):
        '''Test check_apps_stop_timeout() - bad (list)'''
        self.set_test_snap_yaml("apps", {"bar": {"stop-timeout": []}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_timeout_bad_granularity(self):
        '''Test check_apps_stop_timeout() - bad with granularity'''
        self.set_test_snap_yaml("apps", {"bar": {"stop-timeout": '30a'}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_timeout_range_low(self):
        '''Test check_apps_stop_timeout() - out of range (low)'''
        self.set_test_snap_yaml("apps", {"bar": {"stop-timeout": -1}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_stop_timeout_range_high(self):
        '''Test check_apps_stop_timeout() - out of range (high)'''
        self.set_test_snap_yaml("apps", {"bar": {"stop-timeout": 61}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket(self):
        '''Test check_apps_socket()'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket": True,
                                                 "listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_no_listen_stream(self):
        '''Test check_apps_socket() - missing listen-stream'''
        self.set_test_snap_yaml("apps", {"bar": {"socket": True}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_bad(self):
        '''Test check_apps_socket() - bad'''
        self.set_test_snap_yaml("apps", {"bar": {"socket": ""}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_nonexistent(self):
        '''Test check_apps_socket() - nonexistent'''
        self.set_test_snap_yaml("apps", {"bar": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_listen_stream_abspkgname(self):
        '''Test check_apps_listen_stream() - @pkgname'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_listen_stream()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_listen_stream_abspkgname2(self):
        '''Test check_apps_listen_stream() - @pkgname_'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"listen-stream":
                                                 "@%s_something" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_listen_stream()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_listen_stream_nonexistent(self):
        '''Test check_apps_listen_stream() - nonexistent'''
        self.set_test_snap_yaml("apps", {"bar": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_listen_stream()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_listen_stream_bad(self):
        '''Test check_apps_listen_stream() - bad (list)'''
        self.set_test_snap_yaml("apps", {"bar": {"listen-stream": []}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_listen_stream()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_listen_stream_bad_abstract(self):
        '''Test check_apps_listen_stream() - bad (wrong name)'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"listen-stream":
                                                 "@%s/nomatch" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_listen_stream()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_listen_stream_bad_relative(self):
        '''Test check_apps_listen_stream() - bad (not / or @)'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"listen-stream": name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_listen_stream()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_listen_stream_bad_path(self):
        '''Test check_apps_listen_stream() - bad path'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"listen-stream":
                                                 "/var/log/%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_listen_stream()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_listen_stream_empty(self):
        '''Test check_apps_listen_stream() - empty'''
        self.set_test_snap_yaml("apps", {"bar": {"listen-stream": ""}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_listen_stream()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_user(self):
        '''Test check_apps_socket_user()'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-user": name,
                                                 "listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_user()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_user_no_listen_stream(self):
        '''Test check_apps_socket_user() - missing listen-stream'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-user": name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_user()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_user_bad(self):
        '''Test check_apps_socket_user() - bad user'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-user": name + "-no",
                                                 "listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_user()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_user_bad2(self):
        '''Test check_apps_socket_user() - bad (list)'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-user": [],
                                                 "listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_user()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_user_empty(self):
        '''Test check_apps_socket_user() - empty'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-user": "",
                                                 "listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_user()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_user_nonexistent(self):
        '''Test check_apps_socket_user() - nonexistent'''
        self.set_test_snap_yaml("apps", {"bar": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_user()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_group(self):
        '''Test check_apps_socket_group()'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-group": name,
                                                 "listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_group()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_group_no_listen_stream(self):
        '''Test check_apps_socket_group() - missing listen-stream'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-group": name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_group()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_group_bad(self):
        '''Test check_apps_socket_group() - bad group'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-group": name + "-no",
                                                 "listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_group()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_group_bad2(self):
        '''Test check_apps_socket_group() - bad (list)'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-group": [],
                                                 "listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_group()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_group_empty(self):
        '''Test check_apps_socket_group() - empty'''
        name = self.test_snap_yaml['name']
        self.set_test_snap_yaml("apps", {"bar": {"socket-group": "",
                                                 "listen-stream":
                                                 "@%s" % name}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_group()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_socket_group_nonexistent(self):
        '''Test check_apps_socket_group() - nonexistent'''
        self.set_test_snap_yaml("apps", {"bar": {}})
        c = SnapReviewLint(self.test_name)
        c.check_apps_socket_group()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_uses(self):
        '''Test check_uses()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': 13, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_uses_bad_type(self):
        '''Test check_uses() - bad type (list)'''
        uses = {'skill-caps': {'type': [],
                               'caps': ['network-client']}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_empty_type(self):
        '''Test check_uses() - empty type'''
        uses = {'skill-caps': {'type': "",
                               'caps': ['network-client']}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_unspecified_type(self):
        '''Test check_uses() - unspecified type'''
        uses = {'migration-skill': {'caps': ['network-client']}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_uses_unknown_type(self):
        '''Test check_uses() - type (unknown)'''
        uses = {'skill-caps': {'type': 'nonexistent',
                               'caps': ['network-client']}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_unspecified_unknown_type(self):
        '''Test check_uses() - unspecified type (unknown)'''
        uses = {'nonexistent': {'caps': ['network-client']}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_missing_attrib(self):
        '''Test check_uses() - missing attrib'''
        uses = {'migration-skill': {}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_missing_attrib_explicit_type(self):
        '''Test check_uses() - missing attrib'''
        uses = {'skill-caps': {'type': 'migration-skill'}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_unknown_attrib(self):
        '''Test check_uses() - unknown attrib'''
        uses = {'skill-caps': {'type': "migration-skill",
                               'nonexistent': 'abc'}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_bad_attrib_caps(self):
        '''Test check_uses() - bad attrib - caps'''
        uses = {'skill-caps': {'type': "migration-skill",
                               'caps': 'bad'}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_bad_attrib_security_override(self):
        '''Test check_uses() - bad attrib - security-override'''
        uses = {'skill-caps': {'type': "migration-skill",
                               'security-override': 'bad'}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_bad_attrib_security_policy(self):
        '''Test check_uses() - bad attrib - security-policy'''
        uses = {'skill-caps': {'type': "migration-skill",
                               'security-policy': 'bad'}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_uses_bad_attrib_security_template(self):
        '''Test check_uses() - bad attrib - security-template'''
        uses = {'skill-caps': {'type': "migration-skill",
                               'security-template': []}}
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewLint(self.test_name)
        c.check_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_uses(self):
        '''Test check_apps_uses()'''
        uses = self._create_top_uses()
        apps_uses = self._create_apps_uses()
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", apps_uses)
        c = SnapReviewLint(self.test_name)
        c.check_apps_uses()
        r = c.click_report
        expected_counts = {'info': 10, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_no_uses(self):
        '''Test check_apps_uses() - no uses'''
        uses = self._create_top_uses()
        apps_uses = {'bar': {'command': 'bin/bar'}}
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", apps_uses)
        c = SnapReviewLint(self.test_name)
        c.check_apps_uses()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_apps_uses_bad(self):
        '''Test check_apps_uses() - bad (dict)'''
        uses = self._create_top_uses()
        apps_uses = {'bar': {'uses': {}}}
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", apps_uses)
        c = SnapReviewLint(self.test_name)
        c.check_apps_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_uses_empty(self):
        '''Test check_apps_uses() - empty'''
        uses = self._create_top_uses()
        apps_uses = {'bar': {'uses': []}}
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", apps_uses)
        c = SnapReviewLint(self.test_name)
        c.check_apps_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_uses_bad_entry(self):
        '''Test check_apps_uses() - bad entry (dict)'''
        uses = self._create_top_uses()
        apps_uses = {'bar': {'uses': [{}]}}
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", apps_uses)
        c = SnapReviewLint(self.test_name)
        c.check_apps_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_apps_uses_unknown_entry(self):
        '''Test check_apps_uses() - unknown'''
        uses = self._create_top_uses()
        apps_uses = {'bar': {'uses': ['nonexistent']}}
        self.set_test_snap_yaml("uses", uses)
        self.set_test_snap_yaml("apps", apps_uses)
        c = SnapReviewLint(self.test_name)
        c.check_apps_uses()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)


# Below is if we ever want to use this methodology
# from unittest import TestCase
# from clickreviews.common import cleanup_unpack
# from clickreviews.tests import utils
# import shutil
# import tempfile
# class SnapReviewLintTestCase(TestCase):
#     """Tests without mocks where they are not needed."""
#     def setUp(self):
#         # XXX cleanup_unpack() is required because global variables
#         # UNPACK_DIR, RAW_UNPACK_DIR are initialised to None at module
#         # load time, but updated when a real (non-Mock) test runs, such as
#         # here. While, at the same time, two of the existing tests using
#         # mocks depend on both global vars being None. Ideally, those
#         # global vars should be refactored away.
#         self.addCleanup(cleanup_unpack)
#         super().setUp()
#
#     def mkdtemp(self):
#         """Create a temp dir which is cleaned up after test."""
#         tmp_dir = tempfile.mkdtemp()
#         self.addCleanup(shutil.rmtree, tmp_dir)
#         return tmp_dir
#
#     def _test_check_dot_click_root(self):
#         package = utils.make_package(extra_files=['.click/'],
#                                      output_dir=self.mkdtemp())
#         c = SnapReviewLint(package)
#
#         c.check_dot_click()
#
#         errors = list(c.click_report['error'].keys())
#         self.assertEqual(errors, ['lint:dot_click'])
