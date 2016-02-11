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

    def test_check_uses_redflag(self):
        '''Test check_uses_redflag()'''
        uses = self._create_top_uses()
        self.set_test_snap_yaml("uses", uses)
        c = SnapReviewSecurity(self.test_name)
        c.check_uses_redflag()
        report = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(report, expected_counts)
