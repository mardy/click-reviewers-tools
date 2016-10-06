'''test_sr_declaration.py: tests for the sr_declaration module'''
#
# Copyright (C) 2014-2016 Canonical Ltd.
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

from clickreviews.sr_declaration import SnapReviewDeclaration
import clickreviews.sr_tests as sr_tests


class TestSnapReviewDeclaration(sr_tests.TestSnapReview):
    """Tests for the lint review tool."""

    def test_check_base_declaration(self):
        '''Test check_base_declaration()'''
        c = SnapReviewDeclaration(self.test_name)
        c.check_base_declaration()
        r = c.click_report
        # We should end up with 1 info
        expected_counts = {'info': 48, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)
