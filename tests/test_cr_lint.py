'''test_cr_lint.py: tests for the cr_lint module'''
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


from mock import patch
from unittest import TestCase


class OverrideClickReview(object):
    def __init__(self, fn, fnn):
        self.click_package = fn


class TestClickReviewLint(TestCase):
    """Tests for the lint review tool."""

    @patch('cr_common.ClickReview', OverrideClickReview)
    def test_check_package_filename(self):
        """Test that package names comply to the policies."""
        from cr_lint import ClickReviewLint
        test_name = 'net.launchpad.click-webapps.amazon_2_unknown.click'
        c = ClickReviewLint(test_name)
        c.check_package_filename()