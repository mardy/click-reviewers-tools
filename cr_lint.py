'''lint.py: click lint checks'''
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

from __future__ import print_function

from cr_common import ClickReview

class ClickReviewLint(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "lint")

    def verify_pkgname(self):
        '''Verify package name matches manifest'''
        self._add_result('warn', 'pkgname', 'TODO')

    def verify_version(self):
        '''Verify package version matches manifest'''
        self._add_result('warn', 'version', 'TODO')

    def do_checks(self):
        '''Perform lint checks'''
        self.verify_pkgname()
        self.verify_version()
