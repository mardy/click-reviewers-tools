'''cr_skeleton.py: click skeleton'''
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

class ClickReviewSkeleton(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "skeleton")

    def verify_foo(self):
        '''Verify foo'''
        t = 'info'
        n = 'foo'
        s = "OK"
        if False:
            t = 'error'
            s = "some message"
        self._add_result(t, n, s)

    def verify_bar(self):
        '''Verify bar'''
        t = 'info'
        n = 'bar'
        s = "OK"
        if True:
            t = 'error'
            s = "some message"
        self._add_result(t, n, s)

    def verify_baz(self):
        '''Verify baz'''
        self._add_result('warn', 'baz', 'TODO')

    def do_checks(self):
        '''Perform checks'''
        self.verify_foo()
        self.verify_bar()
        self.verify_baz()
