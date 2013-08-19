'''cr_desktop.py: click desktop checks'''
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

from cr_common import ClickReview, error
import os


class ClickReviewDesktop(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "desktop")

        self.desktop_files = dict()
        for app in self.manifest['hooks']:
            if 'desktop' not in self.manifest['hooks'][app]:
                error("could not find desktop hook for '%s'" % app)
            if not isinstance(self.manifest['hooks'][app]['desktop'], str):
                error("manifest malformed: hooks/%s/desktop is not str" % app)
            d = self.manifest['hooks'][app]['desktop']
            self.desktop_files[app] = os.path.join(self.unpack_dir, d)

    def check_desktop_file(self):
        '''Check desktop file'''
        for app in sorted(self.desktop_files):
            d = self.manifest['hooks'][app]['desktop']
            self._add_result('warn', 'file_%s' % d, 'TODO')
