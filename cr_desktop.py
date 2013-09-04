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

from cr_common import ClickReview, error, open_file_read
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
            full_fn = os.path.join(self.unpack_dir, d)
            if os.path.exists(full_fn):
                self.desktop_files[app] = full_fn

    def check_desktop_file(self):
        '''Check desktop file'''
        t = 'info'
        n = 'files_available'
        s = 'OK'
        if not self.desktop_files:
            t = 'warn'
            s = 'No .desktop files available.'
        self._add_result(t, n, s)
        for app in sorted(self.desktop_files):
            d = self.manifest['hooks'][app]['desktop']
            content = open_file_read(self.desktop_files[app]).readlines()

            # desktop_icon tests
            icon_lines = list(filter(lambda l: l.startswith('Icon='), content))
            t = 'info'
            n = 'icon_specified (%s)' % d
            s = 'OK'
            if not icon_lines:
                t = 'warn'
                s = 'No icon specified in .desktop file.'
            self._add_result(t, n, s)

            t = 'info'
            n = 'one_icon_specified (%s)' % d
            s = 'OK'
            if len(icon_lines) > 1:
                t = 'warn'
                s = 'More than one icon line specified in .desktop file.'
            self._add_result(t, n, s)
            icon_path = icon_lines[0].split("=")[1].strip()
            
            # https://public.apps.ubuntu.com/download/com.ubuntu.developer.mhall119/uReadIt/com.ubuntu.developer.mhall119.uReadIt-0.9.1.click?noauth=1
            t = 'info'
            n = 'icon_full_path (%s)' % d
            s = 'OK'
            if icon_path.startswith('/'):
                t = 'error'
                s = 'Absolute path `%s` for icon given in .desktop file.' \
                        % icon_path
            self._add_result(t, n, s)
