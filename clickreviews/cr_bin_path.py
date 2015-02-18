'''cr_bin_path.py: click bin-path'''
#
# Copyright (C) 2014 Canonical Ltd.
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

from clickreviews.cr_common import ClickReview
import os


class ClickReviewBinPath(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        peer_hooks = dict()
        my_hook = 'bin-path'
        peer_hooks[my_hook] = dict()
        peer_hooks[my_hook]['required'] = ["apparmor"]
        peer_hooks[my_hook]['allowed'] = peer_hooks[my_hook]['required']

        ClickReview.__init__(self, fn, "bin-path", peer_hooks=peer_hooks)

        self.bin_paths = dict()
        for app in self.manifest['hooks']:
            if 'bin-path' not in self.manifest['hooks'][app]:
                #  msg("Skipped missing bin-path hook for '%s'" % app)
                continue
            self.bin_paths[app] = self._extract_bin_path(app)

    def _extract_bin_path(self, app):
        '''Get bin-path for app'''
        rel = self.manifest['hooks'][app]['bin-path']
        fn = os.path.join(self.unpack_dir, rel)
        if not os.path.exists(fn):
            error("Could not find '%s'" % rel)
        return fn

    def _check_bin_path_executable(self, app):
        '''Check that the provided path exists'''
        rel = self.manifest['hooks'][app]['bin-path']
        fn = os.path.join(self.unpack_dir, rel)
        return os.access(fn, os.X_OK)

    def check_path(self):
        '''Check path exists'''
        t = 'info'
        n = 'path exists'
        s = "OK"

        for app in sorted(self.bin_paths):
            t = 'info'
            n = 'path executable'
            s = "OK"
            if not self._check_bin_path_executable(app):
                t = 'error'
                s = "'%s' is not executable" % \
                    (self.manifest['hooks'][app]['bin-path'])
            self._add_result(t, n, s)
