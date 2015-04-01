'''cr_framework.py: click framework'''
#
# Copyright (C) 2014-2015 Canonical Ltd.
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

from clickreviews.cr_common import ClickReview, error, open_file_read
import os


class ClickReviewFramework(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        ClickReview.__init__(self, fn, "framework", overrides=overrides)

        self.frameworks_file = dict()
        self.frameworks = dict()
        for app in self.manifest['hooks']:
            if 'framework' not in self.manifest['hooks'][app]:
                # msg("Skipped missing framework hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['framework'], str):
                error("manifest malformed: hooks/%s/framework is not str" %
                      app)
            (full_fn, data) = self._extract_framework(app)
            self.frameworks_file[app] = full_fn
            self.frameworks[app] = data

    def _extract_framework(self, app):
        '''Get framework for app'''
        rel = self.manifest['hooks'][app]['framework']
        fn = os.path.join(self.unpack_dir, rel)
        if not os.path.exists(fn):
            error("Could not find '%s'" % rel)

        data = dict()
        fh = open_file_read(fn)
        for line in fh.readlines():
            tmp = line.split(':')
            if len(tmp) != 2:
                continue
            data[tmp[0].strip()] = tmp[1].strip()
        fh.close()

        return (fn, data)

    def _has_framework_in_metadir(self):
        '''Check if snap has meta/<name>.framework'''
        if not self.is_snap:
            return False

        return os.path.exists(os.path.join(self.unpack_dir, 'meta',
                                           '%s.framework' %
                                           self.pkg_yaml['name']))

    def check_framework_hook_obsolete(self):
        '''Check manifest doesn't specify 'framework' hook'''
        t = 'info'
        n = "obsolete_declaration"
        s = "OK"
        if len(self.frameworks) > 0:
            t = 'error'
            s = "framework hook found for '%s'" % \
                ",".join(sorted(self.frameworks))
        self._add_result(t, n, s)

    def check_snappy_framework_file_obsolete(self):
        '''Check snap doesn't ship .framework file'''
        if not self.is_snap:
            return
        t = 'info'
        n = "obsolete_framework_file"
        s = "OK"
        if self._has_framework_in_metadir():
            t = 'warn'
            s = "found '%s.framework' (safe to remove)" % self.pkg_yaml['name']
        self._add_result(t, n, s)
