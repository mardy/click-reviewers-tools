'''cr_framework.py: click framework'''
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

from clickreviews.cr_common import ClickReview, open_file_read
import os


class ClickReviewFramework(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "framework")
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

    def check_single_framework(self):
        '''Check only have one framework in the click'''
        t = 'info'
        n = 'single_framework'
        s = "OK"
        if len(self.frameworks.keys()) > 1:
            t = 'error'
            s = 'framework hook specified multiple times'
        self._add_result(t, n, s)

    def check_framework_base_name(self):
        '''Check framework Base-Name'''
        for app in sorted(self.frameworks):
            t = 'info'
            n = "base_name_present '%s'" % app
            s = "OK"
            if 'Base-Name' not in self.frameworks[app]:
                t = 'error'
                s = "Could not find 'Base-Name' in '%s'" % \
                    (self.frameworks_file[app])
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = "base_name_namespacing '%s'" % app
            s = "OK"
            if self.frameworks[app]['Base-Name'] != self.manifest['name']:
                t = 'error'
                s = "'%s' != '%s'" % (self.frameworks[app]['Base-Name'],
                                      self.manifest['name'])
            self._add_result(t, n, s)

    def check_framework_base_version(self):
        '''Check framework Base-Version'''
        for app in sorted(self.frameworks):
            t = 'info'
            n = "base_version_present '%s'" % app
            s = "OK"
            if 'Base-Version' not in self.frameworks[app]:
                t = 'error'
                s = "Could not find 'Base-Version' in '%s'" % \
                    (self.frameworks_file[app])
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            v = self.frameworks[app]['Base-Version']
            t = 'info'
            n = "base_version_number '%s'" % app
            s = "OK"
            try:
                float(v)
            except ValueError:
                t = 'error'
                s = "'Base-Version' malformed: '%s' is not a number" % v
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = "base_version_positive '%s'" % app
            s = "OK"
            if float(v) < 0:
                t = 'error'
                s = "'Base-Version' malformed: '%s' is negative" % v
            self._add_result(t, n, s)

    def check_framework_hooks(self):
        '''Check if peer hooks are valid'''
        d = self.verify_peer_hooks("framework",
                                   allowed=[],
                                   # required=[])
                                   required=['apparmor-policy'])
        print(d)
        t = 'info'
        n = "peer_hooks_required"
        s = "OK"

        if 'missing' in d and len(d['missing'].keys()) > 0:
            t = 'error'
            for app in d['missing']:
                s = "Missing required hooks for '%s': %s" % (app,
                    ", ".join(d['missing'][app]))
                self._add_result(t, n, s)
        else:
            self._add_result(t, n, s)

        t = 'info'
        n = "peer_hooks_disallowed"
        s = "OK"

        if 'disallowed' in d and len(d['disallowed'].keys()) > 0:
            t = 'error'
            for app in d['disallowed']:
                s = "Found disallowed hooks for '%s': %s" % (app,
                    ", ".join(d['disallowed'][app]))
                self._add_result(t, n, s)
        else:
            self._add_result(t, n, s)
