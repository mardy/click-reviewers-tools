'''cr_systemd.py: click systemd'''
#
# Copyright (C) 2015 Canonical Ltd.
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

from clickreviews.cr_common import ClickReview, error, open_file_read, msg
import yaml
import os


class ClickReviewSystemd(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        peer_hooks = dict()
        my_hook = 'snappy-systemd'
        peer_hooks[my_hook] = dict()
        peer_hooks[my_hook]['required'] = ["apparmor"]
        peer_hooks[my_hook]['allowed'] = peer_hooks[my_hook]['required']

        ClickReview.__init__(self, fn, "snappy-systemd", peer_hooks=peer_hooks)

        # snappy-systemd currently only allows specifying:
        # - start (required)
        # - description (required)
        # - stop
        # - poststop
        # - stop-timeout
        self.required_keys = ['start', 'description']
        self.optional_keys = ['stop', 'poststop', 'stop-timeout']

        self.systemd_files = dict()  # click-show-files and tests
        self.systemd = dict()
        for app in self.manifest['hooks']:
            if 'snappy-systemd' not in self.manifest['hooks'][app]:
                # msg("Skipped missing systemd hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['snappy-systemd'],
               str):
                error("manifest malformed: hooks/%s/snappy-systemd is not str"
                      % app)
            (full_fn, jd) = self._extract_systemd(app)
            self.systemd_files[app] = full_fn
            self.systemd[app] = jd

    def _extract_systemd(self, app):
        '''Get systemd yaml'''
        u = self.manifest['hooks'][app]['snappy-systemd']
        fn = os.path.join(self.unpack_dir, u)

        bn = os.path.basename(fn)
        if not os.path.exists(fn):
            error("Could not find '%s'" % bn)

        fh = open_file_read(fn)
        contents = ""
        for line in fh.readlines():
            contents += line
        fh.close()

        try:
            yd = yaml.safe_load(contents)
        except Exception as e:
            error("snappy-systemd yaml unparseable: %s (%s):\n%s" % (bn,
                  str(e), contents))

        if not isinstance(yd, dict):
            error("snappy-systemd yaml is malformed: %s:\n%s" % (bn, contents))

        return (fn, yd)

    def check_required(self):
        '''Check snappy-systemd required fields'''
        for app in sorted(self.systemd):
            for r in self.required_keys:
                found = False
                t = 'info'
                n = 'required_key_%s_%s' % (app, r)
                s = "OK"
                if r in self.systemd[app]:
                    if not isinstance(self.systemd[app][r], str):
                        t = 'error'
                        s = "'%s' is not a string" % r
                    elif self.systemd[app][r] == "":
                        t = 'error'
                        s = "'%s' is empty" % r
                    else:
                        found = True
                if not found and t != 'error':
                    t = 'error'
                    s = "Missing required field '%s'" % r
                self._add_result(t, n, s)

    def check_optional(self):
        '''Check snappy-systemd optional fields'''
        for app in sorted(self.systemd):
            for o in self.optional_keys:
                found = False
                t = 'info'
                n = 'optional_key_%s_%s' % (app, o)
                s = "OK"
                if o in self.systemd[app]:
                    if o == 'stop-timeout' and \
                       not isinstance(self.systemd[app][o], int):
                        t = 'error'
                        s = "'%s' is not an integer" % o
                    elif not isinstance(self.systemd[app][o], str):
                        t = 'error'
                        s = "'%s' is not a string" % o
                    elif self.systemd[app][o] == "":
                        t = 'error'
                        s = "'%s' is empty" % o
                    else:
                        found = True
                if not found and t != 'error':
                    s = "OK (skip missing)"
                self._add_result(t, n, s)

    def check_unknown(self):
        '''Check snappy-systemd unknown fields'''
        for app in sorted(self.systemd):
            unknown = []
            t = 'info'
            n = 'unknown_key_%s' % app
            s = "OK"

            for f in self.systemd[app].keys():
                if f not in self.required_keys and \
                   f not in self.optional_keys:
                    unknown.append(f)

            if len(unknown) == 1:
                t = 'warn'
                s = "Unknown field '%s'" % unknown[0]
            elif len(unknown) > 1:
                t = 'warn'
                s = "Unknown fields '%s'" % ", ".join(unknown)
            self._add_result(t, n, s)
