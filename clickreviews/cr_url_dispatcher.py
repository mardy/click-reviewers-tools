'''cr_url dispatcher.py: click url_dispatcher'''
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

from clickreviews.cr_common import ClickReview, error, open_file_read, msg
import json
import os

# https://wiki.ubuntu.com/URLDispatcher


class ClickReviewUrlDispatcher(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "url_dispatcher")

        self.required_keys = ['protocol']
        self.optional_keys = ['domain-suffix']

        self.url_dispatcher_files = dict()  # click-show-files and tests
        self.url_dispatcher = dict()
        for app in self.manifest['hooks']:
            if 'urls' not in self.manifest['hooks'][app]:
                # msg("Skipped missing urls hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['urls'], str):
                error("manifest malformed: hooks/%s/urls is not str" % app)
            (full_fn, jd) = self._extract_url_dispatcher(app)
            self.url_dispatcher_files[app] = full_fn
            self.url_dispatcher[app] = jd

    def _extract_url_dispatcher(self, app):
        '''Get url dispatcher json'''
        u = self.manifest['hooks'][app]['urls']
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
            jd = json.loads(contents)
        except Exception as e:
            error("url-dispatcher json unparseable: %s (%s):\n%s" % (bn,
                  str(e), contents))

        if not isinstance(jd, list):
            error("url-dispatcher json is malformed: %s:\n%s" % (bn, contents))

        return (fn, jd)

    def check_required(self):
        '''Check url-dispatcher required fields'''
        for app in sorted(self.url_dispatcher):
            for r in self.required_keys:
                found = False
                t = 'info'
                n = 'required_entry_%s_%s' % (app, r)
                s = "OK"
                for entry in self.url_dispatcher[app]:
                    if not isinstance(entry, dict):
                        t = 'error'
                        s = "'%s' is not a dict" % str(entry)
                        self._add_result(t, n, s)
                        continue
                    if r in entry:
                        if not isinstance(entry[r], str):
                            t = 'error'
                            s = "'%s' is not a string" % r
                        elif entry[r] == "":
                            t = 'error'
                            s = "'%s' is empty" % r
                        else:
                            found = True
                if not found and t != 'error':
                    t = 'error'
                    s = "Missing required field '%s'" % r
                self._add_result(t, n, s)

    def check_optional(self):
        '''Check url-dispatcher optional fields'''
        for app in sorted(self.url_dispatcher):
            for o in self.optional_keys:
                found = False
                t = 'info'
                n = 'optional_entry_%s_%s' % (app, o)
                s = "OK"
                for entry in self.url_dispatcher[app]:
                    if not isinstance(entry, dict):
                        t = 'error'
                        s = "'%s' is not a dict" % str(entry)
                        self._add_result(t, n, s)
                        continue
                    if o in entry:
                        if not isinstance(entry[o], str):
                            t = 'error'
                            s = "'%s' is not a string" % o
                        elif entry[o] == "":
                            t = 'error'
                            s = "'%s' is empty" % o
                        else:
                            found = True
                if not found and t != 'error':
                    s = "OK (skip missing)"
                self._add_result(t, n, s)

    def check_unknown(self):
        '''Check url-dispatcher unknown fields'''
        for app in sorted(self.url_dispatcher):
            unknown = []
            for entry in self.url_dispatcher[app]:
                t = 'info'
                n = 'unknown_entry_%s' % app
                s = "OK"
                if not isinstance(entry, dict):
                    t = 'error'
                    s = "'%s' is not a dict" % str(entry)
                    self._add_result(t, n, s)
                    continue

                for f in entry.keys():
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
