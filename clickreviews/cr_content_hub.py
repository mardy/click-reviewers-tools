'''cr_content_hub.py: click content-hub checks'''
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
import json
import os


class ClickReviewContentHub(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        peer_hooks = dict()
        my_hook = 'content-hub'
        peer_hooks[my_hook] = dict()
        peer_hooks[my_hook]['allowed'] = ClickReview.app_allowed_peer_hooks
        peer_hooks[my_hook]['required'] = []

        ClickReview.__init__(self, fn, "content_hub", peer_hooks=peer_hooks,
                             overrides=overrides)
        if not self.is_click and not self.is_snap1:
            return

        self.valid_keys = ['destination', 'share', 'source']

        self.content_hub_files = dict()  # click-show-files and tests
        self.content_hub = dict()

        if self.manifest is None:
            return

        for app in self.manifest['hooks']:
            if 'content-hub' not in self.manifest['hooks'][app]:
                # msg("Skipped missing content-hub hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['content-hub'], str):
                error("manifest malformed: hooks/%s/urls is not str" % app)
            (full_fn, jd) = self._extract_content_hub(app)
            self.content_hub_files[app] = full_fn
            self.content_hub[app] = jd

    def _extract_content_hub(self, app):
        '''Get content-hub hook content'''
        c = self.manifest['hooks'][app]['content-hub']
        fn = os.path.join(self.unpack_dir, c)

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
            error("content-hub json unparseable: %s (%s):\n%s" % (bn,
                  str(e), contents))

        if not isinstance(jd, dict):
            error("content-hub json is malformed: %s:\n%s" % (bn, contents))

        return (fn, jd)

    def check_valid(self):
        '''Check validity of content-hub entries'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.content_hub):
            for k in self.content_hub[app].keys():
                t = "info"
                n = self._get_check_name('valid', app=app, extra=k)
                s = "OK"

                if not isinstance(self.content_hub[app][k], list):
                    t = "error"
                    s = "'%s' is not a list" % k
                elif len(self.content_hub[app][k]) < 1:
                    t = "error"
                    s = "'%s' is empty" % k
                self._add_result(t, n, s)
                if t == "error":
                    continue

                for v in self.content_hub[app][k]:
                    t = "info"
                    n = self._get_check_name('valid_value', app=app, extra=k)
                    s = "OK"
                    if not isinstance(v, str):
                        t = "error"
                        s = "'%s' is not a string" % k
                    elif v == "":
                        t = "error"
                        s = "'%s' is empty" % k
                    self._add_result(t, n, s)

    def check_unknown_keys(self):
        '''Check unknown'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.content_hub):
            unknown = []
            t = "info"
            n = self._get_check_name('unknown', app=app)
            s = "OK"
            for key in self.content_hub[app].keys():
                if key not in self.valid_keys:
                    unknown.append(key)
            if len(unknown) == 1:
                t = "warn"
                s = "Unknown field '%s'" % unknown[0]
            elif len(unknown) > 1:
                t = "warn"
                s = "Unknown fields '%s'" % ", ".join(unknown)
            self._add_result(t, n, s)
