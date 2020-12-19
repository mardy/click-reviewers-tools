'''cr_push_helper.py: click push-helper checks'''
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


class ClickReviewPushHelper(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        peer_hooks = dict()
        my_hook = 'push-helper'
        peer_hooks[my_hook] = dict()
        peer_hooks[my_hook]['allowed'] = ['apparmor']
        peer_hooks[my_hook]['required'] = ['apparmor']

        ClickReview.__init__(self, fn, "push_helper", peer_hooks=peer_hooks,
                             overrides=overrides)

        if not self.is_click and not self.is_snap1:
            return

        self.required_keys = ['exec']
        self.optional_keys = ['app_id']

        self.push_helper_files = dict()  # click-show-files and tests
        self.push_helper = dict()

        if self.manifest is None:
            return

        for app in self.manifest['hooks']:
            if 'push-helper' not in self.manifest['hooks'][app]:
                # msg("Skipped missing push-helper hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['push-helper'], str):
                error("manifest malformed: hooks/%s/push-helper is not str" %
                      app)
            (full_fn, jd) = self._extract_push_helper(app)
            self.push_helper_files[app] = full_fn
            self.push_helper[app] = jd

    def _extract_push_helper(self, app):
        '''Get push-helper hook content'''
        c = self.manifest['hooks'][app]['push-helper']
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
            error("push-helper json unparseable: %s (%s):\n%s" % (bn,
                  str(e), contents))

        if not isinstance(jd, dict):
            error("push-helper json is malformed: %s:\n%s" % (bn, contents))

        return (fn, jd)

    def check_valid(self):
        '''Check validity of push-helper entries'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.push_helper):
            for k in self.push_helper[app].keys():
                t = "info"
                n = self._get_check_name("valid", app=app, extra=k)
                s = "OK"

                if not isinstance(self.push_helper[app][k], str):
                    t = "error"
                    s = "'%s' is not a string" % k
                elif self.push_helper[app][k] == "":
                    t = "error"
                    s = "'%s' is empty" % k
                self._add_result(t, n, s)

            for k in self.required_keys:
                t = "info"
                n = self._get_check_name("valid_required", app=app, extra=k)
                s = "OK"
                if k not in self.push_helper[app]:
                    t = "error"
                    s = "'%s' is missing" % k
                self._add_result(t, n, s)

    def check_unknown_keys(self):
        '''Check unknown'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.push_helper):
            unknown = []
            t = "info"
            n = self._get_check_name("unknown", app=app)
            s = "OK"
            for key in self.push_helper[app].keys():
                if key not in self.required_keys and \
                   key not in self.optional_keys:
                    unknown.append(key)
            if len(unknown) == 1:
                t = "warn"
                s = "Unknown field '%s'" % unknown[0]
            elif len(unknown) > 1:
                t = "warn"
                s = "Unknown fields '%s'" % ", ".join(unknown)
            self._add_result(t, n, s)

    def check_hooks(self):
        '''Verify combinations of click hooks with the push-helper hook'''
        if not self.is_click and not self.is_snap1:
            return

        if self.manifest is None:
            return

        for app in sorted(self.manifest['hooks']):
            if app not in self.push_helper:
                continue

            t = "info"
            n = self._get_check_name("other_hooks", app=app)
            s = "OK"

            bad = []
            for hook in self.manifest['hooks'][app]:
                # Only the apparmor hook can be used with the push-helper
                if hook not in ['push-helper', 'apparmor']:
                    bad.append(hook)
            if len(bad) > 0:
                t = 'error'
                s = "Found unusual hooks with push-helper: %s" % ", ".join(bad)
            self._add_result(t, n, s)
