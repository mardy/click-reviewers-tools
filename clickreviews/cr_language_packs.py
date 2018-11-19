'''cr_language_packs.py: click language packs'''
#
# Copyright (C) 2018 The UBports Foundation
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


class ClickReviewLanguagePacks(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        peer_hooks = dict()
        my_hook = 'language-packs'
        peer_hooks[my_hook] = dict()
        peer_hooks[my_hook]['allowed'] = ['apparmor']
        peer_hooks[my_hook]['required'] = []

        ClickReview.__init__(self,
                             fn,
                             "language_packs",
                             peer_hooks=peer_hooks,
                             overrides=overrides)
        if not self.is_click and not self.is_snap1:
            return

        self.language_packs_files = dict()
        self.language_packs = dict()

        if self.manifest is None:
            return

        for app in self.manifest['hooks']:
            if my_hook not in self.manifest['hooks'][app]:
                # msg("Skipped missing %s hook for '%s'" % (my_hook, app))
                continue
            if not isinstance(self.manifest['hooks'][app][my_hook], str):
                error("manifest malformed: hooks/%s/%s is not a str" % (
                      app, my_hook))

            (full_fn, parsed) = self._extract_language_pack(app)
            self.language_packs_files[app] = full_fn
            self.language_packs[app] = parsed

    def _extract_language_pack(self, app):
        '''Extract language pack'''
        if self.manifest is None:
            return

        a = self.manifest['hooks'][app]['language-packs']
        fn = os.path.join(self.unpack_dir, a)

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
            error("language pack json unparseable: %s (%s):\n%s" % (bn,
                  str(e), contents))

        if not isinstance(jd, dict):
            error("language pack json is malformed: %s:\n%s" % (bn, contents))

        return (fn, jd)

    def check_manifest(self):
        '''Check manifest'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.language_packs.keys()):
            t = 'error'
            n = self._get_check_name('manifest', app=app)
            s = "(NEEDS REVIEW) Language packs need manual review"
            # Return always valid, but request manual review. This is in order
            # to avoid having multiple language packs for the same language,
            # uploaded by different users.
            manual_review = True
            self._add_result(t, n, s, manual_review=manual_review)
