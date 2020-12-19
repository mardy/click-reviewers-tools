'''cr_scope.py: click scope'''
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

from clickreviews.cr_common import ClickReview, error
import codecs
import configparser
import os
import re

# Please refer to the config file documentation at:
# https://github.com/ubports/unity-scopes-api/blob/xenial/CONFIGFILES

KNOWN_SECTIONS = set(["ScopeConfig", "Appearance"])


class ClickReviewScope(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        peer_hooks = dict()
        my_hook = 'scope'
        peer_hooks[my_hook] = dict()
        peer_hooks[my_hook]['allowed'] = ClickReview.scope_allowed_peer_hooks
        peer_hooks[my_hook]['required'] = ['apparmor']

        ClickReview.__init__(self, fn, "scope", peer_hooks=peer_hooks,
                             overrides=overrides)

        if not self.is_click and not self.is_snap1:
            return

        self.scopes = dict()

        if self.manifest is None:
            return

        for app in self.manifest['hooks']:
            if 'scope' not in self.manifest['hooks'][app]:
                # msg("Skipped missing scope hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['scope'], str):
                error("manifest malformed: hooks/%s/scope is not str" % app)
            self.scopes[app] = self._extract_scopes(app)

    def _extract_scopes(self, app):
        '''Get scopes'''
        d = dict()

        s = self.manifest['hooks'][app]['scope']
        fn = os.path.join(self.unpack_dir, s)

        bn = os.path.basename(fn)
        if not os.path.exists(fn):
            error("Could not find '%s'" % bn)
        elif not os.path.isdir(fn):
            error("'%s' is not a directory" % bn)

        ini_fn = os.path.join(fn, "%s_%s.ini" % (self.manifest['name'], app))
        ini_fn_bn = os.path.relpath(ini_fn, self.unpack_dir)
        if not os.path.exists(ini_fn):
            error("Could not find scope INI file '%s'" % ini_fn_bn)
        try:
            d["scope_config"] = configparser.ConfigParser()
            d["scope_config"].read_file(codecs.open(ini_fn, "r", "utf8"))
        except Exception as e:
            error("scope config unparseable: %s (%s)" % (ini_fn_bn, str(e)))

        d["dir"] = fn
        d["dir_rel"] = bn
        d["ini_file"] = ini_fn
        d["ini_file_rel"] = ini_fn_bn

        return d

    def check_scope_ini(self):
        '''Check scope .ini file'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.scopes.keys()):
            t = 'info'
            n = self._get_check_name('ini_scope_section', app=app)
            s = "OK"

            sections = set(self.scopes[app]["scope_config"].sections())
            unknown_sections = sections.difference(KNOWN_SECTIONS)

            if unknown_sections:
                t = 'error'
                s = "'%s' has unknown sections: %s" % (
                    self.scopes[app]["ini_file_rel"],
                    ", ".join(unknown_sections))
            elif "ScopeConfig" not in sections:
                t = 'error'
                s = "Could not find 'ScopeConfig' in '%s'" % (
                    self.scopes[app]["ini_file_rel"])
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            # Make these all lower case for easier comparisons
            required = ['author',
                        'description',
                        'displayname']
            optional = ['art',
                        'childscopes',
                        'hotkey',
                        'icon',
                        'idletimeout',
                        'invisible',
                        'keywords',
                        'locationdataneeded',
                        'resultsttltype',
                        'scoperunner',
                        'searchhint']
            translated = ['description',
                          'displayname',
                          'searchhint']
            internal = ['debugmode']

            missing = []
            t = 'info'
            n = self._get_check_name('ini_scope_required_fields', app=app)
            s = "OK"
            for r in required:
                if r not in self.scopes[app]["scope_config"]['ScopeConfig']:
                    missing.append(r)
            if len(missing) == 1:
                t = 'error'
                s = "Missing required field in '%s': %s" % (
                    self.scopes[app]["ini_file_rel"],
                    missing[0])
            elif len(missing) > 1:
                t = 'error'
                s = "Missing required fields in '%s': %s" % (
                    self.scopes[app]["ini_file_rel"],
                    ", ".join(missing))
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('ini_scope_unknown_fields', app=app)
            s = 'OK'
            unknown = []
            for i in self.scopes[app]["scope_config"]['ScopeConfig'].keys():
                f = i.lower()
                if f not in required and f not in optional and \
                    f not in internal and \
                    (f.split("[")[0] not in translated or not
                        re.search(r'.*\[[a-z]{2,3}(_[a-z]{2,3})?\]$', f)):
                    unknown.append(f)

            if len(unknown) == 1:
                t = 'warn'
                s = "Unknown field in '%s': %s" % (
                    self.scopes[app]["ini_file_rel"],
                    unknown[0])
            elif len(unknown) > 1:
                t = 'warn'
                s = "Unknown fields in '%s': %s" % (
                    self.scopes[app]["ini_file_rel"],
                    ", ".join(unknown))
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('ini_scope_internal_fields', app=app)
            s = "OK"
            forbidden = []
            for r in internal:
                if r in self.scopes[app]["scope_config"]['ScopeConfig']:
                    forbidden.append(r)
            if len(forbidden) == 1:
                t = 'error'
                s = "Forbidden field in '%s': %s" % (
                    self.scopes[app]["ini_file_rel"],
                    forbidden[0])
            elif len(forbidden) > 1:
                t = 'error'
                s = "Forbidden fields in '%s': %s" % (
                    self.scopes[app]["ini_file_rel"],
                    ", ".join(forbidden))
            self._add_result(t, n, s)
