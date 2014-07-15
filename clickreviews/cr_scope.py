'''cr_scope.py: click scope'''
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

from clickreviews.cr_common import ClickReview, error, msg
import configparser
import os


class ClickReviewScope(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "scope")

        self.scopes = dict()
        for app in self.manifest['hooks']:
            if 'scope' not in self.manifest['hooks'][app]:
                msg("Skipped missing scope hook for '%s'" % app)
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

        ini_fn = os.path.join(fn, "%s.ini" % self.manifest['name'])
        ini_fn_bn = os.path.relpath(ini_fn, self.unpack_dir)
        if not os.path.exists(ini_fn):
            error("Could not find scope INI file '%s'" % ini_fn_bn)
        try:
            d["scope_config"] = configparser.ConfigParser()
            d["scope_config"].read(ini_fn)
        except Exception:
            error("scope config unparseable: %s (%s)" % (ini_fn_bn, str(e)))

        d["dir"] = fn
        d["dir_rel"] = bn
        d["ini_file"] = ini_fn
        d["ini_file_rel"] = ini_fn_bn

        return d

    def check_scope_ini(self):
        '''Check scope .ini file'''
        for app in sorted(self.scopes.keys()):
            t = 'info'
            n = 'ini_%s_scope_section' % app
            s = "OK"

            if len(self.scopes[app]["scope_config"].sections()) > 1:
                t = 'error'
                s = "'%s' has too many sections: %s" % (
                    self.scopes[app]["ini_file_rel"],
                    ", ".join(self.scopes[app]["scope_config"].sections()))
            elif "ScopeConfig" not in \
                    self.scopes[app]["scope_config"].sections():
                t = 'error'
                s = "Could not find 'ScopeConfig' in '%s'" % (
                    self.scopes[app]["ini_file_rel"])
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            # Make these all lower case for easier comparisons
            required = ['scoperunner',
                        'displayname',
                        'icon',
                        'searchhint']
            optional = ['description',
                        'author',
                        'art']

            missing = []
            t = 'info'
            n = 'ini_%s_scope_required_fields' % (app)
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
            n = 'ini_%s_scope_unknown_fields' % (app)
            s = 'OK'
            unknown = []
            for f in self.scopes[app]["scope_config"]['ScopeConfig'].keys():
                if f.lower() not in required and f.lower() not in optional:
                    unknown.append(f.lower())

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
