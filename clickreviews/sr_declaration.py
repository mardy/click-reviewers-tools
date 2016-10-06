'''sr_declaration.py: click declaration'''
#
# Copyright (C) 2014-2016 Canonical Ltd.
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
from clickreviews.sr_common import SnapReview, SnapReviewException


class SnapDeclarationException(SnapReviewException):
    '''This class represents SnapDeclaration exceptions'''


class SnapReviewDeclaration(SnapReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        SnapReview.__init__(self, fn, "declaration-snap-v2",
                            overrides=overrides)

        for series in self.base_declaration:
            self._verify_declaration(self.base_declaration[series], base=True)

    def _verify_declaration(self, decl, base=False):
        '''Verify declaration'''
        def malformed(s, base=False):
            pre = ""
            if base:
                pre = "base "
            err = "%sdeclaration malformed (%s)" % (pre, s)
            if base:
                raise SnapDeclarationException(err)
            return 'error', err

        def is_bool(item):
            if isinstance(item, int) and (item is True or item is False):
                return True
            return False

        if not isinstance(decl, dict):
            t, s = malformed("not a dict", base)
            if t == 'error':
                n = self._get_check_name('valid_dict')
                self._add_result(t, n, s)
                return

        for key in decl:
            if key not in ["plugs", "slots"]:
                t, s = malformed("unknown key '%s'" % key, base)
                if t == 'error':
                    n = self._get_check_name('valid_key')
                    self._add_result(t, n, s)
                    return

            if not isinstance(decl[key], dict):
                t, s = malformed("not True, False or dict", base)
                if t == 'error':
                    n = self._get_check_name('valid_dict', app=key)
                    self._add_result(t, n, s)
                    return

            for iface in decl[key]:
                # iface may be bool or dict
                if is_bool(decl[key][iface]):
                    n = self._get_check_name('valid', app=key, extra=iface)
                    self._add_result('info', n, 'OK')
                    continue
                elif not isinstance(decl[key][iface], dict):
                    t, s = malformed("%s not True, False or dict" % iface,
                                     base)
                    if t == 'error':
                        n = self._get_check_name('valid_dict', app=key,
                                                 extra=iface)
                        self._add_result(t, n, s)
                        continue

                for constraint in decl[key][iface]:
                    t = 'info'
                    n = self._get_check_name('valid_%s' % constraint,
                                             app=key, extra=iface)
                    s = "OK"
                    cstr = decl[key][iface][constraint]

                    if constraint in ["allow-installation",
                                      "deny-installation"]:
                        allowed = ["on-classic"]
                        if key == "plugs":
                            allowed.append("plug-snap-type")
                            allowed.append("plug-attributes")
                        elif key == "slots":
                            allowed.append("slot-snap-type")
                            allowed.append("slot-attributes")

                        # constraint may be bool or dict
                        if is_bool(cstr):
                            self._add_result(t, n, s)
                            continue
                        elif not isinstance(cstr, dict):
                            t, s = malformed("%s not True, False or dict" %
                                             constraint, base)
                            self._add_result(t, n, s)
                            continue

                        for cstr_key in cstr:
                            if cstr_key not in allowed:
                                t, s = malformed("unknown key '%s'" % cstr_key,
                                                 base)
                                self._add_result(t, n, s)
                                break
                    elif constraint in ["allow-connection",
                                        "allow-auto-connection",
                                        "deny-connection",
                                        "deny-auto-connection"]:
                        allowed = ["plug-attributes", "slot-attributes",
                                   "on-classic"]
                        if key == "plugs":
                            allowed.append("slot-publisher-id")
                            allowed.append("slot-snap-id")
                            allowed.append("slot-snap-type")
                        elif key == "slots":
                            allowed.append("plug-publisher-id")
                            allowed.append("plug-snap-id")
                            allowed.append("plug-snap-type")

                        # constraint may be bool or dict
                        if is_bool(cstr):
                            continue
                        elif not isinstance(cstr, dict):
                            t, s = malformed("not True, False or dict", base)
                            self._add_result(t, n, s)
                            continue

                        for cstr_key in cstr:
                            if cstr_key not in allowed:
                                t, s = malformed("unknown key '%s'" % cstr_key,
                                                 base)
                                self._add_result(t, n, s)
                                break
                    else:
                        t, s = malformed("unknown constraint '%s'" %
                                         constraint, base)
                        self._add_result(t, n, s)
                        break

                    cstr_bools = ["on-classic"]
                    cstr_lists = ["plug-snap-type",
                                  "slot-snap-type",
                                  "plug-publisher-id"
                                  "slot-publisher-id",
                                  "plug-snap-id",
                                  "slot-snap-id"
                                  ]
                    cstr_dicts = ["plug-attributes", "slot-attributes"]
                    for cstr_key in cstr:
                        if cstr_key in cstr_bools:
                            if not isinstance(cstr[cstr_key], int) and \
                                    cstr[cstr_key] is not True and \
                                    cstr[cstr_key] is not False:
                                t, s = malformed("'%s' not True or False" %
                                                 cstr_key, base)
                        elif cstr_key in cstr_lists:
                            if not isinstance(cstr[cstr_key], list):
                                t, s = malformed("'%s' not a list" % cstr_key,
                                                 base)
                            else:
                                for entry in cstr[cstr_key]:
                                    if not isinstance(entry, str):
                                        t, s = malformed("'%s' not string" %
                                                         entry, base)
                        elif cstr_key in cstr_dicts:
                            if not isinstance(cstr[cstr_key], dict):
                                t, s = malformed("'%s' not a dict" % cstr_key,
                                                 base)
                            # TODO

                    self._add_result(t, n, s)

    def check_base_declaration(self):
        '''Check base declaration'''
        if not self.is_snap2:
            return

        t = 'info'
        n = self._get_check_name('base-declaration')
        s = "OK"
        if False:
            t = 'error'
            s = "some message"
        self._add_result(t, n, s)
