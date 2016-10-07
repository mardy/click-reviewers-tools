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
        def malformed(name, s, base=False):
            pre = ""
            if base:
                pre = "base "
            err = "%sdeclaration malformed (%s)" % (pre, s)
            if base:
                raise SnapDeclarationException(err)
            self._add_result('error', name, err)

        def is_bool(item):
            if isinstance(item, int) and (item is True or item is False):
                return True
            return False

        if not isinstance(decl, dict):
            malformed(self._get_check_name('valid_dict'), "not a dict", base)
            return
        elif len(decl) == 0:
            malformed(self._get_check_name('valid_dict'), "empty", base)
            return

        for key in decl:
            if key not in ["plugs", "slots"]:
                malformed(self._get_check_name('valid_key'),
                          "unknown key '%s'" % key, base)
                return

            if not isinstance(decl[key], dict):
                malformed(self._get_check_name('valid_dict', app=key),
                          "not a dict", base)
                return

            for iface in decl[key]:
                # iface may be bool or dict
                if is_bool(decl[key][iface]):
                    n = self._get_check_name('valid_%s' % key, app=iface)
                    self._add_result('info', n, 'OK')
                    continue
                elif not isinstance(decl[key][iface], dict):
                    malformed(self._get_check_name('valid_%s_dict' % key,
                                                   app=iface),
                              "interface not True, False or dict", base)
                    continue

                found_errors = False
                for constraint in decl[key][iface]:
                    t = 'info'
                    n = self._get_check_name('valid_%s' % key, app=iface,
                                             extra=constraint)
                    s = "OK"
                    cstr = decl[key][iface][constraint]

                    allowed_ctrs = ["allow-installation",
                                    "deny-installation",
                                    "allow-connection",
                                    "allow-auto-connection",
                                    "deny-connection",
                                    "deny-auto-connection"
                                    ]
                    if constraint not in allowed_ctrs:
                        malformed(n, "unknown constraint '%s'" % constraint,
                                  base)
                        break

                    allowed = []
                    if constraint.endswith("-installation"):
                        allowed = ["on-classic"]
                        if key == "plugs":
                            allowed.append("plug-snap-type")
                            allowed.append("plug-attributes")
                        elif key == "slots":
                            allowed.append("slot-snap-type")
                            allowed.append("slot-attributes")
                    else:
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
                        if not base:
                            self._add_result('info', n, s)
                        continue
                    elif not isinstance(cstr, dict):
                        malformed(n, "%s not True, False or dict" %
                                  constraint, base)
                        continue

                    for cstr_key in cstr:
                        if cstr_key not in allowed:
                            name = self._get_check_name('valid_%s' % key,
                                                        app=iface,
                                                        extra="%s_%s" % (
                                                               constraint,
                                                               cstr_key))
                            malformed(name, "unknown constraint key '%s'" %
                                      cstr_key, base)
                            found_errors = True

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
                                malformed(n, "'%s' not True or False" %
                                          cstr_key, base)
                        elif cstr_key in cstr_lists:
                            if not isinstance(cstr[cstr_key], list):
                                malformed(n, "'%s' not a list" % cstr_key,
                                          base)
                            else:
                                for entry in cstr[cstr_key]:
                                    if not isinstance(entry, str):
                                        malformed(n, "'%s' not string" % entry,
                                                  base)
                        elif cstr_key in cstr_dicts:
                            if not isinstance(cstr[cstr_key], dict):
                                malformed(n, "'%s' not a dict" % cstr_key,
                                          base)
                            else:
                                for attrib in cstr[cstr_key]:
                                    if iface not in self.interfaces_attribs:
                                        malformed(n, "unknown attribute '%s'" %
                                                  attrib, base)
                                        continue
                                    for tmp in self.interfaces_attribs[iface]:
                                        known, side = tmp.split('/')
                                        spec_side = side[:-1]
                                        if not cstr_key.startswith(spec_side):
                                            malformed(n, "attribute '%s' wrong for '%ss'" % (attrib, spec_side), base)
                                            continue
                                        attr_type = cstr[cstr_key][attrib]
                                        if not isinstance(attr_type, type(self.interfaces_attribs[iface][tmp])):
                                            malformed(n, "wrong type '%s' for attribute '%s'" % (attr_type, attrib), base)
                                            continue
                    # TODO: verify snap-type, publisher-id

                    if not base and not found_errors:
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
