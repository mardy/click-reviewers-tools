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
import re

# Specification:
# https://docs.google.com/document/d/1QkglVjSzHC65lPthXV3ZlQcqPpKxuGEBL-FMuGP6ogs/edit#


class SnapDeclarationException(SnapReviewException):
    '''This class represents SnapDeclaration exceptions'''


class SnapReviewDeclaration(SnapReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        SnapReview.__init__(self, fn, "declaration-snap-v2",
                            overrides=overrides)

        if not self.is_snap2:
            return

        self._verify_declaration(self.base_declaration, base=True)

        self.snap_declaration = None
        if overrides is not None and ('snap_decl_plugs' in overrides or
                                      'snap_decl_slots' in overrides):
            self.snap_declaration = {}
            self.snap_declaration = {'plugs': {}, 'slots': {}}
            if 'snap_decl_plugs' in overrides:
                self.snap_declaration['plugs'] = overrides['snap_decl_plugs']
            if 'snap_decl_slots' in overrides:
                self.snap_declaration['slots'] = overrides['snap_decl_slots']

            self._verify_declaration(self.snap_declaration, base=False)

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

        def _verify_constraint(constraint, cstr, key, iface, base, count):
            found_errors = False
            ctxt = constraint
            if count > 1:
                ctxt = "%s_%d" % (constraint, count)

            t = 'info'
            n = self._get_check_name('valid_%s' % key, app=iface,
                                     extra=ctxt)
            s = "OK"

            allowed_ctrs = ["allow-installation",
                            "deny-installation",
                            "allow-connection",
                            "allow-auto-connection",
                            "deny-connection",
                            "deny-auto-connection"
                            ]
            if constraint not in allowed_ctrs:
                malformed(n, "unknown constraint '%s'" % ctxt, base)
                return False

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
                return True
            elif not isinstance(cstr, dict):
                malformed(n, "%s not True, False or dict" % ctxt, base)
                # found_errors = True
                return True

            for cstr_key in cstr:
                if cstr_key not in allowed:
                    name = self._get_check_name('valid_%s' % key, app=iface,
                                                extra="%s_%s" % (ctxt,
                                                                 cstr_key))
                    malformed(name,
                              "unknown constraint key '%s'" % cstr_key, base)
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
                badn = self._get_check_name('valid_%s' % key, app=iface,
                                            extra="%s_%s" % (ctxt,
                                                             cstr_key))
                if cstr_key in cstr_bools:
                    if not isinstance(cstr[cstr_key], int) and \
                            cstr[cstr_key] is not True and \
                            cstr[cstr_key] is not False:
                        malformed(badn,
                                  "'%s' not True or False" % cstr_key, base)
                        found_errors = True
                elif cstr_key in cstr_lists:
                    if not isinstance(cstr[cstr_key], list):
                        malformed(badn, "'%s' not a list" % cstr_key, base)
                        found_errors = True
                    else:
                        for entry in cstr[cstr_key]:
                            if not isinstance(entry, str):
                                malformed(badn,
                                          "'%s' in '%s' not a string" %
                                          (entry, cstr_key), base)
                                found_errors = True
                elif cstr_key in cstr_dicts:
                    if not isinstance(cstr[cstr_key], dict):
                        malformed(badn, "'%s' not a dict" % cstr_key, base)
                        found_errors = True
                    else:
                        for attrib in cstr[cstr_key]:
                            bn = self._get_check_name('valid_%s' % key,
                                                      app=iface,
                                                      extra="%s_%s" %
                                                      (ctxt, cstr_key))
                            if iface not in self.interfaces_attribs:
                                malformed(bn,
                                          "unknown attribute '%s'" % attrib,
                                          base)
                                found_errors = True
                                continue

                            found_iface_attr = False
                            for tmp in self.interfaces_attribs[iface]:
                                known, side = tmp.split('/')
                                if attrib != known:
                                    continue
                                spec_side = side[:-1]

                                if cstr_key.startswith(spec_side):
                                    found_iface_attr = True

                                attr_type = cstr[cstr_key][attrib]
                                if not isinstance(attr_type,
                                                  type(self.interfaces_attribs[iface][tmp])):
                                    malformed(bn,
                                              "wrong type '%s' for attribute '%s'"
                                              % (attr_type, attrib),
                                              base)
                                    found_errors = True
                                    break

                            if not found_iface_attr:
                                malformed(bn,
                                          "attribute '%s' wrong for '%ss'"
                                          % (attrib, cstr_key[:4]),
                                          base)
                                found_errors = True

                if not found_errors and \
                        cstr_key == "plug-publisher-id" or \
                        cstr_key == "slot-publisher-id":
                    for pubid in cstr[cstr_key]:
                        if not pub_pat.search(pubid):
                            malformed(n,
                                      "invalid format for publisher id '%s'" %
                                      pubid)
                            found_errors = True
                            break
                        if pubid.startswith('$'):
                            if cstr_key == "plug-publisher-id" and \
                                    pubid != "$SLOT_PUBLISHER_ID":
                                malformed(n,
                                          "invalid publisher id '%s'" % pubid)
                                found_errors = True
                                break
                            elif cstr_key == "slot-publisher-id" and \
                                    pubid != "$PLUG_PUBLISHER_ID":
                                malformed(n,
                                          "invalid publisher id '%s'" % pubid)
                                found_errors = True
                                break
                elif not found_errors and \
                        cstr_key == "plug-snap-id" or \
                        cstr_key == "slot-snap-id":
                    for id in cstr[cstr_key]:
                        if not id_pat.search(id):
                            malformed(n,
                                      "invalid format for snap id '%s'" % id)
                            found_errors = True
                            break
                elif not found_errors and \
                        cstr_key == "plug-snap-type" or \
                        cstr_key == "slot-snap-type":
                    for snap_type in cstr[cstr_key]:
                        if snap_type not in self.valid_snap_types:
                            malformed(n, "invalid snap type '%s'" % snap_type)
                            found_errors = True
                            break

            if not base and not found_errors:
                self._add_result(t, n, s)

            return True

        # from snapd.git/assers/ifacedecls.go
        id_pat = re.compile(r'^[a-z0-9A-Z]{32}$')
        pub_pat = re.compile(r'^(?:[a-z0-9A-Z]{32}|[-a-z0-9]{2,28}|\$[A-Z][A-Z0-9_]*)$')

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
                elif isinstance(decl[key][iface], list):
                    err = False
                    for item in decl[key][iface]:
                        if not isinstance(item, dict):
                            malformed(self._get_check_name('valid_%s_alt_dict'
                                                           % key, app=iface),
                                      "interface alternate not True, False or dict",
                                      base)
                            err = True
                            break
                    if err:
                        continue
                elif not isinstance(decl[key][iface], dict):
                    malformed(self._get_check_name('valid_%s_dict' % key,
                                                   app=iface),
                              "interface not True, False or dict", base)
                    continue

                alternates = []
                if isinstance(decl[key][iface], dict):
                    alternates.append(decl[key][iface])
                else:
                    alternates = decl[key][iface]

                count = 1
                for alt in alternates:
                    for constraint in alt:
                        cstr = alt[constraint]
                        if not _verify_constraint(constraint, cstr, key,
                                                  iface, base, count):
                            break
                    count += 1

    def _match(self, against, val):
        '''Ordering matters since 'against' is treated as a regex if str'''
        if type(against) != type(val):
            return False

        if type(val) not in [str, list, dict, bool]:
            raise SnapDeclarationException("unknown type '%s'" % val)

        matched = False

        if isinstance(val, str):
            if re.search(r'^(%s)$' % against, val):
                matched = True
        elif isinstance(val, list):
            matched = (sorted(against) == sorted(val))
        else:  # bools and dicts
            matched = (against == val)

        return matched

    def _search(self, d, key, val=None, subkey=None, subval=None, subval_inverted=False):
        '''Search dictionary 'd' for matching values. Returns true when
           - val == d[key]
           - subval in d[key][subkey]
           - subval dictionary has any matches in d[key][subkey] dict
           - subval_inverted == True and subval not in d[key][subkey]
           - subval_inverted == True and subval has any non-matches in
             d[key][subkey] dict

           has_say is True if the key/subkey is present but the value doesn't
           match
        '''
        found = False
        has_say = False
        if key not in d:
            return (found, has_say)
        has_say = True

        if val is not None and val == d[key]:
            found = True
        elif isinstance(d[key], dict) and subkey is not None and \
                subval is not None and subkey in d[key]:
            if isinstance(d[key][subkey], list):
                if subval_inverted:
                    if subval not in d[key][subkey]:
                        found = True
                elif subval in d[key][subkey]:
                    found = True
            elif isinstance(d[key][subkey], dict) and isinstance(subval, dict):
                d_keys = set(d[key][subkey].keys())
                subval_keys = set(subval.keys())
                int_keys = d_keys.intersection(subval_keys)
                matches = 0
                for subsubkey in int_keys:
                    if self._match(d[key][subkey][subsubkey],
                                   subval[subsubkey]):
                        found = True
                        matches += 1

                if subval_inverted:
                    # return true when something didn't match
                    if matches != len(int_keys):
                        found = True
                    else:
                        found = False

        return (found, has_say)

    def _manual(self, decls, side, key_type, subkey=None, subval=None, decl_types=["snap", "base"]):
        for i in decl_types:
            if side not in decls[i]:
                continue

            for d in decls[i][side]:
                for k in ['deny', 'allow']:
                    val = None
                    subval_inverted = False
                    key = "%s-%s" % (k, key_type)

                    if subkey is None:
                        if k == "deny":
                            val = True
                        else:
                            val = False
                    else:
                        subval_inverted = (k == 'allow')

                    (found, has_say) = self._search(d, key, val, subkey, subval, subval_inverted)

                    if found:
                        return (found, i, key)
                    elif has_say:
                        return (False, None, None)

        return (False, None, None)

    def _get_decls(self, interface):
        '''Create data structure used by _manual()'''
        def _create_decls(side, interface, base=False):
            decls = []
            if base:
                d = self.base_declaration
            else:
                d = self.snap_declaration

            if side in d and interface in d[side]:
                cstrs = []
                if isinstance(d[side][interface], list):
                    cstrs = d[side][interface]
                else:
                    cstrs.append(d[side][interface])

                for cstr in cstrs:
                    decl = {}
                    if isinstance(cstr, dict):
                        for k in cstr:
                            decl[k] = cstr[k]
                    else:
                        decl = cstr

                    decls.append(decl)

            return decls

        decls = {}
        decls['snap'] = {}
        decls['base'] = {}
        for side in ['plugs', 'slots']:
            if self.snap_declaration is not None:
                decls['snap'][side] = _create_decls(side, interface)
            decls['base'][side] = _create_decls(side, interface, True)

        return decls

    def _verify_iface(self, name, iface, interface, attribs=None):
        '''verify interface
           This will:
           - error if interface doesn't exist in base declaration
           - flag if allow/deny-connection/installation matches boolean
           - flag if allow/deny-installation snap-type doesn't match
           - flag if allow/deny-connection attributes don't match
           - flag if allow/deny-connection attributes don't match slot side of
             base declaration (since base declaration is mostly slot side)
        '''
        if name.endswith('slot'):
            side = 'slots'
            oside = 'plugs'
        elif name.endswith('plug'):
            side = 'plugs'
            oside = 'slots'

        t = 'info'
        n = self._get_check_name('%s_known' % name, app=iface, extra=interface)
        s = 'OK'
        if side in self.base_declaration and \
                interface not in self.base_declaration[side] and \
                oside in self.base_declaration and \
                interface not in self.base_declaration[oside]:
            if name.startswith('app_') and side in self.snap_yaml and \
                    interface in self.snap_yaml[side]:
                # If it is an interface reference used by an app, skip since it
                # will be checked in top-level interface checks.
                return
            t = 'error'
            s = "interface '%s' not found in base declaration" % interface
            self._add_result(t, n, s)
            return

        decls = self._get_decls(interface)

        # top-level allow/deny-installation
        ok = True
        (require_manual, decl_type, decl_key) = self._manual(decls, side,
                                                             "installation")
        if require_manual:
            self._add_result('error',
                             self._get_check_name("%s_%s" %
                                                  (side, decl_key),
                                                  app=iface,
                                                  extra=interface),
                             "not allowed by '%s' in %s declaration" %
                             (decl_key, decl_type),
                             manual_review=True)
            ok = False

        # top-level allow/deny-connection
        (require_manual, decl_type, decl_key) = self._manual(decls, side,
                                                             "connection")
        if require_manual:
            self._add_result('error',
                             self._get_check_name("%s_%s" %
                                                  (side, decl_key),
                                                  app=iface,
                                                  extra=interface),
                             "not allowed by '%s' in %s declaration" %
                             (decl_key, decl_type),
                             manual_review=True)
            ok = False

        # deny/allow-installation snap-type
        snap_type = 'app'
        if 'type' in self.snap_yaml:
            snap_type = self.snap_yaml['type']
            if snap_type == 'os':
                snap_type = 'core'
        decl_subkey = '%s-snap-type' % side[:-1]

        (require_manual, decl_type, decl_key) = self._manual(decls, side,
                                                             "installation",
                                                             subkey=decl_subkey,
                                                             subval=snap_type)
        if require_manual:
            self._add_result('error',
                             self._get_check_name("%s_%s" %
                                                  (side, decl_key),
                                                  app=iface,
                                                  extra=interface),
                             "not allowed by '%s/%s' in %s declaration" %
                             (decl_key, decl_subkey, decl_type),
                             manual_review=True)
            ok = False

        # deny/allow-connection attributes
        decl_subkey = '%s-attributes' % side[:-1]
        if attribs is not None:
            # flag if any deny-*/attribs match or any allow-*/attribs don't
            (require_manual, decl_type, decl_key) = self._manual(decls, side,
                                                                 "connection",
                                                                 subkey=decl_subkey,
                                                                 subval=attribs)
            if require_manual:
                self._add_result('error',
                                 self._get_check_name("%s_%s" %
                                                      (side, decl_key),
                                                      app=iface,
                                                      extra=interface),
                                 "not allowed by '%s/%s' in %s declaration" %
                                 (decl_key, decl_subkey, decl_type),
                                 manual_review=True)
                ok = False
            # Since base declaration mostly has slots side, if plugs, look
            # at the other side for checking plug-attributes
            elif len(decls["snap"]) == 0 and side == 'plugs':
                (require_manual, decl_type, decl_key) = self._manual(decls,
                                                                     oside,
                                                                     "connection",
                                                                     subkey=decl_subkey,
                                                                     subval=attribs,
                                                                     decl_types=["base"])
                if require_manual:
                    self._add_result('error',
                                     self._get_check_name("%s_%s" %
                                                          (side, decl_key),
                                                          app=iface,
                                                          extra=interface),
                                     "not allowed by '%s/%s' in %s declaration" %
                                     (decl_key, decl_subkey, decl_type),
                                     manual_review=True)
                    ok = False

        # Report something back if everything ok
        if ok:
            self._add_result('info',
                             self._get_check_name("%s" % side, app=iface,
                                                  extra=interface),
                             "OK", manual_review=False)

    def check_declaration(self):
        '''Check base/snap declaration requires manual review for top-level
           plugs/slots
        '''
        if not self.is_snap2:
            return

        for side in ['plugs', 'slots']:
            if side not in self.snap_yaml:
                continue

            for iface in self.snap_yaml[side]:
                # If the 'interface' name is the same as the 'plug/slot' name,
                # then 'interface' is optional since the interface name and the
                # plug/slot name are the same
                interface = iface
                attribs = None

                spec = self.snap_yaml[side][iface]
                if isinstance(spec, str):
                    # Abbreviated syntax (no attributes)
                    # <plugs|slots>:
                    #   <alias>: <interface>
                    interface = spec
                elif 'interface' in spec:
                    # Full specification.
                    # <plugs|slots>:
                    #   <alias>:
                    #     interface: <interface>
                    interface = spec['interface']
                    if len(spec) > 1:
                        attribs = spec
                        del attribs['interface']

                self._verify_iface(side[:-1], iface, interface, attribs)

    def check_declaration_apps(self):
        '''Check base/snap declaration requires manual review for apps
           plugs/slots
        '''
        if not self.is_snap2 or 'apps' not in self.snap_yaml:
            return

        for app in self.snap_yaml['apps']:
            for side in ['plugs', 'slots']:
                if side not in self.snap_yaml['apps'][app]:
                    continue

                # The interface referenced in the app's 'plugs' or 'slots'
                # field can either be a known interface (when the interface
                # name reference and the interface is the same) or can
                # reference a name in the snap's toplevel 'plugs' or 'slots'
                # mapping
                for ref in self.snap_yaml['apps'][app][side]:
                    if not isinstance(ref, str):
                        continue  # checked elsewhere

                    self._verify_iface('app_%s' % side[:-1], app, ref)
