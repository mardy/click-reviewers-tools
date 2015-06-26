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

from clickreviews.cr_common import ClickReview, error, open_file_read
import yaml
import os
import re


class ClickReviewSystemd(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        peer_hooks = dict()
        my_hook = 'snappy-systemd'
        peer_hooks[my_hook] = dict()
        peer_hooks[my_hook]['required'] = ["apparmor"]
        peer_hooks[my_hook]['allowed'] = peer_hooks[my_hook]['required']

        ClickReview.__init__(self, fn, "snappy-systemd", peer_hooks=peer_hooks,
                             overrides=overrides)

        # snappy-systemd currently only allows specifying:
        # - start (required)
        # - description (required)
        # - stop
        # - poststop
        # - stop-timeout
        # - caps (checked in in cr_security.py)
        # - security-template (checked in in cr_security.py)
        # - security-override (checked in in cr_security.py)
        # - security-policy (checked in in cr_security.py)
        self.required_keys = ['start', 'description']
        self.optional_keys = ['stop',
                              'poststop',
                              'stop-timeout',
                              'bus-name',
                              'ports'
                              ] + self.snappy_exe_security

        self.systemd_files = dict()  # click-show-files and tests
        self.systemd = dict()

        if self.is_snap and 'services' in self.pkg_yaml:
            if len(self.pkg_yaml['services']) == 0:
                error("package.yaml malformed: 'services' is empty")
            for service in self.pkg_yaml['services']:
                if 'name' not in service:
                    error("package.yaml malformed: required 'name' not found "
                          "for entry in %s" % self.pkg_yaml['services'])
                elif not isinstance(service['name'], str):
                    error("package.yaml malformed: required 'name' is not str"
                          "for entry in %s" % self.pkg_yaml['services'])

                app = service['name']
                (full_fn, yd) = self._extract_systemd(app)
                self.systemd_files[app] = full_fn
                self.systemd[app] = yd

        # Now verify click manifest
        for app in self.manifest['hooks']:
            if not self.is_snap and \
               'snappy-systemd' not in self.manifest['hooks'][app]:
                #  non-snappy clicks don't need snappy-systemd hook
                # msg("Skipped missing systemd hook for '%s'" % app)
                continue
            elif 'snappy-systemd' in self.manifest['hooks'][app] and \
                 not isinstance(self.manifest['hooks'][app]['snappy-systemd'],
                                str):
                error("manifest malformed: hooks/%s/snappy-systemd is not str"
                      % app)

    def _extract_systemd(self, app):
        '''Get systemd yaml'''
        fn = os.path.join(self.unpack_dir, "meta", "%s.snappy-systemd" % app)

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

    def _verify_required(self, my_dict, test_str):
        for app in sorted(my_dict):
            f = os.path.basename(self.systemd_files[app])
            for r in self.required_keys:
                found = False
                t = 'info'
                n = '%s_required_key_%s_%s' % (test_str, r, f)
                s = "OK"
                if r in my_dict[app]:
                    if not isinstance(my_dict[app][r], str):
                        t = 'error'
                        s = "'%s' is not a string" % r
                    elif my_dict[app][r] == "":
                        t = 'error'
                        s = "'%s' is empty" % r
                    else:
                        found = True
                if not found and t != 'error':
                    t = 'error'
                    s = "Missing required field '%s'" % r
                self._add_result(t, n, s)

    def check_required(self):
        '''Check snappy-systemd required fields'''
        self._verify_required(self.systemd, 'hook')

    def check_snappy_required(self):
        '''Check for package.yaml required fields'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_required(self._create_dict(self.pkg_yaml['services']),
                              'package_yaml')

    def _verify_optional(self, my_dict, test_str):
        for app in sorted(my_dict):
            f = os.path.basename(self.systemd_files[app])
            for o in self.optional_keys:
                if o in self.snappy_exe_security:
                    continue  # checked in cr_security.py
                found = False
                t = 'info'
                n = '%s_optional_key_%s_%s' % (test_str, o, f)
                s = "OK"
                if o in my_dict[app]:
                    if o == 'stop-timeout':
                        if isinstance(my_dict[app][o], int):
                            found = True
                        elif not isinstance(my_dict[app][o], str):
                            t = 'error'
                            s = "'%s' is not a string or integer" % o
                        elif not re.search(r'[0-9]+[ms]?$', my_dict[app][o]):
                            t = 'error'
                            s = "'%s' is not of form NN[ms] (%s)" % \
                                (my_dict[app][o], o)
                        else:
                            found = True
                    elif o == 'ports':
                        if not isinstance(my_dict[app][o], dict):
                            t = 'error'
                            s = "'%s' is not dictionary" % o
                    elif not isinstance(my_dict[app][o], str):
                        t = 'error'
                        s = "'%s' is not a string" % o
                    elif my_dict[app][o] == "":
                        t = 'error'
                        s = "'%s' is empty" % o
                    else:
                        found = True
                if not found and t != 'error':
                    s = "OK (skip missing)"
                self._add_result(t, n, s)

    def check_optional(self):
        '''Check snappy-systemd optional fields'''
        self._verify_optional(self.systemd, 'hook')

    def check_snappy_optional(self):
        '''Check snappy packate.yaml optional fields'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_optional(self._create_dict(self.pkg_yaml['services']),
                              'package_yaml')

    def _verify_unknown(self, my_dict, test_str):
        for app in sorted(my_dict):
            f = os.path.basename(self.systemd_files[app])
            unknown = []
            t = 'info'
            n = '%s_unknown_key_%s' % (test_str, f)
            s = "OK"

            for f in my_dict[app].keys():
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

    def check_unknown(self):
        '''Check snappy-systemd unknown fields'''
        self._verify_unknown(self.systemd, 'hook')

    def check_snappy_unknown(self):
        '''Check snappy package.yaml unknown fields'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_unknown(self._create_dict(self.pkg_yaml['services']),
                             'package_yaml')

    def _verify_service_description(self, my_dict, test_str):
        '''Check snappy-systemd description'''
        for app in sorted(my_dict):
            f = os.path.basename(self.systemd_files[app])
            t = 'info'
            n = '%s_description_present_%s' % (test_str, f)
            s = 'OK'
            if 'description' not in my_dict[app]:
                s = 'required description field not specified'
                self._add_result('error', n, s)
                return
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_description_empty_%s' % (test_str, f)
            s = 'OK'
            if len(my_dict[app]['description']) == 0:
                t = 'error'
                s = "description is empty"
            self._add_result(t, n, s)

    def check_service_description(self):
        '''Check snappy-systemd description'''
        self._verify_service_description(self.systemd, 'hook')

    def check_snappy_service_description(self):
        '''Check snappy package.yaml description'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_service_description(self._create_dict(
                                         self.pkg_yaml['services']),
                                         'package_yaml')

    def _verify_entry(self, my_dict, d, test_str):
        for app in sorted(my_dict):
            if d not in my_dict[app]:
                continue
            f = os.path.basename(self.systemd_files[app])

            t = 'info'
            n = '%s_%s_empty_%s' % (test_str, d, f)
            s = 'OK'
            if len(my_dict[app][d]) == 0:
                t = 'error'
                s = "%s entry is empty" % d
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_%s_absolute_path_%s' % (test_str, d, f)
            s = 'OK'
            if my_dict[app][d].startswith('/'):
                t = 'error'
                s = "'%s' should not specify absolute path" % my_dict[app][d]
            self._add_result(t, n, s)

    def check_service_start(self):
        '''Check snappy-systemd start'''
        self._verify_entry(self.systemd, 'start', 'hook')

    def check_snappy_service_start(self):
        '''Check snappy package.yaml start'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_entry(self._create_dict(self.pkg_yaml['services']),
                           'start', 'package_yaml')

    def check_service_stop(self):
        '''Check snappy-systemd stop'''
        self._verify_entry(self.systemd, 'stop', 'hook')

    def check_snappy_service_stop(self):
        '''Check snappy package.yaml stop'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_entry(self._create_dict(self.pkg_yaml['services']),
                           'stop', 'package_yaml')

    def check_service_poststop(self):
        '''Check snappy-systemd poststop'''
        self._verify_entry(self.systemd, 'poststop', 'hook')

    def check_snappy_service_poststop(self):
        '''Check snappy package.yaml poststop'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_entry(self._create_dict(self.pkg_yaml['services']),
                           'poststop', 'package_yaml')

    def _verify_service_stop_timeout(self, my_dict, test_str):
        for app in sorted(my_dict):
            f = os.path.basename(self.systemd_files[app])
            t = 'info'
            n = '%s_stop_timeout_%s' % (test_str, f)
            s = "OK"

            if 'stop-timeout' not in my_dict[app]:
                s = "OK (skip missing)"
                self._add_result(t, n, s)
                return

            st = my_dict[app]['stop-timeout']

            if not isinstance(st, int) and not isinstance(st, str):
                t = 'error'
                s = 'stop-timeout is not a string or integer'
                self._add_result(t, n, s)
                return

            if isinstance(st, str):
                if re.search(r'[0-9]+[ms]?$', st):
                    st = int(st.rstrip(r'[ms]'))
                else:
                    t = 'error'
                    s = "'%s' is not of form NN[ms] (%s)" % (my_dict[app], st)
                self._add_result(t, n, s)
                return

            if st < 0 or st > 60:
                t = 'error'
                s = "stop-timeout '%d' out of range (0-60)" % \
                    my_dict[app]['stop-timeout']

            self._add_result(t, n, s)

    def check_service_stop_timeout(self):
        '''Check snappy-systemd stop-timeout'''
        self._verify_service_stop_timeout(self.systemd, 'hook')

    def check_snappy_service_stop_timeout(self):
        '''Check snappy package.yaml stop-timeout'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_service_stop_timeout(self._create_dict(
                                          self.pkg_yaml['services']),
                                          'package_yaml')

    def _verify_service_bus_name(self, pkgname, my_dict, test_str):
        for app in sorted(my_dict):
            if 'bus-name' not in my_dict[app]:
                continue
            f = os.path.basename(self.systemd_files[app])

            t = 'info'
            n = '%s_bus-name_empty_%s' % (test_str, f)
            s = 'OK'
            if len(my_dict[app]['bus-name']) == 0:
                t = 'error'
                s = "'bus-name' is empty"
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_bus-name_format_%s' % (test_str, f)
            l = None
            s = 'OK'
            if not re.search(r'^[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9][A-Za-z0-9_-]*)+$',
                             my_dict[app]['bus-name']):
                t = 'error'
                l = 'http://dbus.freedesktop.org/doc/dbus-specification.html'
                s = "'%s' is not of form '^[A-Za-z0-9][A-Za-z0-9_-]*(\\.[A-Za-z0-9][A-Za-z0-9_-]*)+$'" % \
                    (my_dict[app]['bus-name'])
            self._add_result(t, n, s, l)

            t = 'info'
            n = '%s_bus-name_matches_name_%s' % (test_str, f)
            s = 'OK'
            suggested = [pkgname,
                         "%s.%s" % (pkgname, app)
                         ]
            if self.is_snap and 'vendor' in self.pkg_yaml:
                tmp = self.pkg_yaml['vendor'].split('@')
                if len(tmp) > 1:
                    rev = tmp[1].rstrip('>').split('.')
                    rev.reverse()
                    suggested.append("%s.%s" % (".".join(rev),
                                                pkgname))
                    suggested.append("%s.%s.%s" % (".".join(rev),
                                                   pkgname,
                                                   app))
            found = False
            for name in suggested:
                if my_dict[app]['bus-name'].endswith(name):
                    found = True
                    break
            if not found:
                t = 'error'
                s = "'%s' doesn't end with one of: %s" % \
                    (my_dict[app]['bus-name'], ", ".join(suggested))
            self._add_result(t, n, s)

    def check_service_bus_name(self):
        '''Check snappy-systemd bus-name'''
        self._verify_service_bus_name(self.click_pkgname, self.systemd, 'hook')

    def check_snappy_service_bus_name(self):
        '''Check snappy package.yaml bus-name'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_service_bus_name(self.pkg_yaml['name'],
                                      self._create_dict(
                                          self.pkg_yaml['services']),
                                      'package_yaml')

    def _verify_service_ports(self, pkgname, my_dict, test_str):
        for app in sorted(my_dict):
            if 'ports' not in my_dict[app]:
                continue
            f = os.path.basename(self.systemd_files[app])

            t = 'info'
            n = '%s_ports_empty_%s' % (test_str, f)
            s = 'OK'
            if len(my_dict[app]['ports'].keys()) == 0:
                t = 'error'
                s = "'ports' must contain 'internal' and/or 'external'"
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_ports_bad_key_%s' % (test_str, f)
            s = 'OK'
            badkeys = []
            for i in my_dict[app]['ports'].keys():
                if i not in ['internal', 'external']:
                    badkeys.append(i)
            if len(badkeys) > 0:
                t = 'error'
                s = "Unknown '%s' found in 'ports'" % ",".join(badkeys)
            self._add_result(t, n, s)

            port_pat = re.compile(r'^[0-9]+/[a-z0-9\-]+$')
            for key in ['internal', 'external']:
                if key not in my_dict[app]['ports']:
                    continue

                if len(my_dict[app]['ports'][key].keys()) < 1:
                    t = 'error'
                    n = '%s_ports_%s_%s' % (test_str, key, f)
                    s = 'Could not find any %s ports' % key
                    self._add_result(t, n, s)
                    continue

                for tagname in my_dict[app]['ports'][key]:
                    entry = my_dict[app]['ports'][key][tagname]
                    if len(entry.keys()) < 1:
                        t = 'error'
                        n = '%s_ports_%s_%s' % (test_str, key, f)
                        s = 'Could not find any subkeys for %s' % tagname
                        self._add_result(t, n, s)
                        continue
                    # Annoyingly, the snappy-systemd file uses 'Port' and
                    # 'Negotiable' instead of 'port' and 'negotiable' from the
                    # yaml
                    if (test_str == 'package_yaml' and
                            'negotiable' not in entry and
                            'port' not in entry) or \
                       (test_str == 'hook' and
                            'Negotiable' not in entry and
                            'Port' not in entry):
                        t = 'error'
                        n = '%s_ports_%s_invalid_%s' % (test_str, key, f)
                        s = "Must specify specify at least 'port' or " + \
                            "'negotiable'"
                        self._add_result(t, n, s)
                        continue

                    # port
                    subkey = 'port'
                    if test_str == 'hook':
                        subkey = 'Port'
                    t = 'info'
                    n = '%s_ports_%s_%s_format' % (test_str, tagname, subkey)
                    s = 'OK'
                    if subkey not in entry:
                        s = 'OK (skipped, not found)'
                    else:
                        tmp = entry[subkey].split('/')
                        if not port_pat.search(entry[subkey]) or \
                           int(tmp[0]) < 1 or int(tmp[0]) > 65535:
                            t = 'error'
                            s = "'%s' should be of form " % entry[subkey] + \
                                "'port/protocol' where port is an integer " + \
                                "(1-65535) and protocol is found in " + \
                                "/etc/protocols"
                    self._add_result(t, n, s)

                    # negotiable
                    subkey = 'negotiable'
                    if test_str == 'hook':
                        subkey = 'Negotiable'
                    t = 'info'
                    n = '%s_ports_%s_%s_format' % (test_str, tagname, subkey)
                    s = 'OK'
                    if subkey not in entry:
                        s = 'OK (skipped, not found)'
                    elif entry[subkey] not in [True, False]:
                        t = 'error'
                        s = "'%s: %s' should be either 'yes' or 'no'" % \
                            (subkey, entry[subkey])
                    self._add_result(t, n, s)

    def check_service_ports(self):
        '''Check snappy-systemd ports'''
        self._verify_service_ports(self.click_pkgname, self.systemd, 'hook')

    def check_snappy_service_ports(self):
        '''Check snappy package.yaml ports'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_service_ports(self.pkg_yaml['name'],
                                   self._create_dict(
                                       self.pkg_yaml['services']),
                                   'package_yaml')
