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

from clickreviews.cr_common import ClickReview, error
import copy
import re


class ClickReviewSystemd(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        # systemd isn't implemented as a hook any more so don't setup peerhooks
        ClickReview.__init__(self, fn, "snappy-systemd", overrides=overrides)

        self.systemd_files = dict()  # click-show-files and tests
        self.systemd = dict()

        if not self.is_snap1:
            return

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
                              'listen-stream',
                              'socket',
                              'socket-user',
                              'socket-group',
                              'ports'
                              ] + self.snappy_exe_security

        if self.is_snap1 and 'services' in self.pkg_yaml:
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
                self.systemd[app] = copy.deepcopy(service)
                del self.systemd[app]['name']

    def _verify_required(self, my_dict, test_str):
        for app in sorted(my_dict):
            for r in self.required_keys:
                found = False
                t = 'info'
                n = self._get_check_name(
                    '%s_required_key' % test_str, extra=r, app=app)
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

    def check_snappy_required(self):
        '''Check for package.yaml required fields'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        self._verify_required(self._create_dict(self.pkg_yaml['services']),
                              'package_yaml')

    def _verify_optional(self, my_dict, test_str):
        for app in sorted(my_dict):
            for o in self.optional_keys:
                if o in self.snappy_exe_security:
                    continue  # checked in cr_security.py
                found = False
                t = 'info'
                n = self._get_check_name(
                    '%s_optional_key' % test_str, extra=o, app=app)
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
                    elif o == 'socket':
                        if not isinstance(my_dict[app][o], bool):
                            t = 'error'
                            s = "'%s' is not boolean" % o
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

    def check_snappy_optional(self):
        '''Check snappy packate.yaml optional fields'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        self._verify_optional(self._create_dict(self.pkg_yaml['services']),
                              'package_yaml')

    def _verify_unknown(self, my_dict, test_str):
        for app in sorted(my_dict):
            unknown = []
            t = 'info'
            n = self._get_check_name('%s_unknown_key' % test_str, app=app)
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

    def check_snappy_unknown(self):
        '''Check snappy package.yaml unknown fields'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        self._verify_unknown(self._create_dict(self.pkg_yaml['services']),
                             'package_yaml')

    def _verify_service_description(self, my_dict, test_str):
        '''Check snappy systemd description'''
        for app in sorted(my_dict):
            t = 'info'
            n = self._get_check_name('%s_description_present' % test_str,
                                     app=app)
            s = 'OK'
            if 'description' not in my_dict[app]:
                s = 'required description field not specified'
                self._add_result('error', n, s)
                return
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('%s_description_empty' % test_str,
                                     app=app)
            s = 'OK'
            if len(my_dict[app]['description']) == 0:
                t = 'error'
                s = "description is empty"
            self._add_result(t, n, s)

    def check_snappy_service_description(self):
        '''Check snappy package.yaml description'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        self._verify_service_description(self._create_dict(
                                         self.pkg_yaml['services']),
                                         'package_yaml')

    def _verify_entry(self, my_dict, d, test_str):
        for app in sorted(my_dict):
            if d not in my_dict[app]:
                continue

            t = 'info'
            n = self._get_check_name('%s_empty' % test_str, extra=d, app=app)
            s = 'OK'
            if len(my_dict[app][d]) == 0:
                t = 'error'
                s = "%s entry is empty" % d
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('%s_absolute_path' % test_str,
                                     extra=d, app=app)
            s = 'OK'
            if my_dict[app][d].startswith('/'):
                t = 'error'
                s = "'%s' should not specify absolute path" % my_dict[app][d]
            self._add_result(t, n, s)

    def check_snappy_service_start(self):
        '''Check snappy package.yaml start'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        self._verify_entry(self._create_dict(self.pkg_yaml['services']),
                           'start', 'package_yaml')

    def check_snappy_service_stop(self):
        '''Check snappy package.yaml stop'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        self._verify_entry(self._create_dict(self.pkg_yaml['services']),
                           'stop', 'package_yaml')

    def check_snappy_service_poststop(self):
        '''Check snappy package.yaml poststop'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        self._verify_entry(self._create_dict(self.pkg_yaml['services']),
                           'poststop', 'package_yaml')

    def _verify_service_stop_timeout(self, my_dict, test_str):
        for app in sorted(my_dict):
            t = 'info'
            n = self._get_check_name('%s_stop_timeout' % test_str, app=app)
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

    def check_snappy_service_stop_timeout(self):
        '''Check snappy package.yaml stop-timeout'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        self._verify_service_stop_timeout(self._create_dict(
                                          self.pkg_yaml['services']),
                                          'package_yaml')

    def _verify_service_bus_name(self, pkgname, my_dict, test_str, is_fwk):
        for app in sorted(my_dict):
            if 'bus-name' not in my_dict[app]:
                continue

            t = 'info'
            n = self._get_check_name('%s_bus-name_framework' % test_str,
                                     app=app)
            s = 'OK'
            if not is_fwk:
                t = 'error'
                s = "Use of bus-name requires package be of 'type: framework'"
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('%s_bus-name_empty' % test_str, app=app)
            s = 'OK'
            if len(my_dict[app]['bus-name']) == 0:
                t = 'error'
                s = "'bus-name' is empty"
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('%s_bus-name_format' % test_str, app=app)
            link = None
            s = 'OK'
            if not re.search(r'^[A-Za-z0-9][A-Za-z0-9_-]*'
                             r'(\.[A-Za-z0-9][A-Za-z0-9_-]*)+$',
                             my_dict[app]['bus-name']):
                t = 'error'
                link = ('http://dbus.freedesktop.org/doc/'
                        'dbus-specification.html')
                s = ("'%s' is not of form '^[A-Za-z0-9][A-Za-z0-9_-]*"
                     "(\\.[A-Za-z0-9][A-Za-z0-9_-]*)+$'" %
                     (my_dict[app]['bus-name']))
            self._add_result(t, n, s, link)

            t = 'info'
            n = self._get_check_name('%s_bus-name_matches_name' % test_str,
                                     app=app)
            s = 'OK'
            suggested = [pkgname,
                         "%s.%s" % (pkgname, app)
                         ]
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

    def check_snappy_service_bus_name(self):
        '''Check snappy package.yaml bus-name'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        is_framework = False
        if 'type' in self.pkg_yaml and self.pkg_yaml['type'] == 'framework':
            is_framework = True

        self._verify_service_bus_name(self.pkg_yaml['name'],
                                      self._create_dict(
                                          self.pkg_yaml['services']),
                                      'package_yaml',
                                      is_framework)

    def _verify_service_ports(self, pkgname, my_dict, test_str):
        for app in sorted(my_dict):
            if 'ports' not in my_dict[app]:
                continue

            t = 'info'
            n = self._get_check_name('%s_ports_empty' % test_str, app=app)
            s = 'OK'
            if len(my_dict[app]['ports'].keys()) == 0:
                t = 'error'
                s = "'ports' must contain 'internal' and/or 'external'"
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('%s_ports_bad_key' % test_str, app=app)
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
                    n = self._get_check_name('%s_ports' % test_str, extra=key,
                                             app=app)
                    s = 'Could not find any %s ports' % key
                    self._add_result(t, n, s)
                    continue

                for tagname in my_dict[app]['ports'][key]:
                    entry = my_dict[app]['ports'][key][tagname]
                    if len(entry.keys()) < 1:
                        t = 'error'
                        n = self._get_check_name('%s_ports' % test_str,
                                                 extra=key, app=app)
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
                        n = self._get_check_name('%s_ports_invalid' % test_str,
                                                 extra=key, app=app)
                        s = "Must specify specify at least 'port' or " + \
                            "'negotiable'"
                        self._add_result(t, n, s)
                        continue

                    # port
                    subkey = 'port'
                    if test_str == 'hook':
                        subkey = 'Port'
                    t = 'info'
                    n = self._get_check_name('%s_ports_%s_format' %
                                             (test_str, tagname),
                                             extra=subkey)
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
                    n = self._get_check_name('%s_ports_%s_format' %
                                             (test_str, tagname),
                                             extra=subkey)
                    s = 'OK'
                    if subkey not in entry:
                        s = 'OK (skipped, not found)'
                    elif entry[subkey] not in [True, False]:
                        t = 'error'
                        s = "'%s: %s' should be either 'yes' or 'no'" % \
                            (subkey, entry[subkey])
                    self._add_result(t, n, s)

    def check_snappy_service_ports(self):
        '''Check snappy package.yaml ports'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return
        self._verify_service_ports(self.pkg_yaml['name'],
                                   self._create_dict(
                                       self.pkg_yaml['services']),
                                   'package_yaml')

    def _verify_service_listen_stream(self, pkgname, my_dict, test_str):
        for app in sorted(my_dict):
            if 'listen-stream' not in my_dict[app]:
                continue

            t = 'info'
            n = self._get_check_name('%s_listen-stream_empty' % test_str,
                                     app=app)
            s = 'OK'
            if len(my_dict[app]['listen-stream']) == 0:
                t = 'error'
                s = "'listen-stream' is empty"
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('%s_listen-stream_matches_name' %
                                     test_str, app=app)
            s = 'OK'
            sock = my_dict[app]['listen-stream']
            if sock.startswith('@'):
                if sock != '@%s' % pkgname and \
                        not sock.startswith('@%s_' % pkgname):
                    t = 'error'
                    s = ("abstract socket '%s' is neither '%s' nor starts "
                         "with '%s'" % (sock, '@%s' % pkgname,
                                        '@%s_' % pkgname))
            elif sock.startswith('/'):
                found = False
                for path in ["/tmp/",
                             "/var/lib/apps/%s/" % pkgname,
                             "/var/lib/apps/%s." % pkgname,
                             "/run/shm/snaps/%s/" % pkgname,
                             "/run/shm/snaps/%s." % pkgname]:
                    if sock.startswith(path):
                        found = True
                        break
                if not found:
                    t = 'error'
                    s = ("named socket '%s' should be in a writable"
                         "app-specific area or /tmp" % sock)
            else:
                t = 'error'
                s = ("'%s' does not specify an abstract socket (starts "
                     "with '@') or absolute filename" % (sock))
            self._add_result(t, n, s)

    def check_snappy_service_listen_stream(self):
        '''Check snappy package.yaml listen-stream'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return

        self._verify_service_listen_stream(self.pkg_yaml['name'],
                                           self._create_dict(
                                               self.pkg_yaml['services']),
                                           'package_yaml')

    def check_snappy_service_socket_user(self):
        '''Check snappy package.yaml socket-user'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return

        my_dict = self._create_dict(self.pkg_yaml['services'])
        for app in sorted(my_dict):
            if 'socket-user' not in my_dict[app]:
                continue

            t = 'error'
            n = self._get_check_name('package_yaml_socket-user', app=app)
            s = "'socket-user' should not be used until snappy supports " + \
                "per-app users"
            self._add_result(t, n, s, manual_review=True)

            t = 'info'
            n = self._get_check_name('package_yaml_socket-user_matches',
                                     app=app)
            s = "OK"
            if my_dict[app]['socket-user'] != self.pkg_yaml['name']:
                t = 'error'
                s = "'%s' != '%s'" % (my_dict[app]['socket-user'],
                                      self.pkg_yaml['name'])
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('package_yaml_socket-user_listen-stream',
                                     app=app)
            s = "OK"
            if 'listen-stream' not in my_dict[app]:
                t = 'error'
                s = "'socket-user' specified without 'listen-stream'"
            self._add_result(t, n, s)

    def check_snappy_service_socket_group(self):
        '''Check snappy package.yaml socket-group'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return

        my_dict = self._create_dict(self.pkg_yaml['services'])
        for app in sorted(my_dict):
            if 'socket-group' not in my_dict[app]:
                continue

            t = 'error'
            n = self._get_check_name('package_yaml_socket-group', app=app)
            s = "'socket-group' should not be used until snappy supports " + \
                "per-app groups"
            self._add_result(t, n, s, manual_review=True)

            t = 'info'
            n = self._get_check_name('package_yaml_socket-group_matches',
                                     app=app)
            s = "OK"
            if my_dict[app]['socket-group'] != self.pkg_yaml['name']:
                t = 'error'
                s = "'%s' != '%s'" % (my_dict[app]['socket-group'],
                                      self.pkg_yaml['name'])
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('package_yaml_socket-group_listen-stream',
                                     app=app)
            s = "OK"
            if 'listen-stream' not in my_dict[app]:
                t = 'error'
                s = "'socket-group' specified without 'listen-stream'"
            self._add_result(t, n, s)

    def check_snappy_service_socket(self):
        '''Check snappy package.yaml socket'''
        if not self.is_snap1 or 'services' not in self.pkg_yaml:
            return

        my_dict = self._create_dict(self.pkg_yaml['services'])
        for app in sorted(my_dict):
            if 'socket' not in my_dict[app]:
                continue

            t = 'info'
            n = self._get_check_name('package_yaml_socket_listen-stream',
                                     app=app)
            s = "OK"
            if 'listen-stream' not in my_dict[app]:
                t = 'error'
                s = "'socket' specified without 'listen-stream'"
            self._add_result(t, n, s)
