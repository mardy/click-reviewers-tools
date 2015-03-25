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

from clickreviews.cr_common import ClickReview, error, open_file_read, msg
import yaml
import os


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
        # - TODO: caps
        self.required_keys = ['start', 'description']
        self.optional_keys = ['stop', 'poststop', 'stop-timeout']

        self.systemd_files = dict()  # click-show-files and tests
        self.systemd = dict()
        for app in self.manifest['hooks']:
            if 'snappy-systemd' not in self.manifest['hooks'][app]:
                # msg("Skipped missing systemd hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['snappy-systemd'],
               str):
                error("manifest malformed: hooks/%s/snappy-systemd is not str"
                      % app)
            (full_fn, yd) = self._extract_systemd(app)
            self.systemd_files[app] = full_fn
            self.systemd[app] = yd

    def _extract_systemd(self, app):
        '''Get systemd yaml'''
        u = self.manifest['hooks'][app]['snappy-systemd']
        fn = os.path.join(self.unpack_dir, u)

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
                found = False
                t = 'info'
                n = '%s_optional_key_%s_%s' % (test_str, o, f)
                s = "OK"
                if o in my_dict[app]:
                    if o == 'stop-timeout' and \
                       not isinstance(my_dict[app][o], int):
                        t = 'error'
                        s = "'%s' is not an integer" % o
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
            elif not isinstance(my_dict[app]['stop-timeout'], int):
                t = 'error'
                s = 'stop-timeout is not an integer'
            elif my_dict[app]['stop-timeout'] < 0 or \
                    my_dict[app]['stop-timeout'] > 60:
                t = 'error'
                s = "stop-timeout '%d' out of range (0-60)" % \
                    my_dict[app]['stop-timeout']

            self._add_result(t, n, s)

    def check_service_stop_timeout(self):
        '''Check snappy-systemd'''
        self._verify_service_stop_timeout(self.systemd, 'hook')

    def check_snappy_service_stop_timeout(self):
        '''Check snappy package.yaml top-timeout'''
        if not self.is_snap or 'services' not in self.pkg_yaml:
            return
        self._verify_service_stop_timeout(self._create_dict(
                                          self.pkg_yaml['services']),
                                          'package_yaml')
