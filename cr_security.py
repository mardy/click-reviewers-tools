'''cr_security.py: click security checks'''
#
# Copyright (C) 2013 Canonical Ltd.
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

from cr_common import ClickReview, error
import cr_common
import glob
import json
import os

easyprof_dir = "/usr/share/apparmor/easyprof"
if not os.path.isdir(easyprof_dir):
    error("Error importing easyprof. Please install apparmor-easyprof")
if not os.path.isdir(os.path.join(easyprof_dir, "templates/ubuntu")):
    error("Error importing easyprof. Please install apparmor-easyprof-ubuntu")

import apparmor.easyprof


class ClickReviewSecurity(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "security")

        version_dirs = sorted(glob.glob("%s/templates/ubuntu/*" %
                                        easyprof_dir))
        self.supported_policy_versions = []
        for d in version_dirs:
            if not os.path.isdir(d):
                continue
            try:
                self.supported_policy_versions.append(float(
                                                      os.path.basename(d)))
            except TypeError:
                continue
        self.supported_policy_versions = sorted(self.supported_policy_versions)

        self.all_fields = ['abstractions',
                           'author',
                           'binary',
                           'comment',
                           'copyright',
                           'name',
                           'policy_groups',
                           'policy_vendor',
                           'policy_version',
                           'read_path',
                           'template',
                           'template_variables',
                           'write_path']
        self.ignored_fields = ['author',
                               'comment',
                               'copyright',
                               'name']
        self.required_fields = ['policy_groups',
                                'policy_version']
        self.redflag_fields = ['abstractions',
                               'binary',
                               'policy_vendor',
                               'read_path',
                               'template',
                               'template_variables',
                               'write_path']

        self.security_manifests = dict()
        for app in self.manifest['hooks']:
            if 'apparmor' not in self.manifest['hooks'][app]:
                error("could not find apparmor hook for '%s'" % app)
            if not isinstance(self.manifest['hooks'][app]['apparmor'], str):
                error("manifest malformed: hooks/%s/apparmor is not str" % app)
            d = self.manifest['hooks'][app]['apparmor']
            f = os.path.join(self.unpack_dir, d)
            rel_fn = os.path.relpath(f, self.unpack_dir)
            self.security_manifests[rel_fn] = self._get_security_manifest(f)

    def _get_security_manifest(self, fn):
        '''Get security manifest and verify it has the expected structure'''
        rel_fn = os.path.relpath(fn, self.unpack_dir)
        m = json.load(cr_common.open_file_read(fn))
        mp = json.dumps(m, sort_keys=True, indent=2, separators=(',', ': '))
        if not isinstance(m, dict):
            error("'%s' malformed:\n%s" % (rel_fn, mp))
        for k in sorted(m):
            if k not in self.all_fields:
                error("'%s' malformed: unsupported field '%s':\n%s" % (rel_fn,
                                                                       k, mp))
            if k in ['abstractions', 'policy_groups', 'read_path',
                     'write_path']:
                if not isinstance(m[k], list):
                    error("'%s' malformed: '%s' is not list:\n%s" % (rel_fn,
                                                                     k, mp))
            elif k == 'template_variables':
                if not isinstance(m[k], dict):
                    error("'%s' malformed: '%s' is not dict:\n%s" % (rel_fn,
                                                                     k, mp))
            elif k == "policy_version":
                if not isinstance(m[k], float):
                    error("'%s' malformed: '%s' is not float:\n%s" % (rel_fn,
                                                                      k, mp))
            else:
                if not isinstance(m[k], str):
                    error("'%s' malformed: '%s' is not str:\n%s" % (rel_fn,
                                                                    k, mp))
        return m

    def check_policy_vendor(self):
        '''Check policy_vendor'''
        for f in sorted(self.security_manifests):
            m = self.security_manifests[f]
            t = 'info'
            n = 'policy_vendor (%s)' % f
            s = "OK"
            if 'policy_vendor' in m and m['policy_vendor'] != "ubuntu":
                t = 'error'
                s = "policy_vendor '%s' not found" % m['policy_vendor']
            self._add_result(t, n, s)

    def check_policy_version(self):
        '''Check policy version'''
        for f in sorted(self.security_manifests):
            m = self.security_manifests[f]

            n = 'policy_version_exists (%s)' % f
            if 'policy_version' not in m:
                self._add_result('error', n,
                                 'could not find policy_version in manifest')
                continue

            t = 'info'
            s = "OK"
            vendor = "ubuntu"
            if 'policy_vendor' in m:
                vendor = m['policy_vendor']
            version = str(m['policy_version'])
            cmd_args = ['--list-templates', '--policy-vendor=%s' % vendor,
                        '--policy-version=%s' % version]
            (options, args) = apparmor.easyprof.parse_args(cmd_args)
            try:
                apparmor.easyprof.AppArmorEasyProfile(None, options)
            except Exception:
                t = 'error'
                s = 'could not find policy for %s/%s' % (vendor, version)
            self._add_result(t, n, s)

            highest = sorted(self.supported_policy_versions)[-1]
            t = 'info'
            n = 'policy_version_is_%s (%s)' % (str(highest), f)
            s = "OK"
            if float(m['policy_version']) != highest:
                t = 'warn'
                s = '%s != %s' % (str(m['policy_version']), str(highest))
            self._add_result(t, n, s)

    def check_template(self):
        '''Check template'''
        for f in sorted(self.security_manifests):
            m = self.security_manifests[f]

            t = 'info'
            n = 'template_exists (%s)' % f
            if 'template' not in m:
                # If template not specified, we just use the default
                self._add_result(t, n, 'OK (none specified)')
                continue
            elif m['template'] == "unconfined":
                # If template is specified as unconfined, manual review
                self._add_result('error', n,
                                 '(MANUAL REVIEW) unconfined not allowed')
                continue
            elif 'policy_version' not in m:
                self._add_result('error', n,
                                 'could not find policy_version in manifest')
                continue

            s = "OK"
            vendor = "ubuntu"
            if 'policy_vendor' in m:
                vendor = m['policy_vendor']
            version = str(m['policy_version'])
            cmd_args = ['--list-templates', '--policy-vendor=%s' % vendor,
                        '--policy-version=%s' % version]
            (options, args) = apparmor.easyprof.parse_args(cmd_args)
            templates = []
            try:
                easyp = apparmor.easyprof.AppArmorEasyProfile(None, options)
                templates = easyp.get_templates()
            except Exception:
                t = 'error'
                s = 'could not find policy_version=%s' % version
                self._add_result(t, n, s)
                continue
            if len(templates) < 1:
                t = 'error'
                s = 'could not find templates'
                self._add_result(t, n, s)
                continue

            # If we got here, we can see if a valid template was specified
            found = False
            for i in templates:
                if os.path.basename(i) == m['template']:
                    found = True
                    break
            if not found:
                t = 'error'
                s = "specified unsupported template '%s'" % m['template']

            self._add_result(t, n, s)

    def check_ignored(self):
        '''Check ignored fields'''
        for f in sorted(self.security_manifests):
            m = self.security_manifests[f]

            t = 'info'
            n = 'ignored_fields (%s)' % f
            s = "OK"
            found = []
            for i in self.ignored_fields:
                if i in m:
                    found.append(i)

            if len(found) > 0:
                t = 'warn'
                s = "found ignored fields: %s" % ", ".join(found)
            self._add_result(t, n, s)

    def check_redflag(self):
        '''Check redflag fields'''
        for f in sorted(self.security_manifests):
            m = self.security_manifests[f]

            t = 'info'
            n = 'redflag_fields (%s)' % f
            s = "OK"
            found = []
            for i in self.redflag_fields:
                if i in m:
                    found.append(i)

            if len(found) > 0:
                t = 'error'
                s = "(MANUAL REVIEW) found redflagged fields: %s" % \
                    ", ".join(found)
            self._add_result(t, n, s)

    def check_required(self):
        '''Check required fields'''
        for f in sorted(self.security_manifests):
            m = self.security_manifests[f]

            t = 'info'
            n = 'ignored_fields (%s)' % f
            s = "OK"
            not_found = []
            for i in self.required_fields:
                if i not in m:
                    not_found.append(i)

            if len(not_found) > 0:
                t = 'error'
                s = "missing required fields: %s" % ", ".join(not_found)
            self._add_result(t, n, s)
