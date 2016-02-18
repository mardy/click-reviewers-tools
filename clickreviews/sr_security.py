'''sr_security.py: snap security checks'''
#
# Copyright (C) 2013-2016 Canonical Ltd.
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

from clickreviews.sr_common import (
    SnapReview,
)
from clickreviews.common import (
    error,
    open_file_read
)
import clickreviews.apparmor_policy as apparmor_policy
import os
import re


class SnapReviewSecurity(SnapReview):
    '''This class represents snap security reviews'''
    def __init__(self, fn, overrides=None):
        SnapReview.__init__(self, fn, "security-snap-v2", overrides=overrides)

        if not self.is_snap2:
            return

        # If local_copy is None, then this will check the server to see if
        # we are up to date. However, if we are working within the development
        # tree, use it unconditionally.
        local_copy = None
        branch_fn = os.path.join(os.path.dirname(__file__),
                                 '../data/apparmor-easyprof-ubuntu.json')
        if os.path.exists(branch_fn):
            local_copy = branch_fn
        p = apparmor_policy.ApparmorPolicy(local_copy)
        self.aa_policy = p.policy

        self.sec_skipped_types = ['oem',
                                  'os',
                                  'kernel']  # these don't need security items

        self.policies = self._extract_security_yaml()

        # TODO: may need updating for ubuntu-personal, etc
        self.policy_vendor = "ubuntu-core"
        self.policy_version = str(self._pkgfmt_version())

    def _extract_security_yaml(self):
        '''Extract security bits from snap.yaml in a way that can be easily
           used in these tests.
        '''
        sec = {}

        if 'uses' in self.snap_yaml:
            sec['uses'] = {}
            # TODO: need to adjust for native security skills
            for slot in self.snap_yaml['uses']:
                if 'type' not in self.snap_yaml['uses'][slot] or \
                        self.snap_yaml['uses'][slot]['type'] != \
                        'migration-skill':
                    continue
                for k in self.skill_types['migration-skill']:
                    if k in self.snap_yaml['uses'][slot]:
                        if not isinstance(self.snap_yaml['uses'][slot][k],
                                          type(self.skill_types['migration-skill'][k])):
                            error("Invalid yaml for uses/%s/%s" % (slot, k))  # pragma: nocover
                        if slot not in sec['uses']:
                            sec['uses'][slot] = {}
                        sec['uses'][slot][k] = self.snap_yaml['uses'][slot][k]

        if 'apps' in self.snap_yaml:
            sec['apps'] = {}
            for app in self.snap_yaml['apps']:
                if 'uses' not in self.snap_yaml['apps'][app]:
                    continue
                if app not in sec['apps']:
                    sec['apps'][app] = {}
                sec['apps'][app]['uses'] = self.snap_yaml['apps'][app]['uses']

        return sec

    def _extract_security_profile(self, app):
        '''Extract security profile'''
        rel_fn = self.manifest['hooks'][app]['apparmor-profile']

        fn = os.path.join(self.unpack_dir, rel_fn)
        if not os.path.exists(fn):
            error("Could not find '%s'" % rel_fn)

        fh = open_file_read(fn)
        contents = ""
        for line in fh.readlines():
            contents += line
        fh.close()

        # We could try to run this through apparmor_parser, but that is going
        # to be system dependent (eg, a profile may reference features on a
        # new parser and fail here on the local parser)

        return contents

    def check_security_policy_vendor(self):
        '''Check policy-vendor'''
        if not self.is_snap2:
            return

        t = 'info'
        n = self._get_check_name('policy-vendor')
        s = 'OK'
        if self.policy_vendor not in self.aa_policy:
            t = 'error'
            s = "unknown policy-vendor '%s'" % self.policy_vendor
        self._add_result(t, n, s)

    def check_security_policy_version(self):
        '''Check policy-version'''
        if not self.is_snap2 or self.policy_vendor not in self.aa_policy:
            return

        t = 'info'
        n = self._get_check_name('policy-version')
        s = 'OK'
        if self.policy_version not in self.aa_policy[self.policy_vendor]:
            t = 'error'
            s = "unknown policy-version '%s'" % self.policy_version
        self._add_result(t, n, s)

    def check_security_caps(self):
        '''Check security-caps'''
        if not self.is_snap2:
            return

        caps = self._get_policy_groups(version=self.policy_version,
                                       vendor=self.policy_vendor)

        frameworks = []
        if 'frameworks' in self.snap_yaml:
            frameworks = self.snap_yaml['frameworks']
        elif 'type' in self.snap_yaml and \
                self.snap_yaml['type'] == 'framework':
            # frameworks may reference their own caps
            frameworks.append(self.snap_yaml['name'])

        for slot in self.policies['uses']:
            if 'caps' not in self.policies['uses'][slot]:
                continue

            dupes = []
            for cap in self.policies['uses'][slot]['caps']:
                # TODO: this will go away when frameworks are gone
                framework_cap = False
                for f in frameworks:
                    if cap.startswith("%s_" % f):
                        framework_cap = True

                t = 'info'
                n = self._get_check_name('cap_exists', app=slot, extra=cap)
                s = "OK"
                if framework_cap:
                    s = "OK (matches '%s' framework)" % cap.split('_')[0]
                elif cap not in caps:
                    t = 'error'
                    s = "unsupported cap '%s'" % cap
                elif self.policies['uses'][slot]['caps'].count(cap) > 1 and \
                        cap not in dupes:
                    dupes.append(cap)
                    t = 'error'
                    s = "'%s' specified multiple times" % cap
                self._add_result(t, n, s)
                if t == 'error':
                    continue

                t = 'info'
                n = self._get_check_name('cap_safe', app=slot, extra=cap)
                s = "OK"
                m = False
                l = None
                sec_type = self._get_policy_group_type(self.policy_vendor,
                                                       self.policy_version,
                                                       cap)
                if cap == "debug":
                    t = 'error'
                    s = "'%s' not for production use" % cap
                    l = 'http://askubuntu.com/a/562123/94326'
                elif sec_type == "reserved":
                    t = 'error'
                    s = "%s cap '%s' for vetted applications only" % (sec_type,
                                                                      cap)
                    m = True
                elif sec_type != "common":
                    t = 'error'
                    s = "unknown type '%s' for cap '%s'" % (sec_type, cap)
                self._add_result(t, n, s, l, manual_review=m)

    def check_security_override(self):
        '''Check security-override'''
        if not self.is_snap2:
            return

        # These regexes are pretty strict, but lets try to guard against
        # any malfeasance
        allowed_fields = {'read-paths': re.compile(r'^[/@]'),
                          'write-paths': re.compile(r'^[/@]'),
                          'abstractions': re.compile(r'^[a-zA-Z0-9_]{2,64}$'),
                          'syscalls': re.compile(r'^[a-z0-9_]{2,64}$'),
                          }

        for slot in self.policies['uses']:
            key = 'security-override'
            if key not in self.policies['uses'][slot]:
                continue

            t = 'info'
            n = self._get_check_name(key, extra=slot)
            s = "OK"
            if len(self.policies['uses'][slot][key].keys()) == 0:
                t = 'error'
                s = "nothing specified in '%s' for '%s'" % (key, slot)
            else:
                for f in self.policies['uses'][slot][key].keys():
                    if f not in allowed_fields:
                        t = 'error'
                        s = "unknown field '%s' in " % f + \
                            "'%s' for '%s'" % (key, slot)
                    elif not isinstance(self.policies['uses'][slot][key][f],
                                        list):
                        t = 'error'
                        s = "invalid %s entry: %s (not a list)" % \
                            (f, self.policies['uses'][slot][key][f])
                    else:
                        errors = []
                        for v in self.policies['uses'][slot][key][f]:
                            if not allowed_fields[f].search(v):
                                errors.append(v)
                        if len(errors) > 0:
                            t = 'error'
                            s = "malformed '%s' in '%s'" % (",".join(errors),
                                                            f)
            self._add_result(t, n, s)

    def check_security_policy(self):
        '''TODO: Check security-policy'''
        if not self.is_snap2:
            return

    def check_security_template(self):
        '''Check security-template'''
        if not self.is_snap2:
            return

        templates = self._get_templates(version=self.policy_version,
                                        vendor=self.policy_vendor)

        frameworks = []
        if 'frameworks' in self.snap_yaml:
            frameworks = self.snap_yaml['frameworks']
        elif 'type' in self.snap_yaml and \
                self.snap_yaml['type'] == 'framework':
            # frameworks may reference their own caps
            frameworks.append(self.snap_yaml['name'])

        for slot in self.policies['uses']:
            if 'security-template' not in self.policies['uses'][slot]:
                continue

            template = self.policies['uses'][slot]['security-template']

            # TODO: this will go away when frameworks are gone
            framework_template = False
            for f in frameworks:
                if template.startswith("%s_" % f):
                    framework_template = True

            t = 'info'
            n = self._get_check_name('template_exists', app=slot, extra=template)
            s = "OK"
            if framework_template:
                s = "OK (matches '%s' framework)" % template.split('_')[0]
            elif template not in templates:
                t = 'error'
                s = "unsupported template '%s'" % template
            self._add_result(t, n, s)
            if t == 'error':
                continue

            t = 'info'
            n = self._get_check_name('template_safe', app=slot, extra=template)
            s = "OK"
            m = False
            sec_type = self._get_template_type(self.policy_vendor,
                                               self.policy_version,
                                               template)
            if sec_type == "reserved":
                t = 'error'
                s = "%s template '%s' for vetted applications only" % (
                    sec_type, template)
                m = True
            elif sec_type != "common":
                t = 'error'
                s = "unknown type '%s' for template '%s'" % (sec_type, template)
            self._add_result(t, n, s, manual_review=m)

    def check_security_combinations(self):
        '''Verify security yaml uses valid combinations'''
        if not self.is_snap2:
            return

        for slot in self.policies['uses']:
            t = 'info'
            n = self._get_check_name('yaml_combinations', extra=slot)
            s = "OK"
            if "security-policy" in self.policies['uses'][slot]:
                for i in ['security-override', 'security-template', 'caps']:
                    if i in self.policies['uses'][slot]:
                        t = 'error'
                        s = "found '%s' with 'security-policy'" % i
                        break
            self._add_result(t, n, s)

        # Make sure that a particular app doesn't list conflicting combinations
        # (ie, security-policy with anything else)
        for app in self.policies['apps']:
            if 'uses' not in self.policies['apps'][app]:
                continue

            t = 'info'
            n = self._get_check_name('yaml_combinations_apps', app=app)
            s = "OK"
            has_decl = []
            for slot_ref in self.policies['apps'][app]['uses']:
                if slot_ref not in self.policies['uses']:
                    continue

                for i in ['security-override', 'security-template', 'caps',
                          'security-policy']:
                    if i in self.policies['uses'][slot_ref] and \
                            i not in has_decl:
                        has_decl.append(i)

            if "security-policy" in has_decl:
                for i in ['security-override', 'security-template', 'caps']:
                    if i in has_decl:
                        t = 'error'
                        s = "'%s' uses 'security-policy' with '%s'" % (app, i)
                        break
            self._add_result(t, n, s)

    def check_uses_redflag(self):
        '''Check uses redflag fields'''
        if not self.is_snap2:
            return

        for slot in self.policies['uses']:
            t = 'info'
            n = self._get_check_name('redflag_fields', extra=slot)
            s = 'OK'
            m = False

            attrib = None
            if 'security-override' in self.policies['uses'][slot]:
                attrib = 'security-override'
            elif 'security-policy' in self.policies['uses'][slot]:
                attrib = 'security-policy'
            if attrib:
                t = 'error'
                s = "found redflagged attribute: %s" % attrib
                m = True
            self._add_result(t, n, s, m)

    def check_apps_uses_mapped_migration(self):
        '''Check apps uses mapped migration skill'''
        if not self.is_snap2:
            return

        for app in self.policies['apps']:
            for slot_ref in self.policies['apps'][app]['uses']:
                t = 'info'
                n = self._get_check_name("app_uses", app=app, extra=slot_ref)
                s = 'OK'
                if not isinstance(slot_ref, str):
                    continue  # checked via sr_lint.py
                elif slot_ref not in self.policies['uses']:
                    t = 'error'
                    s = "slot reference '%s' not in toplevel 'uses'" % slot_ref
                self._add_result(t, n, s)

    def check_apparmor_profile_name_length(self):
        '''Check AppArmor profile name length'''
        if not self.is_snap2:
            return

        # There are quite a few kernel interfaces that can cause problems with
        # long profile names. These are outlined in
        # https://launchpad.net/bugs/1499544. The big issue is that the audit
        # message must fit within PAGE_SIZE (at least 4096 on supported archs),
        # so long names could push the audit message to be too big, which would
        # result in a denial for that rule (but, only if the rule would've
        # allowed it). Giving a hard-error on maxlen since we know that this
        # will be a problem. The advisory length is what it is since we know
        # that compound labels are sometimes logged and so a snappy system
        # running an app in a snappy container or a QA testbed running apps
        # under LXC
        maxlen = 230  # 245 minus a bit for child profiles
        advlen = 100

        for app in self.policies['apps']:
            t = 'info'
            n = self._get_check_name('profile_name_length', app=app)
            s = "OK"
            profile = "%s_%s_%s" % (self.snap_yaml['name'],
                                    app,
                                    self.snap_yaml['version'])
            if len(profile) > maxlen:
                t = 'error'
                s = ("'%s' too long (exceeds %d characters). Please shorten "
                     "'%s', '%s' and/or '%s'" % (profile, maxlen,
                                                 self.snap_yaml['name'],
                                                 app,
                                                 self.snap_yaml['version']))
            elif len(profile) > advlen:
                t = 'warn'
                s = ("'%s' is long (exceeds %d characters) and thus could be "
                     "problematic in certain environments. Please consider "
                     "shortening '%s', '%s' and/or '%s'" % (profile, advlen,
                                                            self.snap_yaml['name'],
                                                            app,
                                                            self.snap_yaml['version']))
            self._add_result(t, n, s)
