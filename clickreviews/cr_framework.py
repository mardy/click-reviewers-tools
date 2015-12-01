'''cr_framework.py: click framework'''
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

from clickreviews.cr_common import ClickReview, error, open_file_read
import glob
import os
import re


class ClickReviewFramework(ClickReview):
    '''This class represents click framework reviews'''
    def __init__(self, fn, overrides=None):
        ClickReview.__init__(self, fn, "framework", overrides=overrides)

        self.frameworks_file = dict()
        self.frameworks = dict()

        if self.manifest is not None:
            for app in self.manifest['hooks']:
                if 'framework' not in self.manifest['hooks'][app]:
                    # msg("Skipped missing framework hook for '%s'" % app)
                    continue
                if not isinstance(self.manifest['hooks'][app]['framework'], str):
                    error("manifest malformed: hooks/%s/framework is not str" %
                          app)
                (full_fn, data) = self._extract_framework(app)
                self.frameworks_file[app] = full_fn
                self.frameworks[app] = data

        self.framework_policy_dirs = ['apparmor', 'seccomp']
        self.framework_policy_subdirs = ['templates', 'policygroups']
        (self.framework_policy, self.framework_policy_unknown) = \
            self._extract_framework_policy()

    def _extract_framework(self, app):
        '''Get framework for app'''
        rel = self.manifest['hooks'][app]['framework']
        fn = os.path.join(self.unpack_dir, rel)
        if not os.path.exists(fn):
            error("Could not find '%s'" % rel)

        data = dict()
        fh = open_file_read(fn)
        for line in fh.readlines():
            tmp = line.split(':')
            if len(tmp) != 2:
                continue
            data[tmp[0].strip()] = tmp[1].strip()
        fh.close()

        return (fn, data)

    def _extract_framework_policy(self):
        '''Get framework policy files'''
        policy_dict = dict()
        unknown = []
        fpdir = os.path.join(self.unpack_dir, "meta", "framework-policy")
        for i in glob.glob("%s/*" % fpdir):
            rel_i = os.path.basename(i)
            if not os.path.isdir(i) or rel_i not in self.framework_policy_dirs:
                unknown.append(os.path.relpath(i, self.unpack_dir))
                continue

            policy_dict[rel_i] = dict()
            for j in glob.glob("%s/*" % i):
                rel_j = os.path.basename(j)
                if not os.path.isdir(j) or \
                   rel_j not in self.framework_policy_subdirs:
                    unknown.append(os.path.relpath(j, self.unpack_dir))
                    continue

                policy_dict[rel_i][rel_j] = dict()
                for k in glob.glob("%s/*" % j):
                    rel_k = os.path.basename(k)
                    if not os.path.isfile(k):
                        unknown.append(os.path.relpath(k, self.unpack_dir))
                        continue

                    fh = open_file_read(k)
                    policy_dict[rel_i][rel_j][rel_k] = fh.read()
                    fh.close()
        return (policy_dict, unknown)

    def _has_framework_in_metadir(self):
        '''Check if snap has meta/<name>.framework'''
        if not self.is_snap:
            return False

        return os.path.exists(os.path.join(self.unpack_dir, 'meta',
                                           '%s.framework' %
                                           self.pkg_yaml['name']))

    def check_framework_hook_obsolete(self):
        '''Check manifest doesn't specify 'framework' hook'''
        t = 'info'
        n = self._get_check_name("obsolete_declaration")
        s = "OK"
        if len(self.frameworks) > 0:
            t = 'error'
            s = "framework hook found for '%s'" % \
                ",".join(sorted(self.frameworks))
        self._add_result(t, n, s)

    def check_snappy_framework_file_obsolete(self):
        '''Check snap doesn't ship .framework file'''
        if not self.is_snap or self.pkg_yaml['type'] != 'framework':
            return
        t = 'info'
        n = self._get_check_name("obsolete_framework_file")
        s = "OK"
        if self._has_framework_in_metadir():
            t = 'warn'
            s = "found '%s.framework' (safe to remove)" % self.pkg_yaml['name']
        self._add_result(t, n, s)

    def check_snappy_framework_depends(self):
        '''Check framework doesn't depend on other frameworks'''
        if not self.is_snap or self.pkg_yaml['type'] != 'framework':
            return
        t = 'info'
        n = self._get_check_name("dependency")
        s = "OK"
        if "frameworks" in self.pkg_yaml:
            t = 'error'
            s = "'type: framework' may not specify 'frameworks'"
        self._add_result(t, n, s)

    def check_snappy_framework_policy(self):
        '''Check framework ships at least some policy'''
        if not self.is_snap or self.pkg_yaml['type'] != 'framework':
            return

        t = 'info'
        n = self._get_check_name("policies")
        s = "OK"
        found = False
        for i in self.framework_policy_dirs:
            if i not in self.framework_policy:
                continue
            for j in self.framework_policy_subdirs:
                if j not in self.framework_policy[i]:
                    continue
                if len(self.framework_policy[i][j].keys()) > 0:
                    found = True
        if not found:
            t = 'warn'
            s = "security policy not found"
        self._add_result(t, n, s)

        t = 'info'
        n = self._get_check_name("policy_unknown")
        s = "OK"
        if len(self.framework_policy_unknown) > 0:
            t = 'warn'
            s = "framework policy has unexpected entries: '%s'" % \
                ",".join(self.framework_policy_unknown)
        self._add_result(t, n, s)

    def check_snappy_framework_policy_metadata(self):
        '''Check framework policy has expected meta data'''
        if not self.is_snap or self.pkg_yaml['type'] != 'framework':
            return

        t = 'info'
        n = self._get_check_name("policy_metadata")
        s = "OK"
        msgs = []
        for term in ["# Description: ", "# Usage: "]:
            for i in self.framework_policy_dirs:
                if i not in self.framework_policy:
                    continue
                for j in self.framework_policy_subdirs:
                    if j not in self.framework_policy[i]:
                        continue
                    for k in self.framework_policy[i][j].keys():
                        found = False
                        for l in self.framework_policy[i][j][k].splitlines():
                            if l.startswith(term):
                                found = True
                        if not found:
                            msgs.append("'%s' in '%s/%s/%s'" % (term, i, j, k))
        if len(msgs) > 0:
            t = 'error'
            s = "Could not find meta data: %s" % ",".join(msgs)
        self._add_result(t, n, s)

    def check_snappy_framework_policy_matching(self):
        '''Check framework policy ships apparmor and seccomp for each'''
        if not self.is_snap or self.pkg_yaml['type'] != 'framework':
            return

        t = 'info'
        n = self._get_check_name("has_all_policy")
        s = "OK"
        if len(self.framework_policy.keys()) == 0:
            s = "OK (skipped missing policy)"
            self._add_result(t, n, s)
            return

        for i in self.framework_policy:
            for j in self.framework_policy[i]:
                for k in self.framework_policy[i][j]:
                    for other in self.framework_policy_dirs:
                        if t == i:
                            continue
                        t = 'info'
                        n = self._get_check_name(
                            "policy", extra="%s/%s/%s" % (i, j, k))
                        s = "OK"
                        if j not in self.framework_policy[other] or \
                           k not in self.framework_policy[other][j]:
                            t = 'error'
                            s = "Could not find matching '%s/%s/%s'" % (other,
                                                                        j, k)
                        self._add_result(t, n, s)

    def check_snappy_framework_policy_filenames(self):
        '''Check framework policy file names'''
        if not self.is_snap or self.pkg_yaml['type'] != 'framework':
            return

        for i in self.framework_policy:
            for j in self.framework_policy[i]:
                for k in self.framework_policy[i][j]:
                    f = "%s/%s/%s" % (i, j, k)
                    t = 'info'
                    n = self._get_check_name(
                        "policy_valid_name", extra=f)
                    s = "OK"
                    if not re.search(r'^[a-z0-9][a-z0-9+\.-]+$', k):
                        t = 'error'
                        s = "'%s' should match '^[a-z0-9][a-z0-9+\.-]+$'" % f
                    elif k.startswith(self.pkg_yaml['name']):
                        t = 'warn'
                        s = "'%s' should not begin with package name" % f
                    self._add_result(t, n, s)
