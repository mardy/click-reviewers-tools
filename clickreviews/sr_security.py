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
    cmd,
    create_tempdir,
    error,
    open_file_read,
    ReviewException,
    AA_PROFILE_NAME_MAXLEN,
    AA_PROFILE_NAME_ADVLEN,
    MKSQUASHFS_OPTS,
    VALID_SYSCALL,
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
        self.raw_profiles = self._extract_raw_profiles()

        # TODO: may need updating for ubuntu-personal, etc
        self.policy_vendor = "ubuntu-core"
        self.policy_version = str(self._pkgfmt_version())

    def _extract_security_yaml(self):
        '''Extract security bits from snap.yaml in a way that can be easily
           used in these tests.
        '''
        sec = {}

        if 'plugs' in self.snap_yaml:
            sec['plugs'] = {}
            # TODO: need to adjust for native security interfaces
            for plug in self.snap_yaml['plugs']:
                if 'interface' not in self.snap_yaml['plugs'][plug] or \
                        self.snap_yaml['plugs'][plug]['interface'] != \
                        'old-security':
                    continue
                for k in self.interfaces['old-security']:
                    if k in self.snap_yaml['plugs'][plug]:
                        # This check means we don't have to verify in the
                        # individual tests
                        if not isinstance(self.snap_yaml['plugs'][plug][k],
                                          type(self.interfaces['old-security'][k])):
                            error("Invalid yaml for plugs/%s/%s" % (plug, k))  # pragma: nocover
                        if plug not in sec['plugs']:
                            sec['plugs'][plug] = {}
                        sec['plugs'][plug][k] = self.snap_yaml['plugs'][plug][k]

        if 'apps' in self.snap_yaml:
            sec['apps'] = {}
            for app in self.snap_yaml['apps']:
                if 'plugs' not in self.snap_yaml['apps'][app]:
                    continue
                # This check means we don't have to verify in the individual
                # tests
                elif not isinstance(self.snap_yaml['apps'][app]['plugs'], list):
                    error("Invalid yaml for %s/plugs" % app)  # pragma: nocover
                if app not in sec['apps']:
                    sec['apps'][app] = {}
                sec['apps'][app]['plugs'] = self.snap_yaml['apps'][app]['plugs']

        return sec

    def _extract_security_profile(self, plug, key):
        '''Extract security profile'''
        rel_fn = self.policies['plugs'][plug]['security-policy'][key]

        fn = os.path.join(self.unpack_dir, rel_fn)
        if not os.path.exists(fn):
            error("Could not find '%s'" % rel_fn)  # pragma: nocover

        fh = open_file_read(fn)
        contents = ""
        for line in fh.readlines():
            contents += line
        fh.close()

        return contents

    def _extract_raw_profiles(self):
        '''Get 'security-policy' policies'''
        raw_profiles = {}

        if 'plugs' not in self.policies:
            return raw_profiles

        for plug in self.policies['plugs']:
            if 'security-policy' not in self.policies['plugs'][plug]:
                continue

            if plug not in raw_profiles:
                raw_profiles[plug] = {}

            for k in ['apparmor', 'seccomp']:
                if k in self.policies['plugs'][plug]['security-policy']:
                    raw_profiles[plug][k] = \
                        self._extract_security_profile(plug, k)

        return raw_profiles

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
        if not self.is_snap2 or 'plugs' not in self.policies:
            return

        caps = self._get_policy_groups(version=self.policy_version,
                                       vendor=self.policy_vendor)

        for plug in self.policies['plugs']:
            if 'caps' not in self.policies['plugs'][plug]:
                continue

            dupes = []
            for cap in self.policies['plugs'][plug]['caps']:
                t = 'info'
                n = self._get_check_name('cap_exists', app=plug, extra=cap)
                s = "OK"
                if cap not in caps:
                    t = 'error'
                    s = "unsupported cap '%s'" % cap
                elif self.policies['plugs'][plug]['caps'].count(cap) > 1 and \
                        cap not in dupes:
                    dupes.append(cap)
                    t = 'error'
                    s = "'%s' specified multiple times" % cap
                self._add_result(t, n, s)
                if t == 'error':
                    continue

                t = 'info'
                n = self._get_check_name('cap_safe', app=plug, extra=cap)
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
        if not self.is_snap2 or 'plugs' not in self.policies:
            return

        # These regexes are pretty strict, but lets try to guard against
        # any malfeasance
        allowed_fields = {'read-paths': re.compile(r'^[/@]'),
                          'write-paths': re.compile(r'^[/@]'),
                          'abstractions': re.compile(r'^[a-zA-Z0-9_]{2,64}$'),
                          'syscalls': re.compile(VALID_SYSCALL),
                          }

        for plug in self.policies['plugs']:
            key = 'security-override'
            if key not in self.policies['plugs'][plug]:
                continue

            t = 'info'
            n = self._get_check_name(key, extra=plug)
            s = "OK"
            if len(self.policies['plugs'][plug][key].keys()) == 0:
                t = 'error'
                s = "nothing specified in '%s' for '%s'" % (key, plug)
            else:
                for f in self.policies['plugs'][plug][key].keys():
                    if f not in allowed_fields:
                        t = 'error'
                        s = "unknown field '%s' in " % f + \
                            "'%s' for '%s'" % (key, plug)
                    elif not isinstance(self.policies['plugs'][plug][key][f],
                                        list):
                        t = 'error'
                        s = "invalid %s entry: %s (not a list)" % \
                            (f, self.policies['plugs'][plug][key][f])
                    else:
                        errors = []
                        for v in self.policies['plugs'][plug][key][f]:
                            if not allowed_fields[f].search(v):
                                errors.append(v)
                        if len(errors) > 0:
                            t = 'error'
                            s = "malformed '%s' in '%s'" % (",".join(errors),
                                                            f)
            self._add_result(t, n, s)

    def check_security_policy(self):
        '''Check security-policy'''
        if not self.is_snap2 or 'plugs' not in self.policies:
            return

        allowed_fields = ['apparmor', 'seccomp']
        aa_searches = ['###VAR###',
                       '###PROFILEATTACH###',
                       '@{INSTALL_DIR}',
                       '@{APP_PKGNAME}',
                       '@{APP_VERSION}',
                       ]
        sc_skip_pat = re.compile(r'^(\s*#|\s*$)')
        sc_valid_pat = re.compile(VALID_SYSCALL)

        for plug in self.policies['plugs']:
            key = 'security-policy'
            if key not in self.policies['plugs'][plug]:
                continue

            t = 'info'
            n = self._get_check_name(key, extra=plug)
            s = "OK"
            for f in self.policies['plugs'][plug][key].keys():
                if f not in allowed_fields:
                    t = 'error'
                    s = "unknown field '%s' in " % f + \
                        "'%s' for '%s'" % (key, plug)
                elif not isinstance(self.policies['plugs'][plug][key][f],
                                    str):
                    t = 'error'
                    s = "invalid %s entry: %s (not a str)" % \
                        (f, self.policies['plugs'][plug][key][f])
            self._add_result(t, n, s)

        for plug in self.raw_profiles:
            for f in allowed_fields:
                t = 'info'
                n = self._get_check_name('%s_%s' % (key, f), extra=plug)
                s = "OK"
                if f not in self.raw_profiles[plug]:
                    t = 'error'
                    s = "required field '%s' not present" % f
                self._add_result(t, n, s)

                if f == 'apparmor':
                    if t == 'error':
                        continue

                    p = self.raw_profiles[plug]['apparmor']
                    t = 'info'
                    n = self._get_check_name('%s_%s_var' % (key, f),
                                             extra=plug)
                    s = "OK"
                    for v in aa_searches:
                        if v not in p:
                            if v.startswith('@') and \
                                    ("# Unrestricted AppArmor policy" in p or
                                     "# This profile offers no protection" in
                                     p):
                                s = "SKIPPED for '%s' (boilerplate)" % v
                            else:
                                t = 'warn'
                                s = "could not find '%s' in profile" % v
                            break
                    self._add_result(t, n, s)
                elif f == 'seccomp':
                    if t == 'error':
                        continue

                    invalid = []
                    for line in self.raw_profiles[plug]['seccomp'].splitlines():
                        if line.startswith('deny '):
                            line = line.replace('deny ', '')
                        if sc_skip_pat.search(line):
                            continue
                        if not sc_valid_pat.search(line):
                            invalid.append(line)

                    t = 'info'
                    n = self._get_check_name('%s_%s_valid' % (key, f),
                                             extra=plug)
                    s = "OK"
                    if len(invalid) > 0:
                        t = 'error'
                        s = "invalid syscalls: %s" % ",".join(invalid)
                    self._add_result(t, n, s)

    def check_security_template(self):
        '''Check security-template'''
        if not self.is_snap2 or 'plugs' not in self.policies:
            return

        templates = self._get_templates(version=self.policy_version,
                                        vendor=self.policy_vendor)

        for plug in self.policies['plugs']:
            if 'security-template' not in self.policies['plugs'][plug]:
                continue

            template = self.policies['plugs'][plug]['security-template']

            t = 'info'
            n = self._get_check_name('template_exists', app=plug,
                                     extra=template)
            s = "OK"
            if template not in templates:
                t = 'error'
                s = "unsupported template '%s'" % template
            self._add_result(t, n, s)
            if t == 'error':
                continue

            t = 'info'
            n = self._get_check_name('template_safe', app=plug, extra=template)
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
                s = "unknown type '%s' for template '%s'" % (sec_type,
                                                             template)
            self._add_result(t, n, s, manual_review=m)

    def check_security_combinations(self):
        '''Verify security yaml plugs valid combinations'''
        if not self.is_snap2 or 'plugs' not in self.policies:
            return

        for plug in self.policies['plugs']:
            t = 'info'
            n = self._get_check_name('yaml_combinations', extra=plug)
            s = "OK"
            if "security-policy" in self.policies['plugs'][plug]:
                for i in ['security-override', 'security-template', 'caps']:
                    if i in self.policies['plugs'][plug]:
                        tmp = list(self.policies['plugs'][plug].keys())
                        tmp.remove("security-policy")
                        t = 'error'
                        s = "found '%s' with 'security-policy'" % \
                            ",".join(sorted(tmp))
                        break
            self._add_result(t, n, s)

        # Make sure that a particular app doesn't list conflicting combinations
        # (ie, security-policy with anything else)
        if 'apps' not in self.policies:
            return
        for app in self.policies['apps']:
            t = 'info'
            n = self._get_check_name('yaml_combinations_apps', app=app)
            s = "OK"
            has_decl = []
            for plug_ref in self.policies['apps'][app]['plugs']:
                if plug_ref not in self.policies['plugs']:
                    continue

                for i in ['security-override', 'security-template', 'caps',
                          'security-policy']:
                    if i in self.policies['plugs'][plug_ref] and \
                            i not in has_decl:
                        has_decl.append(i)

            if "security-policy" in has_decl:
                for i in ['security-override', 'security-template', 'caps']:
                    if i in has_decl:
                        has_decl.remove("security-policy")
                        t = 'error'
                        s = "'%s' plugs 'security-policy' with '%s'" % (
                            app, ",".join(sorted(has_decl)))
                        break
            self._add_result(t, n, s)

    def check_plugs_redflag(self):
        '''Check plugs redflag fields'''
        if not self.is_snap2 or 'plugs' not in self.policies:
            return

        for plug in self.policies['plugs']:
            t = 'info'
            n = self._get_check_name('redflag_fields', extra=plug)
            s = 'OK'
            m = False

            attrib = None
            if 'security-override' in self.policies['plugs'][plug]:
                attrib = 'security-override'
            elif 'security-policy' in self.policies['plugs'][plug]:
                attrib = 'security-policy'
            if attrib:
                t = 'error'
                s = "found redflagged attribute: %s" % attrib
                m = True
            self._add_result(t, n, s, manual_review=m)

    def check_apps_plugs_mapped_oldsecurity(self):
        '''Check apps plugs mapped old-security interface'''
        if not self.is_snap2 or 'apps' not in self.policies:
            return

        for app in self.policies['apps']:
            for plug_ref in self.policies['apps'][app]['plugs']:
                t = 'info'
                n = self._get_check_name("app_plugs", app=app, extra=plug_ref)
                s = 'OK'
                if not isinstance(plug_ref, str):
                    continue  # checked via sr_lint.py
                elif plug_ref not in self.policies['plugs']:
                    t = 'error'
                    s = "plug reference '%s' not in toplevel 'plugs'" % plug_ref
                self._add_result(t, n, s)

    def check_apparmor_profile_name_length(self):
        '''Check AppArmor profile name length'''
        if not self.is_snap2 or 'apps' not in self.snap_yaml:
            return

        maxlen = AA_PROFILE_NAME_MAXLEN
        advlen = AA_PROFILE_NAME_ADVLEN

        for app in self.snap_yaml['apps']:
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

    def check_squashfs_resquash(self):
        '''Check resquash of squashfs'''
        if not self.is_snap2:
            return

        fn = os.path.abspath(self.pkg_filename)

        # Verify squashfs supports the -fstime option, if not, warn (which
        # blocks in store)
        (rc, out) = cmd(['unsquashfs', '-fstime', fn])
        if rc != 0:
            t = 'warn'
            n = self._get_check_name('squashfs_supports_fstime')
            s = 'could not determine fstime of squashfs'
            self._add_result(t, n, s)
            return
        fstime = out.strip()

        # For now, skip the checks on if have symlinks due to LP: #1555305
        (rc, out) = cmd(['unsquashfs', '-lls', fn])
        if rc != 0:
            t = 'error'
            n = self._get_check_name('squashfs_lls')
            s = 'could not list contents of squashfs'
            self._add_result(t, n, s)
            return
        elif 'lrwxrwxrwx' in out:
            t = 'info'
            n = self._get_check_name('squashfs_resquash_1555305')
            s = 'cannot reproduce squashfs'
            l = 'https://launchpad.net/bugs/1555305'
            self._add_result(t, n, s, link=l)
            return
        # end LP: #1555305 workaround

        tmpdir = create_tempdir()  # this is autocleaned
        tmp_unpack = os.path.join(tmpdir, 'squashfs-root')
        tmp_repack = os.path.join(tmpdir, 'repack.snap')

        curdir = os.getcwd()
        os.chdir(tmpdir)
        # ensure we don't alter the permissions from the unsquashfs
        old_umask = os.umask(000)

        try:
            (rc, out) = cmd(['unsquashfs', '-d', tmp_unpack, fn])
            if rc != 0:
                raise ReviewException("could not unsquash '%s': %s" %
                                      (os.path.basename(fn), out))
            (rc, out) = cmd(['mksquashfs', tmp_unpack, tmp_repack,
                             '-fstime', fstime] + MKSQUASHFS_OPTS)
            if rc != 0:
                raise ReviewException("could not mksquashfs '%s': %s" %
                                      (os.path.relpath(tmp_unpack, tmpdir),
                                       out))
        except ReviewException as e:
            t = 'error'
            n = self._get_check_name('squashfs_resquash')
            self._add_result(t, n, str(e))
            return
        finally:
            os.umask(old_umask)
            os.chdir(curdir)

        # Now calculate the hashes
        t = 'info'
        n = self._get_check_name('squashfs_repack_checksum')
        s = "OK"

        (rc, out) = cmd(['sha512sum', fn])
        if rc != 0:
            t = 'error'
            s = "could not determine checksum of '%s'" % os.path.basename(fn)
            self._add_result(t, n, s)
            return
        orig_sum = out.split()[0]

        (rc, out) = cmd(['sha512sum', tmp_repack])
        if rc != 0:
            t = 'error'
            s = "could not determine checksum of '%s'" % \
                os.path.relpath(tmp_repack, tmpdir)
            self._add_result(t, n, s)
            return
        repack_sum = out.split()[0]

        if orig_sum != repack_sum:
            t = 'error'
            s = "checksums do not match. Please ensure the snap is " + \
                "created with either 'snapcraft snap <DIR>' or " + \
                "'mksquashfs <dir> <snap> %s'" % " ".join(MKSQUASHFS_OPTS)
        self._add_result(t, n, s)
