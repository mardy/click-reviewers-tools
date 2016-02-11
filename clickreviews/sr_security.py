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

        # FIXME
        # framework policy is based on major framework version. Snappy doesn't
        # use these any more.
        self.major_framework_policy = {
            'ubuntu-core-16.04': {
                'policy_vendor': 'ubuntu-core',
                'policy_version': 16.04,
            },
        }
        framework_overrides = self.overrides.get('framework', {})
        self._override_framework_policies(framework_overrides)

        # snappy
        self.sec_skipped_types = ['oem',
                                  'os',
                                  'kernel']  # these don't need security items

        # Note: 16.04 employs migration skills for security policy and these
        # skills declarations are currently only in the toplevel 'uses' field.
        # When native security skills are supported, this will need to be
        # adjusted.

    def _override_framework_policies(self, overrides):
        # override major framework policies
        self.major_framework_policy.update(overrides)

        # override apparmor policies
        for name, data in overrides.items():
            vendor = data.get('policy_vendor')
            version = str(data.get('policy_version'))

            if vendor not in self.aa_policy:
                self.aa_policy[vendor] = {}

            if version not in self.aa_policy[vendor]:
                # just ensure the version is defined
                # TODO: add support to override templates and policy groups
                self.aa_policy[vendor][version] = {}

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

    def _get_policy_versions(self, vendor):
        '''Get the supported AppArmor policy versions'''
        if vendor not in self.aa_policy:
            error("Could not find vendor '%s'" % vendor, do_exit=False)
            return None

        supported_policy_versions = []
        for i in self.aa_policy[vendor].keys():
            supported_policy_versions.append("%.1f" % float(i))

        return sorted(supported_policy_versions)

    def _get_templates(self, vendor, version, aa_type="all"):
        '''Get templates by type'''
        templates = []
        if aa_type == "all":
            for k in self.aa_policy[vendor][version]['templates'].keys():
                templates += self.aa_policy[vendor][version]['templates'][k]
        else:
            templates = self.aa_policy[vendor][version]['templates'][aa_type]

        return sorted(templates)

    def _get_policy_groups(self, vendor, version, aa_type="all"):
        '''Get policy groups by type'''
        groups = []
        if vendor not in self.aa_policy:
            error("Could not find vendor '%s'" % vendor, do_exit=False)
            return groups

        if not self._has_policy_version(vendor, version):
            error("Could not find version '%s'" % version, do_exit=False)
            return groups

        v = str(version)
        if aa_type == "all":
            for k in self.aa_policy[vendor][v]['policy_groups'].keys():
                groups += self.aa_policy[vendor][v]['policy_groups'][k]
        else:
            groups = self.aa_policy[vendor][v]['policy_groups'][aa_type]

        return sorted(groups)

    def _get_policy_group_type(self, vendor, version, policy_group):
        '''Return policy group type'''
        for t in self.aa_policy[vendor][version]['policy_groups']:
            if policy_group in self.aa_policy[vendor][version]['policy_groups'][t]:
                return t

    # FIXME: finish
    def check_uses_redflag(self):
        '''Check uses redflag fields'''
        if not self.is_snap2 or 'uses' not in self.snap_yaml:
            return

        for slot in self.snap_yaml['uses']:
            t = 'info'
            n = self._get_check_name('redflag_fields', extra=slot)
            s = 'OK'
            m = False
            if 'type' not in self.snap_yaml['uses'][slot] or \
                    self.snap_yaml['uses'][slot]['type'] != 'migration-skill':
                    skill_type = slot
                    if 'type' in self.snap_yaml['uses'][slot]:
                        skill_type = self.snap_yaml['uses'][slot]['type']
                    t = 'error'
                    s = "unknown skill type: %s" % skill_type
            else:
                attrib = None
                if 'security-override' in self.snap_yaml['uses'][slot]:
                    attrib = 'security-override'
                elif 'security-policy' in self.snap_yaml['uses'][slot]:
                    attrib = 'security-policy'
                if attrib:
                    t = 'error'
                    s = "found redflagged attribute: %s" % attrib
                    m = True
            self._add_result(t, n, s, m)

    # FIXME: finish
    def check_apps_uses_redflag(self):
        '''Check apps uses redflag fields'''
        if not self.is_snap2 or 'apps' not in self.snap_yaml:
            return

        for app in self.snap_yaml['apps']:
            if 'uses' not in self.snap_yaml['apps'][app]:
                continue

            # Note: Snappy 16.04 doesn't require a mapping for skills in the
            # toplevel 'uses' if the skill 'type' is the same as the skill
            # slot name, which means that apps may not have a mapping.
            # Currently only 'migration-skill' is supported for security
            # policies, so any other 'uses' that aren't a migration skill are
            # unknown. This will need to be adjusted as skills matures
            if not isinstance(self.snap_yaml['apps'][app]['uses'], list) or \
                    len(self.snap_yaml['apps'][app]['uses']) < 1:
                continue  # checked via sr_lint.py

            for slot_ref in self.snap_yaml['apps'][app]['uses']:
                t = 'info'
                n = self._get_check_name("app_uses", app=app, extra=slot_ref)
                s = 'OK'
                if not isinstance(slot_ref, str):
                    continue  # checked via sr_lint.py
                elif (slot_ref in self.skill_types and
                        slot_ref != 'migration-skill'):
                    t = 'error'
                    s = "unknown slot skill '%s'" % slot_ref
                # elif 'uses' in self.snap_yaml and \
                #        slot_ref in self.snap_yaml['uses'] and \
                #        'type' in
                #     t = 'error'
                #     s = "unknown slot skill name reference '%s'" % slot_ref
                self._add_result(t, n, s)

    def check_security_caps(self):
        '''TODO: Check security-caps'''
        if not self.is_snap2:
            return

    def check_security_override(self):
        '''TODO: Check security-override'''
        if not self.is_snap2:
            return

    def check_security_policy(self):
        '''TODO: Check security-policy'''
        if not self.is_snap2:
            return

    def check_security_template(self):
        '''TODO: Check security-template'''
        if not self.is_snap2:
            return

    def check_security_combinations(self):
        '''TODO: Verify security yaml uses valid combinations'''
        if not self.is_snap2:
            return

    def check_apparmor_profile_name_length(self):
        '''TODO: Check AppArmor profile name length'''
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
#         maxlen = 230  # 245 minus a bit for child profiles
#         advlen = 100
