'''cr_security.py: click security checks'''
#
# Copyright (C) 2013-2015 Canonical Ltd.
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
import clickreviews.cr_common as cr_common
import clickreviews.apparmor_policy as apparmor_policy
import copy
import json
import os


class ClickReviewSecurity(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        peer_hooks = dict()
        my_hook = 'apparmor'
        peer_hooks[my_hook] = dict()
        # Basically, everything except frameworks
        peer_hooks[my_hook]['allowed'] = ClickReview.app_allowed_peer_hooks + \
            ClickReview.scope_allowed_peer_hooks + \
            ClickReview.service_allowed_peer_hooks + \
            ['pay-ui']
        peer_hooks[my_hook]['required'] = []

        my_hook2 = 'apparmor-profile'
        peer_hooks[my_hook2] = dict()
        # Basically, everything except frameworks
        peer_hooks[my_hook2]['allowed'] = \
            ClickReview.service_allowed_peer_hooks
        peer_hooks[my_hook2]['required'] = []

        ClickReview.__init__(self, fn, "security", peer_hooks=peer_hooks,
                             overrides=overrides)

        local_copy = os.path.join(os.path.dirname(__file__),
                                  '../data/apparmor-easyprof-ubuntu.json')
        p = apparmor_policy.ApparmorPolicy(local_copy)
        self.aa_policy = p.policy

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
        self.required_fields = ['policy_version']
        self.redflag_fields = ['abstractions',
                               'binary',
                               'policy_vendor',
                               'read_path',
                               'template_variables',
                               'write_path']
        self.allowed_webapp_policy_groups = ['accounts',
                                             'audio',
                                             # 'camera', non-functional ATM
                                             'content_exchange',
                                             'content_exchange_source',
                                             'location',
                                             'networking',
                                             'video',
                                             'webview']

        self.allowed_push_helper_policy_groups = ['push-notification-client']
        self.allowed_network_scope_policy_groups = ['accounts', 'networking']

        self.redflag_templates = ['unconfined']
        # TODO: how to deal with other vendors
        self.extraneous_ubuntu_templates = ['ubuntu-sdk',
                                            'default']

        # framework policy is based on major framework version. In 13.10, there
        # was only 'ubuntu-sdk-13.10', but in 14.04, there will be several,
        # like 'ubuntu-sdk-14.04-html5', 'ubuntu-sdk-14.04-platform', etc
        self.major_framework_policy = {
            'ubuntu-sdk-13.10': {
                'policy_version': 1.0,
            },
            'ubuntu-sdk-14.04': {
                'policy_version': 1.1,
            },
            'ubuntu-sdk-14.10': {
                'policy_version': 1.2,
            },
            'ubuntu-core-15.04': {
                'policy_vendor': 'ubuntu-snappy',
                'policy_version': 1.3,
            },
        }
        framework_overrides = self.overrides.get('framework', {})
        self._override_framework_policies(framework_overrides)

        self.security_manifests = dict()
        self.security_apps = []
        for app in self.manifest['hooks']:
            if 'apparmor' not in self.manifest['hooks'][app]:
                #  msg("Skipped missing apparmor hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['apparmor'], str):
                error("manifest malformed: hooks/%s/apparmor is not str" % app)
            rel_fn = self.manifest['hooks'][app]['apparmor']
            self.security_manifests[rel_fn] = \
                self._extract_security_manifest(app)
            self.security_apps.append(app)

        self.security_profiles = dict()
        self.security_apps_profiles = []
        for app in self.manifest['hooks']:
            if 'apparmor-profile' not in self.manifest['hooks'][app]:
                #  msg("Skipped missing apparmor hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['apparmor-profile'],
                              str):
                error("manifest malformed: hooks/%s/apparmor-profile is not "
                      "str" % app)
            rel_fn = self.manifest['hooks'][app]['apparmor-profile']
            self.security_profiles[rel_fn] = \
                self._extract_security_profile(app)
            self.security_apps_profiles.append(app)

        # snappy
        self.sec_skipped_types = ['oem']  # these don't need security items

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

    def _extract_security_manifest(self, app):
        '''Extract security manifest and verify it has the expected
           structure'''
        d = self.manifest['hooks'][app]['apparmor']
        fn = os.path.join(self.unpack_dir, d)
        rel_fn = self.manifest['hooks'][app]['apparmor']

        try:
            m = json.load(cr_common.open_file_read(fn))
        except Exception:
            error("Could not load '%s'. Is it properly formatted?" % rel_fn)
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
                # python and Qt don't agree on the JSON output of floats that
                # are integers (ie, 1.0 vs 1). LP: #1214618
                if not isinstance(m[k], float) and not isinstance(m[k], int):
                    error("'%s' malformed: '%s' is not a JSON number:\n%s" %
                          (rel_fn, k, mp))
                if isinstance(m[k], int):
                    m[k] = float(m[k])
            else:
                if not isinstance(m[k], str):
                    error("'%s' malformed: '%s' is not str:\n%s" % (rel_fn,
                                                                    k, mp))
        return m

    def _get_security_manifest(self, app):
        '''Get the security manifest for app'''
        if app not in self.manifest['hooks']:
            error("Could not find '%s' in click manifest" % app)
        elif 'apparmor' not in self.manifest['hooks'][app]:
            error("Could not find apparmor hook for '%s' in click manifest" %
                  app)
        f = self.manifest['hooks'][app]['apparmor']
        m = self.security_manifests[f]
        return (f, m)

    def _extract_security_profile(self, app):
        '''Extract security profile'''
        d = self.manifest['hooks'][app]['apparmor-profile']
        fn = os.path.join(self.unpack_dir, d)
        rel_fn = self.manifest['hooks'][app]['apparmor-profile']

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

    def _get_security_profile(self, app):
        '''Get the security profile for app'''
        if app not in self.manifest['hooks']:
            error("Could not find '%s' in click manifest" % app)
        elif 'apparmor-profile' not in self.manifest['hooks'][app]:
            error("Could not find apparmor-profile hook for '%s' in click "
                  "manifest" % app)
        f = self.manifest['hooks'][app]['apparmor-profile']
        p = self.security_profiles[f]
        return (f, p)

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

    def _has_policy_version(self, vendor, version):
        '''Determine if has specified policy version'''
        if vendor not in self.aa_policy:
            error("Could not find vendor '%s'" % vendor, do_exit=False)
            return False

        if str(version) not in self.aa_policy[vendor]:
            return False
        return True

    def _get_highest_policy_version(self, vendor):
        '''Determine highest policy version for the vendor'''
        if vendor not in self.aa_policy:
            error("Could not find vendor '%s'" % vendor, do_exit=False)
            return None

        return float(sorted(self.aa_policy[vendor].keys())[-1])

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

    def check_policy_vendor(self):
        '''Check policy_vendor'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)
            t = 'info'
            n = 'policy_vendor (%s)' % f
            s = "OK"
            if 'policy_vendor' in m and \
               m['policy_vendor'] not in self.aa_policy:
                t = 'error'
                s = "policy_vendor '%s' not found" % m['policy_vendor']
            self._add_result(t, n, s)

            t = 'info'
            n = 'policy_vendor_matches_framework (%s)' % (f)
            s = "OK"
            if 'policy_vendor' in m:  # policy_vendor is optional
                found_major = False
                for name, data in self.major_framework_policy.items():
                    # TODO: use libclick when it is available
                    if not self.manifest['framework'].startswith(name):
                        continue
                    elif 'policy_vendor' not in data:
                        # when not specified, default to 'ubuntu'
                        data['policy_vendor'] = "ubuntu"
                    found_major = True
                    if m['policy_vendor'] != data['policy_vendor']:
                        t = 'error'
                        s = '%s != %s (%s)' % (str(m['policy_vendor']),
                                               data['policy_vendor'],
                                               self.manifest['framework'])
                if not found_major:
                    t = 'error'
                    s = "Invalid framework '%s'" % self.manifest['framework']
            self._add_result(t, n, s)

    def check_policy_version(self):
        '''Check policy version'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)

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
            if vendor not in self.aa_policy or \
               not self._has_policy_version(vendor, version):
                t = 'error'
                s = 'could not find policy for %s/%s' % (vendor, version)
            self._add_result(t, n, s)

            highest = self._get_highest_policy_version(vendor)
            t = 'info'
            n = 'policy_version_is_highest (%s, %s)' % (str(highest), f)
            s = "OK"
            l = None
            if float(m['policy_version']) != highest:
                t = 'info'
                l = 'http://askubuntu.com/q/562116/94326'
                s = '%s != %s' % (str(m['policy_version']), str(highest))
            self._add_result(t, n, s, l)

            t = 'info'
            n = 'policy_version_matches_framework (%s)' % (f)
            s = "OK"
            found_major = False
            for name, data in self.major_framework_policy.items():
                # TODO: use libclick when it is available
                if not self.manifest['framework'].startswith(name):
                    continue
                found_major = True
                if m['policy_version'] != data['policy_version']:
                    t = 'error'
                    s = '%s != %s (%s)' % (str(m['policy_version']),
                                           data['policy_version'],
                                           self.manifest['framework'])
            if not found_major:
                t = 'error'
                s = "Invalid framework '%s'" % self.manifest['framework']
            self._add_result(t, n, s)

    def check_template(self):
        '''Check template'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)

            t = 'info'
            n = 'template_with_policy_version (%s)' % f
            s = "OK"
            if 'policy_version' not in m:
                self._add_result('error', n,
                                 'could not find policy_version in manifest')
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = 'template_valid (%s)' % f
            s = "OK"
            manual_review = False
            if 'template' not in m:
                # If template not specified, we just use the default
                self._add_result(t, n, 'OK (none specified)')
                continue
            elif m['template'] in self.redflag_templates:
                t = 'error'
                s = "(MANUAL REVIEW) '%s' not allowed" % m['template']
                manual_review = True
            elif ('policy_vendor' not in m or m['policy_vendor'] == 'ubuntu') \
                    and m['template'] in self.extraneous_ubuntu_templates:
                t = 'warn'
                s = "No need to specify '%s' template" % m['template']
            self._add_result(t, n, s, manual_review=manual_review)

            t = 'info'
            n = 'template_exists (%s)' % f
            s = "OK"
            vendor = "ubuntu"
            if 'policy_vendor' in m:
                vendor = m['policy_vendor']
            version = str(m['policy_version'])

            templates = self._get_templates(vendor, version)
            if len(templates) < 1:
                t = 'error'
                s = 'could not find templates'
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            found = False
            if m['template'] in self._get_templates(vendor, version):
                found = True
            elif self.is_snap:
                frameworks = []
                if 'framework' in self.pkg_yaml:
                    frameworks = [x.strip() for x in framework.split(',')]
                elif 'frameworks' in self.pkg_yaml:
                    frameworks = self.pkg_yaml['frameworks']
                for f in frameworks:
                    if m['template'].startswith("%s_" % f):
                        # s = "OK (matches '%s' framework)" % f
                        # t = 'warn'
                        # s = "(STORE CHECK) need to verify " + \
                        #     "'%s' is in framwork " % m['template'] + \
                        #     "'%s'" % f
                        found = True
                        break

            if not found:
                t = 'error'
                s = "specified unsupported template '%s'" % m['template']

            self._add_result(t, n, s)

    def check_policy_groups_webapps(self):
        '''Check policy_groups for webapps'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)
            t = 'info'
            n = 'policy_groups_webapp (%s)' % f
            s = "OK"
            webapp_template = "ubuntu-webapp"
            if 'template' not in m or m['template'] != webapp_template:
                # self._add_result(t, n, s)
                continue
            if 'policy_groups' not in m or \
               'networking' not in m['policy_groups']:
                self._add_result('error', n,
                                 "required group 'networking' not found")
                continue
            bad = []
            for p in m['policy_groups']:
                if p not in self.allowed_webapp_policy_groups:
                    bad.append(p)
            if len(bad) > 0:
                t = 'error'
                s = "found unusual policy groups: %s" % ", ".join(bad)
            self._add_result(t, n, s)

            t = 'info'
            n = 'policy_groups_webapp_webview (%s)' % f
            s = "OK"
            if self.manifest['framework'] == "ubuntu-sdk-13.10":
                s = "SKIPPED (webview not available in 13.10)"
            elif 'webview' not in m['policy_groups']:
                t = 'warn'
                s = "'webview' not specified. Webapp may not function"

            self._add_result(t, n, s)

    def check_template_push_helpers(self):
        '''Check template for push-helpers'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)
            t = 'info'
            n = 'template_push_helper(%s)' % f
            s = "OK"
            if 'push-helper' not in self.manifest['hooks'][app]:
                continue
            if 'template' not in m or m['template'] != "ubuntu-push-helper":
                t = 'error'
                s = "template is not 'ubuntu-push-helper'"
            self._add_result(t, n, s)

    def check_policy_groups_push_helpers(self):
        '''Check policy_groups for push-helpers'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)
            t = 'info'
            n = 'policy_groups_push_helper(%s)' % f
            s = "OK"
            if 'push-helper' not in self.manifest['hooks'][app]:
                continue
            if 'policy_groups' not in m or \
               'push-notification-client' not in m['policy_groups']:
                self._add_result('error', n,
                                 "required group 'push-notification-client' "
                                 "not found")
                continue
            bad = []
            for p in m['policy_groups']:
                if p not in self.allowed_push_helper_policy_groups:
                    bad.append(p)
                elif p == "networking":
                    # The above covers this, but let's be very explicit and
                    # never allow networking with push-helpers
                    bad.append(p)
            if len(bad) > 0:
                t = 'error'
                s = "found unusual policy groups: %s" % ", ".join(bad)
            self._add_result(t, n, s)

    def check_policy_groups_scopes(self):
        '''Check policy_groups for scopes'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)
            t = 'info'
            n = 'policy_groups_scopes (%s)' % f
            s = "OK"
# jdstrand, 2014-06-05: ubuntu-scope-local-content is no longer available
#            scope_templates = ['ubuntu-scope-network',
#                               'ubuntu-scope-local-content']
            scope_templates = ['ubuntu-scope-network']
            if 'template' not in m or m['template'] not in scope_templates:
                continue

            if 'policy_groups' not in m:
                continue

            bad = []
            for p in m['policy_groups']:
                if m['template'] == 'ubuntu-scope-network':
                    # networking scopes should have extremely limited access
                    if p not in self.allowed_network_scope_policy_groups:
                        bad.append(p)
# jdstrand, 2014-06-05: ubuntu-scope-local-content is no longer available
#                elif m['template'] == 'ubuntu-scope-local-content':
#                    if p == 'networking':
#                        bad.append(p)

            if len(bad) > 0:
                t = 'error'
                s = "found inappropriate policy groups: %s" % ", ".join(bad)
            self._add_result(t, n, s)

    def check_policy_groups(self):
        '''Check policy_groups'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)

            t = 'info'
            n = 'policy_groups_exists_%s (%s)' % (app, f)
            if 'policy_groups' not in m:
                # If template not specified, we just use the default
                self._add_result('info', n, 'no policy groups specified')
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

            policy_groups = self._get_policy_groups(version=version, vendor=vendor)
            if len(policy_groups) < 1:
                t = 'error'
                s = 'could not find policy groups'
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            # Check for duplicates
            t = 'info'
            n = 'policy_groups_duplicates_%s (%s)' % (app, f)
            s = 'OK'
            tmp = []
            for p in m['policy_groups']:
                if m['policy_groups'].count(p) > 1 and p not in tmp:
                    tmp.append(p)
                if len(tmp) > 0:
                    tmp.sort()
                    t = 'error'
                    s = 'duplicate policy groups found: %s' % ", ".join(tmp)
            self._add_result(t, n, s)

            # If we got here, we can see if valid policy groups were specified
            for i in m['policy_groups']:
                t = 'info'
                n = 'policy_groups_valid_%s (%s)' % (app, i)
                s = 'OK'

                # SDK will leave and empty policy group, report but don't
                # deny
                if i == "":
                    t = 'error'
                    s = 'found empty policy group'
                    self._add_result(t, n, s)
                    continue

                found = False
                framework_found = False
                frameworks = []
                if self.is_snap:
                    if 'framework' in self.pkg_yaml:
                        frameworks = [x.strip() for x in framework.split(',')]
                    elif 'frameworks' in self.pkg_yaml:
                        frameworks = self.pkg_yaml['frameworks']
                for j in policy_groups:
                    if i == os.path.basename(j):
                        found = True
                        break
                    else:
                        for f in frameworks:
                            if i.startswith("%s_" % f):
                                framework_found = True
                                break
                        if framework_found:
                            found = True
                            break

                if not found:
                    t = 'error'
                    s = "unsupported policy_group '%s'" % i
                self._add_result(t, n, s)

                if found:
                    t = 'info'
                    n = 'policy_groups_safe_%s (%s)' % (app, i)
                    s = 'OK'
                    l = None
                    manual_review = False

                    if framework_found:
                        aa_type = 'framework'
                    else:
                        aa_type = self._get_policy_group_type(vendor, version,
                                                              i)
                    if i == "debug":
                        t = 'error'
                        s = "(REJECT) %s policy group " % aa_type + \
                            "'%s': not for production use" % (i)
                    elif aa_type == "reserved":
                        t = 'error'
                        s = "(MANUAL REVIEW) %s policy group " % aa_type + \
                            "'%s': vetted applications only" % (i)
                        if i == "debug":
                            l = 'http://askubuntu.com/a/562123/94326'
                        manual_review = True
                    elif aa_type == 'framework':
                        s = "OK (matches '%s' framework)" % i.split('_')[0]
                        # t = 'warn'
                        # s = "(STORE CHECK) need to verify '%s' is " % i + \
                        #     "in framework '%s'" % i.split('_')[0]
                    elif aa_type != "common":
                        t = 'error'
                        s = "policy group '%s' has " % i + \
                            "unknown type '%s'" % (aa_type)
                    self._add_result(t, n, s, l, manual_review=manual_review)

    def check_ignored(self):
        '''Check ignored fields'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)

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
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)

            t = 'info'
            n = 'redflag_fields (%s)' % f
            s = "OK"
            found = []
            for i in self.redflag_fields:
                if i in m:
                    if i == 'policy_vendor' and \
                       m[i] in ['ubuntu', 'ubuntu-snappy']:
                        continue
                    found.append(i)

            if len(found) > 0:
                t = 'error'
                s = "found redflagged fields (needs human review): %s" % \
                    ", ".join(found)
            self._add_result(t, n, s)

    def check_required(self):
        '''Check required fields'''
        for app in sorted(self.security_apps):
            (f, m) = self._get_security_manifest(app)

            t = 'info'
            n = 'required_fields (%s)' % f
            s = "OK"
            not_found = []
            for i in self.required_fields:
                if i not in m:
                    not_found.append(i)

            if len(not_found) > 0:
                t = 'error'
                s = "missing required fields: %s" % ", ".join(not_found)
            self._add_result(t, n, s)

    def check_apparmor_profile(self):
        '''Check apparmor-profile'''
        for app in sorted(self.security_apps_profiles):
            (f, p) = self._get_security_profile(app)

            for v in ['###VAR###',
                      '###PROFILEATTACH###',
                      '@{CLICK_DIR}',
                      '@{APP_PKGNAME}',
                      '@{APP_VERSION}',
                      ]:
                t = 'info'
                n = 'apparmor_profile_%s (%s)' % (v, f)
                s = "OK"
                if v not in p:
                    self._add_result('warn', n,
                                     "could not find '%s' in profile" % v)
                    continue
                self._add_result(t, n, s)

    def _compare_security_yamls(self, yaml, click_m):
        '''Compare two security yamls'''
        def find_match(name, key, value, my_dict):
            if 'name' in my_dict and my_dict['name'] == name and \
               key in my_dict and my_dict[key] == value:
                return True
            return False

        for first in [yaml, click_m]:
            if first == yaml:
                second = click_m
                second_m = "click-manifest"
                first_m = "package.yaml"
            else:
                second = yaml
                first_m = "click-manifest"
                second_m = "package.yaml"
            for exe_t in ['binaries', 'services']:
                t = 'info'
                n = 'yaml_%s' % exe_t
                s = 'OK'
                if exe_t in first and exe_t not in second:
                    t = 'error'
                    s = "%s missing '%s'" % (second_m, exe_t)
                elif exe_t not in first and exe_t in second:
                    t = 'error'
                    s = "%s has extra '%s'" % (second_m, exe_t)
                self._add_result(t, n, s)

                if t == 'error':
                    continue
                elif exe_t not in first and exe_t not in second:
                    continue

                t = 'info'
                n = 'yaml_%s_entries' % exe_t
                s = 'OK'
                if len(first[exe_t]) < len(second[exe_t]):
                    t = 'error'
                    s = "%s has extra '%s' entries" % (second_m, exe_t)
                self._add_result(t, n, s)

                for fapp in first[exe_t]:
                    t = 'info'
                    n = 'yaml_%s_%s' % (exe_t, fapp['name'])
                    s = 'OK'
                    sapp = None
                    for tmp in second[exe_t]:
                        if tmp['name'] == fapp['name']:
                            sapp = tmp
                    if sapp is None:
                        t = 'error'
                        s = "%s missing '%s'" % (second_m, fapp['name'])
                        self._add_result(t, n, s)
                        continue
                    self._add_result(t, n, s)

                    for key in ['security-template', 'caps']:
                        if key not in fapp:
                            continue
                        if key == 'caps':
                            fapp['caps'] = set(fapp['caps'])
                        t = 'info'
                        n = 'yaml_%s_%s' % (exe_t, second_m)
                        s = 'OK'
                        if not find_match(fapp['name'], key, fapp[key], sapp):
                            t = 'error'
                            s = "%s has different '%s' for '%s'" % \
                                (second_m, key, fapp['name']) + \
                                " - '%s:%s' vs '%s:%s'" % (first_m, fapp,
                                                           second_m, sapp)
                        self._add_result(t, n, s)

    def _convert_click_security_to_yaml(self):
        '''Convert click manifest to yaml'''
        converted = dict()
        for app in sorted(self.security_apps):
            if 'snappy-systemd' in self.manifest['hooks'][app]:
                key = 'services'
            elif 'bin-path' in self.manifest['hooks'][app]:
                key = 'binaries'
            else:
                t = 'error'
                n = 'yaml_click_%s' % app
                s = "click manifest missing 'snappy-systemd/bin-path' for " + \
                    "'%s'" % app
                self._add_result(t, n, s)
                continue

            if key not in converted:
                converted[key] = []
            tmp = dict()
            tmp['name'] = app

            (f, m) = self._get_security_manifest(app)
            if 'template' in m:
                tmp['security-template'] = m['template']

            if 'policy_groups' in m:
                tmp['caps'] = set(m['policy_groups'])

            converted[key].append(copy.deepcopy(tmp))

        for app in sorted(self.security_apps_profiles):
            if 'snappy-systemd' in self.manifest['hooks'][app]:
                key = 'services'
            elif 'bin-path' in self.manifest['hooks'][app]:
                key = 'binaries'
            else:
                t = 'error'
                n = 'yaml_click_%s' % app
                s = "click manifest missing 'snappy-systemd/bin-path' for " + \
                    "'%s'" % app
                self._add_result(t, n, s)
                continue

            if key not in converted:
                converted[key] = []
            tmp = dict()
            tmp['name'] = app

            (f, p) = self._get_security_profile(app)
            tmp['security-policy'] = {'apparmor': f}

            converted[key].append(copy.deepcopy(tmp))

        return copy.deepcopy(converted)

    def check_security_yaml_and_click(self):
        '''Verify click and security yaml are in sync (not including
           override)
        '''
        if not self.is_snap or self.pkg_yaml['type'] in self.sec_skipped_types:
            return

        converted = self._convert_click_security_to_yaml()

        # setup a small dict that is a subset of self.pkg_yaml
        y = dict()
        if 'binaries' in self.pkg_yaml:
            y['binaries'] = copy.deepcopy(self.pkg_yaml['binaries'])
        if 'services' in self.pkg_yaml:
            y['services'] = copy.deepcopy(self.pkg_yaml['services'])

        self._compare_security_yamls(y, converted)

    def check_security_yaml_override_and_click(self):
        '''Verify click and security yaml override are in sync'''
        if not self.is_snap or self.pkg_yaml['type'] in self.sec_skipped_types:
            return

        for exe_t in ['services', 'binaries']:
            if exe_t not in self.pkg_yaml:
                continue

            for a in self.pkg_yaml[exe_t]:
                if 'name' not in a:
                    t = 'error'
                    n = 'yaml_override_click_name'
                    s = "package.yaml malformed. Could not find 'name' " + \
                        "for entry in '%s'" % a
                    self._add_result(t, n, s)
                    continue

                app = a['name']
                t = 'info'
                n = 'yaml_override_click_%s' % app
                s = "OK"
                if 'security-override' not in a:
                    s = "OK (skipping unspecified override)"
                elif 'apparmor' not in a['security-override']:
                    t = 'error'
                    s = "'apparmor' not specified in 'security-override' " + \
                        "for '%s'" % app
                elif a['security-override']['apparmor'] not in \
                        self.security_manifests:
                    t = 'error'
                    s = "'%s' not found in click manifest for '%s'" % \
                        (a['security-override']['apparmor'], app)
                # NOTE: we skip 'seccomp' because there isn't currently a
                # click hook for it
                self._add_result(t, n, s)

    def check_security_yaml_override(self):
        '''Verify security yaml override'''
        for exe_t in ['services', 'binaries']:
            if exe_t not in self.pkg_yaml:
                continue

            for a in self.pkg_yaml[exe_t]:
                if 'name' not in a:
                    t = 'error'
                    n = 'yaml_override_name'
                    s = "package.yaml malformed. Could not find 'name' " + \
                        "for entry in '%s'" % a
                    self._add_result(t, n, s)
                    continue

                app = a['name']
                t = 'info'
                n = 'yaml_override_format_%s' % app
                s = "OK"
                if 'security-override' not in a:
                    s = "OK (skipping unspecified override)"
                elif 'apparmor' not in a['security-override']:
                    t = 'error'
                    s = "'apparmor' not specified in 'security-override' " + \
                        "for '%s'" % app
                elif 'seccomp' not in a['security-override']:
                    t = 'error'
                    s = "'seccomp' not specified in 'security-override' " + \
                        "for '%s'" % app
                self._add_result(t, n, s)

    def check_security_yaml_policy(self):
        '''Verify security yaml policy'''
        for exe_t in ['services', 'binaries']:
            if exe_t not in self.pkg_yaml:
                continue

            for a in self.pkg_yaml[exe_t]:
                if 'name' not in a:
                    t = 'error'
                    n = 'yaml_policy_name'
                    s = "package.yaml malformed. Could not find 'name' " + \
                        "for entry in '%s'" % a
                    self._add_result(t, n, s)
                    continue

                app = a['name']
                t = 'info'
                n = 'yaml_policy_format_%s' % app
                s = "OK"
                if 'security-policy' not in a:
                    s = "OK (skipping unspecified policy)"
                elif 'apparmor' not in a['security-policy']:
                    t = 'error'
                    s = "'apparmor' not specified in 'security-policy' " + \
                        "for '%s'" % app
                elif 'seccomp' not in a['security-policy']:
                    t = 'error'
                    s = "'seccomp' not specified in 'security-policy' for " + \
                        "'%s'" % app
                self._add_result(t, n, s)

    def check_security_yaml_combinations(self):
        '''Verify security yaml uses valid combinations'''
        if not self.is_snap or self.pkg_yaml['type'] in self.sec_skipped_types:
            return

        for exe_t in ['services', 'binaries']:
            if exe_t not in self.pkg_yaml:
                continue
            for a in self.pkg_yaml[exe_t]:
                if 'name' not in a:
                    t = 'error'
                    n = 'yaml_combinations_name'
                    s = "package.yaml malformed. Could not find 'name' " + \
                        "for entry in '%s'" % a
                    self._add_result(t, n, s)
                    continue

                app = a['name']

                t = 'info'
                n = 'yaml_combinations_%s' % app
                s = "OK"
                if "security-policy" in a:
                    for i in ['security-override', 'security-template',
                              'caps']:
                        if i in a:
                            t = 'error'
                            s = "Found '%s' with 'security-policy'" % (i)
                            break
                elif "security-override" in a:
                    for i in ['security-policy', 'security-template', 'caps']:
                        if i in a:
                            t = 'error'
                            s = "Found '%s' with 'security-override'" % (i)
                            break
                self._add_result(t, n, s)

    def check_security_template(self):
        '''Check snap security-template'''
        if not self.is_snap or self.pkg_yaml['type'] in self.sec_skipped_types:
            return

        for exe_t in ['services', 'binaries']:
            if exe_t not in self.pkg_yaml:
                continue
            for a in self.pkg_yaml[exe_t]:
                if 'security-template' not in a:
                    tmpl = ""
                else:
                    tmpl = a['security-template']

                if 'name' not in a:
                    t = 'error'
                    n = 'yaml_security-template_name'
                    s = "package.yaml malformed. Could not find 'name' " + \
                        "for entry in '%s'" % a
                    self._add_result(t, n, s)
                    continue

                app = a['name']

                t = 'info'
                n = 'yaml_security-template_%s' % app
                s = "OK"
                if not isinstance(tmpl, str):
                    t = 'error'
                    s = "'%s/%s' malformed: '%s' is not str" % (exe_t, app,
                                                                tmpl)
                    self._add_result(t, n, s)
                    continue
                self._add_result(t, n, s)

                t = 'info'
                n = 'yaml_security-template_in_manifest_%s' % app
                s = "OK"
                if app not in self.manifest['hooks']:
                    t = 'error'
                    s = "'%s' not found in click manifest" % app
                    self._add_result(t, n, s)
                    continue
                elif 'apparmor' not in self.manifest['hooks'][app] and \
                     'apparmor-profile' not in self.manifest['hooks'][app]:
                    t = 'error'
                    s = "'apparmor' not found in click manifest for '%s'" % app
                    self._add_result(t, n, s)
                    continue
