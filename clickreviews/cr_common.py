'''cr_common.py: common classes and functions'''
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
from debian.deb822 import Deb822
import glob
import json
import os
import pprint
import re
import yaml


from clickreviews.common import (
    Review,
    ReviewException,
    error,
    open_file_read,
)


#
# Utility classes
#
class ClickReviewException(ReviewException):
    '''This class represents ClickReview exceptions'''


class ClickReview(Review):
    '''This class represents click reviews'''
    # Convenience to break out common types of clicks (eg, app, scope,
    # click service)
    app_allowed_peer_hooks = ["account-application",
                              "account-service",
                              "accounts",
                              "account-provider",
                              "account-qml-plugin",
                              "apparmor",
                              "content-hub",
                              "desktop",
                              "push-helper",
                              "urls",
                              ]
    scope_allowed_peer_hooks = ["account-application",
                                "account-service",
                                "accounts",
                                "apparmor",
                                "scope",
                                ]
    # FIXME: when apparmor-policy is implemented, use this
    service_allowed_peer_hooks = ["apparmor",
                                  "bin-path",  # obsoleted, ignored
                                  "snappy-systemd",  # obsoleted, ignored
                                  ]

    snappy_required = ["name", "version"]
    # optional snappy fields here (may be required by appstore)
    snappy_optional = ["architecture",
                       "architectures",
                       "binaries",
                       "caps",
                       "config",
                       "dtbs",
                       "firmware",
                       "frameworks",
                       "icon",
                       "immutable-config",
                       "initrd",
                       "kernel",
                       "modules",
                       "oem",
                       "gadget",
                       "services",
                       "source",
                       "type",
                       "vendor",  # deprecated, unused
                       ]
    snappy_exe_security = ["caps",
                           "security-template",
                           "security-override",
                           "security-policy"]

    def __init__(self, fn, review_type, peer_hooks=None, overrides=None,
                 peer_hooks_link=None):
        Review.__init__(self, fn, review_type, overrides=overrides)

        # The cr_* scripts only support 15.04 snaps (v1). Use sr_* scripts for
        # 16.04 (v2) or higher
        if not self.is_click and not self.is_snap1:
            return

        if not self.pkg_filename.endswith(".click") and \
                not self.pkg_filename.endswith(".snap"):
            if self.pkg_filename.endswith(".deb"):
                error("filename does not end with '.click', but '.deb' "
                      "instead. See http://askubuntu.com/a/485544/94326 for "
                      "how click packages are different.")
            error("filename does not end with '.click'")

        self.manifest = None
        self.click_pkgname = None
        self.click_version = None
        self.pkg_arch = []
        self.is_snap_oem = False
        self.peer_hooks = peer_hooks
        self.peer_hooks_link = peer_hooks_link

        if self.is_snap1:
            pkg_yaml = self._extract_package_yaml()
            if pkg_yaml:
                try:
                    self.pkg_yaml = yaml.safe_load(pkg_yaml)
                except Exception:
                    error("Could not load package.yaml. "
                          "Is it properly formatted?")
                self._verify_package_yaml_structure()
            else:
                error("Could not load package.yaml.")

            #  default to 'app'
            if 'type' not in self.pkg_yaml:
                self.pkg_yaml['type'] = 'app'

            if 'architectures' in self.pkg_yaml:
                self.pkg_arch = self.pkg_yaml['architectures']
            elif 'architecture' in self.pkg_yaml:
                if isinstance(self.pkg_yaml['architecture'], str):
                    self.pkg_arch = [self.pkg_yaml['architecture']]
                elif isinstance(self.pkg_yaml['architecture'], list):
                    self.pkg_arch = self.pkg_yaml['architecture']
                else:
                    error("Could not load package.yaml: "
                          "invalid 'architecture'")
            else:
                self.pkg_arch = ['all']

            if 'type' in self.pkg_yaml and self.pkg_yaml['type'] == 'oem':
                self.is_snap_oem = True

        if self.is_click or self.is_snap1:
            # Get some basic information from the control file
            control_file = self._extract_control_file()
            tmp = list(Deb822.iter_paragraphs(control_file))
            if len(tmp) != 1:
                error("malformed control file: too many paragraphs")
            control = tmp[0]
            self.click_pkgname = control['Package']
            self.click_version = control['Version']
            if self.is_click:
                if control['Architecture'] not in self.pkg_arch:
                    self.pkg_arch.append(control['Architecture'])
                self.pkgfmt["version"] = str(control['Click-Version'])

            # Parse and store the manifest
            manifest_json = self._extract_manifest_file()
            try:
                self.manifest = json.load(manifest_json)
            except Exception:
                error("Could not load manifest file. "
                      "Is it properly formatted?")
            self._verify_manifest_structure()

            self.valid_frameworks = self._extract_click_frameworks()

    def _extract_click_frameworks(self):
        '''Extract installed click frameworks'''
        # TODO: update to use libclick API when available
        valid_frameworks = []
        frameworks = sorted(
            glob.glob("/usr/share/click/frameworks/*.framework"))
        if len(frameworks) == 0:
            valid_frameworks.append('ubuntu-sdk-13.10')
        else:
            for f in frameworks:
                valid_frameworks.append(os.path.basename(
                                        os.path.splitext(f)[0]))
        return valid_frameworks

    def _extract_manifest_file(self):
        '''Extract and read the manifest file'''
        m = os.path.join(self.unpack_dir, "DEBIAN/manifest")
        if not os.path.isfile(m):
            error("Could not find manifest file")
        return open_file_read(m)

    def _extract_package_yaml(self):
        '''Extract and read the snappy 15.04 package.yaml'''
        y = os.path.join(self.unpack_dir, "meta/package.yaml")
        if not os.path.isfile(y):
            return None  # snappy packaging is still optional
        return open_file_read(y)

    def _extract_hashes_yaml(self):
        '''Extract and read the snappy hashes.yaml'''
        y = os.path.join(self.unpack_dir, "DEBIAN/hashes.yaml")
        return open_file_read(y)

    def _extract_control_file(self):
        '''Extract '''
        fh = open_file_read(os.path.join(self.unpack_dir, "DEBIAN/control"))
        return fh.readlines()

    def _verify_manifest_structure(self):
        '''Verify manifest has the expected structure'''
        # lp:click doc/file-format.rst
        mp = pprint.pformat(self.manifest)
        if not isinstance(self.manifest, dict):
            error("manifest malformed:\n%s" % self.manifest)

        required = ["name", "version", "framework"]  # click required
        for f in required:
            if f not in self.manifest:
                error("could not find required '%s' in manifest:\n%s" % (f,
                                                                         mp))
            elif not isinstance(self.manifest[f], str):
                error("manifest malformed: '%s' is not str:\n%s" % (f, mp))

        # optional click fields here (may be required by appstore)
        # http://click.readthedocs.org/en/latest/file-format.html
        optional = ["title", "description", "maintainer", "architecture",
                    "installed-size", "icon"]

        # https://developer.ubuntu.com/snappy/guides/packaging-format-apps/
        snappy_optional = ["ports", "source", "type"]

        for f in optional:
            if f in self.manifest:
                if f != "architecture" and \
                   not isinstance(self.manifest[f], str):
                    error("manifest malformed: '%s' is not str:\n%s" % (f, mp))
                elif f == "architecture" and not \
                    (isinstance(self.manifest[f], str) or
                     isinstance(self.manifest[f], list)):
                    error("manifest malformed: '%s' is not str or list:\n%s" %
                          (f, mp))

        # FIXME: this is kinda gross but the best we can do while we are trying
        # to support clicks and native snaps
        if 'type' in self.manifest and self.manifest['type'] == 'oem':
            if 'hooks' in self.manifest:
                error("'hooks' present in manifest with type 'oem'")
            # mock up something for other tests
            self.manifest['hooks'] = {'oem': {'reviewtools': True}}

        # Not required by click, but required by appstore. 'hooks' is assumed
        # to be present in other checks
        if 'hooks' not in self.manifest:
            error("could not find required 'hooks' in manifest:\n%s" % mp)
        if not isinstance(self.manifest['hooks'], dict):
            error("manifest malformed: 'hooks' is not dict:\n%s" % mp)
        # 'hooks' is assumed to be present and non-empty in other checks
        if len(self.manifest['hooks']) < 1:
            error("manifest malformed: 'hooks' is empty:\n%s" % mp)
        for app in self.manifest['hooks']:
            if not isinstance(self.manifest['hooks'][app], dict):
                error("manifest malformed: hooks/%s is not dict:\n%s" % (app,
                                                                         mp))
            # let cr_lint.py handle required hooks
            if len(self.manifest['hooks'][app]) < 1:
                error("manifest malformed: hooks/%s is empty:\n%s" % (app, mp))

        for k in sorted(self.manifest):
            if k not in required + optional + snappy_optional + ['hooks']:
                # click supports local extensions via 'x-...', ignore those
                # here but report in lint
                if k.startswith('x-'):
                    continue
                error("manifest malformed: unsupported field '%s':\n%s" % (k,
                                                                           mp))

    def _verify_package_yaml_structure(self):
        '''Verify package.yaml has the expected structure'''
        # https://developer.ubuntu.com/en/snappy/guides/packaging-format-apps/
        # lp:click doc/file-format.rst
        yp = yaml.dump(self.pkg_yaml, default_flow_style=False, indent=4)
        if not isinstance(self.pkg_yaml, dict):
            error("package yaml malformed:\n%s" % self.pkg_yaml)

        for f in self.snappy_required:
            if f not in self.pkg_yaml:
                error("could not find required '%s' in package.yaml:\n%s" %
                      (f, yp))
            elif f in ['name', 'version']:
                # make sure this is a string for other tests since
                # yaml.safe_load may make it an int, float or str
                self.pkg_yaml[f] = str(self.pkg_yaml[f])

        for f in self.snappy_optional:
            if f in self.pkg_yaml:
                if f in ["architecture", "frameworks"] and not \
                    (isinstance(self.pkg_yaml[f], str) or
                     isinstance(self.pkg_yaml[f], list)):
                    error("yaml malformed: '%s' is not str or list:\n%s" %
                          (f, yp))
                elif f in ["binaries", "services"] and not \
                        isinstance(self.pkg_yaml[f], list):
                    error("yaml malformed: '%s' is not list:\n%s" % (f, yp))
                elif f in ["icon", "source", "type", "vendor"] and not \
                        isinstance(self.pkg_yaml[f], str):
                    error("yaml malformed: '%s' is not str:\n%s" % (f, yp))

    def _verify_peer_hooks(self, my_hook):
        '''Compare manifest for required and allowed hooks'''
        d = dict()
        if self.peer_hooks is None:
            return d

        for app in self.manifest["hooks"]:
            if my_hook not in self.manifest["hooks"][app]:
                continue
            for h in self.peer_hooks[my_hook]['required']:
                if h == my_hook:
                    continue
                if h not in self.manifest["hooks"][app]:
                    # Treat these as equivalent for satisfying peer hooks
                    if h == 'apparmor' and \
                       'apparmor-profile' in self.manifest["hooks"][app]:
                        continue

                    if 'missing' not in d:
                        d['missing'] = dict()
                    if app not in d['missing']:
                        d['missing'][app] = []
                    d['missing'][app].append(h)
            for h in self.manifest["hooks"][app]:
                if h == my_hook:
                    continue
                if h not in self.peer_hooks[my_hook]['allowed']:
                    # 'apparmor-profile' is allowed when 'apparmor' is, but
                    # they may not be used together
                    if h == 'apparmor-profile':
                        if 'apparmor' in self.peer_hooks[my_hook]['allowed'] \
                           and 'apparmor' not in self.manifest["hooks"][app]:
                            continue

                    if 'disallowed' not in d:
                        d['disallowed'] = dict()
                    if app not in d['disallowed']:
                        d['disallowed'][app] = []
                    d['disallowed'][app].append(h)

        return d

    def _verify_pkgname(self, n):
        '''Verify package name'''
        if self.is_snap1:
            # snaps can't have '.' in the name
            pat = re.compile(r'^[a-z0-9][a-z0-9+-]+$')
        else:
            pat = re.compile(r'^[a-z0-9][a-z0-9+.-]+$')
        if pat.search(n):
            return True
        return False

    def _verify_maintainer(self, m):
        '''Verify maintainer email'''
        #  Simple regex as used by python3-debian. If we wanted to be more
        #  thorough we could use email_re from django.core.validators
        if re.search(r"^(.*)\s+<(.*@.*)>$", m):
            return True
        return False

    def _create_dict(self, lst, topkey='name'):
        '''Converts list of dicts into dict[topkey][<the rest>]. Useful for
           conversions from yaml list to json dict'''
        d = dict()
        for entry in lst:
            if topkey not in entry:
                error("required field '%s' not present: %s" % (topkey, entry))
            name = entry[topkey]
            d[name] = dict()
            for key in entry:
                if key == topkey:
                    continue
                d[name][key] = entry[key]
        return d

    def _get_policy_versions(self, vendor):
        '''Get the supported AppArmor policy versions'''
        if not self.aa_policy:
            return None

        if vendor not in self.aa_policy:
            error("Could not find vendor '%s'" % vendor, do_exit=False)
            return None

        supported_policy_versions = []
        for i in self.aa_policy[vendor].keys():
            supported_policy_versions.append("%.1f" % float(i))

        return sorted(supported_policy_versions)

    def _get_templates(self, vendor, version, aa_type="all"):
        '''Get templates by type'''
        if not self.aa_policy:
            return None

        templates = []
        if aa_type == "all":
            for k in self.aa_policy[vendor][version]['templates'].keys():
                templates += self.aa_policy[vendor][version]['templates'][k]
        else:
            templates = self.aa_policy[vendor][version]['templates'][aa_type]

        return sorted(templates)

    def _has_policy_version(self, vendor, version):
        '''Determine if has specified policy version'''
        if not self.aa_policy:
            return None

        if vendor not in self.aa_policy:
            error("Could not find vendor '%s'" % vendor, do_exit=False)
            return False

        if str(version) not in self.aa_policy[vendor]:
            return False
        return True

    def _get_policy_groups(self, vendor, version, aa_type="all"):
        '''Get policy groups by type'''
        if not self.aa_policy:
            return None

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
        if not self.aa_policy:
            return None

        policy_groups = self.aa_policy[vendor][version]['policy_groups']
        for t in policy_groups:
            if policy_group in policy_groups[t]:
                return t
        return None

    def _get_template_type(self, vendor, version, template):
        '''Return template type'''
        if not self.aa_policy:
            return None

        for t in self.aa_policy[vendor][version]['templates']:
            if template in self.aa_policy[vendor][version]['templates'][t]:
                return t

    def check_peer_hooks(self, hooks_sublist=[]):
        '''Check if peer hooks are valid'''
        # Nothing to verify
        if not hasattr(self, 'peer_hooks') or self.peer_hooks is None:
            return

        for hook in self.peer_hooks:
            if len(hooks_sublist) > 0 and hook not in hooks_sublist:
                continue
            d = self._verify_peer_hooks(hook)
            t = 'info'
            n = self._get_check_name("peer_hooks_required", extra=hook)
            s = "OK"

            if 'missing' in d and len(d['missing'].keys()) > 0:
                t = 'error'
                for app in d['missing']:
                    s = "Missing required hooks for '%s': %s" % (
                        app, ", ".join(d['missing'][app]))
                    self._add_result(t, n, s, manual_review=True,
                                     link=self.peer_hooks_link)
            else:
                self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name("peer_hooks_disallowed", extra=hook)
            s = "OK"

            if 'disallowed' in d and len(d['disallowed'].keys()) > 0:
                t = 'error'
                for app in d['disallowed']:
                    s = "Disallowed with %s (%s): %s" % (
                        hook, app, ", ".join(d['disallowed'][app]))
                    self._add_result(t, n, s, manual_review=True,
                                     link=self.peer_hooks_link)
            else:
                self._add_result(t, n, s)
