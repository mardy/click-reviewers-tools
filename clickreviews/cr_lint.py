'''cr_lint.py: lint checks'''
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
from apt import apt_pkg
from debian.deb822 import Deb822
import glob
import os
import re

from clickreviews.frameworks import Frameworks
from clickreviews.cr_common import ClickReview, open_file_read, cmd

CONTROL_FILE_NAMES = ["control", "manifest", "md5sums", "preinst"]
MINIMUM_CLICK_FRAMEWORK_VERSION = "0.4"


class ClickReviewLint(ClickReview):
    '''This class represents click lint reviews'''

    def __init__(self, fn, overrides=None):
        '''Set up the class.'''
        ClickReview.__init__(self, fn, "lint")
        self.control_files = dict()
        self._list_control_files()
        # Valid values for Architecture in DEBIAN/control. Note:
        #  all    - no compiled code
        #  multi  - fat packages (click manifest declares which ones as a list)
        #  armhf  - compiled, single arch (unity8-based devices)
        #  i386   - compiled, single arch (unity8-based emulator and desktop)
        #  amd64  - compiled, single arch (unity8-based desktop)
        #  arm64  - compiled, single arch (not available yet)
        #  ppc64el - compiled, single arch (not available yet)
        #  powerpc - compiled, single arch (not available yet)
        self.valid_compiled_architectures = ['armhf',
                                             'i386',
                                             'amd64',
                                             ]
        self.valid_control_architectures = ['all',
                                            'multi',
                                            ] + self.valid_compiled_architectures
        self.vcs_dirs = ['.bzr*', '.git*', '.svn*', '.hg', 'CVS*', 'RCS*']

        if 'maintainer' in self.manifest:
            maintainer = self.manifest['maintainer']
            self.email = maintainer.partition('<')[2].rstrip('>')
            self.is_core_app = (self.click_pkgname.startswith('com.ubuntu.')
                                and not self.click_pkgname.startswith(
                                    'com.ubuntu.developer.')
                                and (self.email ==
                                'ubuntu-touch-coreapps@lists.launchpad.net' or
                                     self.email ==
                                     'ubuntu-devel-discuss@lists.ubuntu.com'))
            # "core scope" is not necessarily a word we use right now, but
            # we want to special case scopes which are written through our
            # vetted development process.
            self.is_core_scope = (self.click_pkgname.startswith('com.ubuntu.scopes.')
                                  and self.email ==
                                  'ubuntu-devel-discuss@lists.ubuntu.com')
            # "core snappy" is not necessarily a word we use right now, but
            # we want to special case scopes which are written through our
            # vetted development process.
            self.is_core_snappy = (self.click_pkgname.startswith('com.ubuntu.snappy.')
                                   and self.email ==
                                   'ubuntu-devel-discuss@lists.ubuntu.com')
        else:
            self.email = None
            self.is_core_app = False
            self.is_core_scope = False
            self.is_core_snappy = False

        self._list_all_compiled_binaries()

        self.known_hooks = ['account-application',
                            'account-provider',
                            'account-qml-plugin',
                            'account-service',
                            'apparmor',
                            'apparmor-profile',
                            'bin-path',
                            'content-hub',
                            'desktop',
                            'framework',
                            'pay-ui',
                            'push-helper',
                            'scope',
                            'snappy-systemd',
                            'urls']

        self.redflagged_hooks = ['framework',
                                 'pay-ui',
                                 'apparmor-profile',
                                 ]

        # Valid values for 'type' in packaging yaml
        # - app
        # - framework
        # - oem
        self.snappy_valid_types = ['app',
                                   'framework',
                                   # 'framework-policy',  # TBI
                                   # 'oem',               # TBI
                                   ]
        self.snappy_redflagged_types = ['framework',
                                        # 'oem',           # TBI
                                        ]

        if overrides is None:
            overrides = {}
        self.overrides = overrides

    def _list_control_files(self):
        '''List all control files with their full path.'''
        for i in CONTROL_FILE_NAMES:
            self.control_files[i] = os.path.join(self.unpack_dir,
                                                 "DEBIAN/%s" % i)

    def check_control_files(self):
        '''Check DEBIAN/* files'''
        for f in self.control_files:
            t = 'info'
            n = 'DEBIAN_has_%s' % os.path.basename(f)
            s = "OK"
            if not os.path.isfile(self.control_files[os.path.basename(f)]):
                t = 'error'
                s = "'%s' not found in DEBIAN/" % os.path.basename(f)
            self._add_result(t, n, s)

        found = []
        for f in sorted(glob.glob("%s/DEBIAN/*" % self.unpack_dir)):
            if os.path.basename(f) not in self.control_files:
                found.append(os.path.basename(f))
        t = 'info'
        n = 'DEBIAN_extra_files'
        s = 'OK'
        if len(found) > 0:
            t = 'warn'
            s = 'found extra files in DEBIAN/: %s' % ", ".join(found)
        self._add_result(t, n, s)

    def check_control(self):
        '''Check control()'''
        fh = self._extract_control_file()
        tmp = list(Deb822.iter_paragraphs(fh))
        t = 'info'
        n = 'control_structure'
        s = 'OK'
        if len(tmp) != 1:
            self._add_result('error', n,
                             'control malformed: too many paragraphs')
            return
        self._add_result(t, n, s)

        control = tmp[0]
        fields = ['Package',
                  'Version',
                  'Click-Version',
                  'Architecture',
                  'Maintainer',
                  'Installed-Size',
                  'Description']

        error = False
        for f in sorted(fields):
            t = 'info'
            n = 'control_has_%s' % f
            s = 'OK'
            if f not in control:
                t = 'error'
                s = "'%s' missing" % f
                error = True
            self._add_result(t, n, s)
        if error is True:
            return

        t = 'info'
        n = 'control_extra_fields'
        s = 'OK'
        found = []
        for k in sorted(control.keys()):
            if k not in fields:
                found.append(k)
        if len(found) > 0:
            self._add_result('error', n,
                             "found extra fields: '%s'" % (", ".join(found)))

        t = 'info'
        n = 'control_package_match'
        s = "OK"
        if self.manifest['name'] != self.click_pkgname:
            t = 'error'
            s = "Package=%s does not match manifest name=%s" % \
                (self.manifest['name'], self.click_pkgname)
        self._add_result(t, n, s)

        t = 'info'
        n = 'control_version_match'
        s = "OK"
        if self.manifest['version'] != self.click_version:
            t = 'error'
            s = "Version=%s does not match manifest version=%s" % \
                (self.manifest['version'], self.click_version)
        self._add_result(t, n, s)

        t = 'info'
        n = 'control_architecture_match'
        s = 'OK'
        if 'architecture' in self.manifest:
            if control['Architecture'] == "multi":
                if not isinstance(self.manifest['architecture'],
                                  (list, tuple)):
                    t = 'error'
                    s = 'If arch=multi, manifest architecture needs to ' + \
                        'list all the individual architectures.'
                elif list(filter(lambda a:
                                 a not in self.valid_compiled_architectures,
                                 self.manifest['architecture'])):
                    t = 'error'
                    s = 'If arch=multi, manifest architecture needs to ' + \
                        'comprise of only compiled architectures.'
            elif control['Architecture'] != self.manifest['architecture']:
                t = 'error'
                s = "Architecture=%s " % control['Architecture'] + \
                    "does not match manifest architecture=%s" % \
                    self.manifest['architecture']
        else:  # Lack of architecture in manifest is not an error
            t = 'info'
            s = 'OK: architecture not specified in manifest'
        self._add_result(t, n, s)

        t = 'info'
        n = 'control_maintainer_match'
        s = 'OK'
        if 'maintainer' in self.manifest:
            if control['Maintainer'] != self.manifest['maintainer']:
                t = 'error'
                s = "Maintainer=%s does not match manifest maintainer=%s" % \
                    (control['Maintainer'], self.manifest['maintainer'])
        else:
            t = 'warn'
            s = 'Skipped: maintainer not in manifest'
        self._add_result(t, n, s)

        # TODO: click currently sets the Description to be the manifest title.
        # Is this intended behavior?
        t = 'info'
        n = 'control_description_match'
        s = 'OK'
        if 'title' in self.manifest:
            if control['Description'] != self.manifest['title']:
                t = 'error'
                s = "Description=%s does not match manifest title=%s" % \
                    (control['Description'], self.manifest['title'])
        else:
            t = 'warn'
            s = 'Skipped: title not in manifest'
        self._add_result(t, n, s)

        t = 'info'
        n = 'control_click_version_up_to_date'
        s = 'OK'
        l = None

        if apt_pkg.version_compare(
                control['Click-Version'], MINIMUM_CLICK_FRAMEWORK_VERSION) < 0:
            t = 'error'
            s = "Click-Version is too old, has '%s', needs '%s' or newer" % (
                control['Click-Version'], MINIMUM_CLICK_FRAMEWORK_VERSION)
            l = 'http://askubuntu.com/questions/417366/what-does-lint-control-click-version-up-to-date-mean/417367'
        self._add_result(t, n, s, l)

        t = 'info'
        n = 'control_installed_size'
        s = 'OK'
        try:
            int(control['Installed-Size'])
        except TypeError:
            t = 'error'
            s = "invalid Installed-Size '%s'" % (control['Installed-Size'])
        self._add_result(t, n, s)

    def check_md5sums(self):
        '''Check md5sums()'''
        curdir = os.getcwd()
        fh = open_file_read(self.control_files["md5sums"])
        badsums = []
        os.chdir(self.unpack_dir)
        for line in fh.readlines():
            split_line = line.strip().split()
            fn = " ".join(split_line[1:])
            (rc, out) = cmd(['md5sum', fn])
            if line != out:
                badsums.append(fn)
        fh.close()
        os.chdir(curdir)

        t = 'info'
        n = 'md5sums'
        s = 'OK'
        if len(badsums) > 0:
            t = 'error'
            s = 'found bad checksums: %s' % ", ".join(badsums)
        self._add_result(t, n, s)

    def check_preinst(self):
        '''Check preinst()'''
        expected = '''#! /bin/sh
echo "Click packages may not be installed directly using dpkg."
echo "Use 'click install' instead."
exit 1
'''
        fh = open_file_read(self.control_files["preinst"])
        contents = ""
        for line in fh.readlines():
            contents += line
        fh.close()

        t = 'info'
        n = 'preinst'
        s = "OK"
        if contents != expected:
            t = 'error'
            s = "unexpected preinst contents"
        self._add_result(t, n, s)

    def check_hooks(self):
        '''Check click manifest hooks'''
        # Some checks are already handled in
        # cr_common.py:_verify_manifest_structure()

        # While we support multiple apps in the hooks db, we don't support
        # multiple apps specifying desktop hooks. Eg, it is ok to specify a
        # scope, an app and a push-helper, but it isn't ok to specify two apps
        t = 'info'
        n = 'hooks_multiple_apps'
        s = 'OK'
        count = 0
        for app in self.manifest['hooks']:
            if "desktop" in self.manifest['hooks'][app]:
                count += 1
        if count > 1:
            t = 'error'
            s = 'more than one desktop app specified in hooks'
        self._add_result(t, n, s)

        # Verify keys are well-formatted
        for app in self.manifest['hooks']:
            t = 'info'
            n = 'hooks_%s_valid' % app
            s = "OK"
            if not re.search(r'^[A-Za-z0-9+-.:~-]+$', app):
                t = 'error'
                s = "malformed application name: '%s'" % app
            self._add_result(t, n, s)

        # Verify we have the required hooks
        required = ['apparmor']
        for f in required:
            for app in self.manifest['hooks']:
                t = 'info'
                n = 'hooks_%s_%s' % (app, f)
                s = "OK"
                if f in list(filter(lambda a: a.startswith('account-'),
                   self.known_hooks)):
                    s = "OK (run check-online-accounts for more checks)"
                elif f == "apparmor":
                    s = "OK (run check-security for more checks)"
                elif f == "content-hub":
                    s = "OK (run check-content-hub for more checks)"
                elif f == "desktop":
                    s = "OK (run check-desktop for more checks)"
                elif f == "scope":
                    s = "OK (run check-scope for more checks)"
                elif f == "urls":
                    s = "OK (run check-url-dispatcher for more checks)"

                if f not in self.manifest['hooks'][app]:
                    # TODO: when have apparmor policy for account-provider and
                    #       account-qml-plugin, remove this conditional
                    if f == 'apparmor' and \
                       'apparmor-profile' in self.manifest['hooks'][app]:
                        # Don't require apparmor if have apparmor-profile
                        pass
                    elif f != 'apparmor' or \
                            len(self.manifest['hooks'][app]) != 2 or \
                            'account-provider' not in \
                            self.manifest['hooks'][app] or \
                            'account-qml-plugin' not in \
                            self.manifest['hooks'][app]:
                        t = 'error'
                        s = "'%s' hook not found for '%s'" % (f, app)
                self._add_result(t, n, s)

        mutually_exclusive = ['scope', 'desktop']
        for app in self.manifest['hooks']:
            t = 'info'
            n = 'exclusive_hooks_%s' % (app)
            s = "OK"
            found = []
            for i in mutually_exclusive:
                if i in self.manifest['hooks'][app]:
                    found.append(i)
            if len(found) > 1:
                t = 'error'
                s = "'%s' hooks should not be used together" % ", ".join(found)
            self._add_result(t, n, s)

        for app in self.manifest['hooks']:
            if "apparmor" in self.manifest['hooks'][app]:
                t = 'info'
                n = 'sdk_security_extension_%s' % (app)
                s = "OK"
                fn = self.manifest['hooks'][app]['apparmor']
                if not fn.endswith(".apparmor"):
                    t = 'info'
                    s = '%s does not end with .apparmor (ok if not using sdk)' % fn
                self._add_result(t, n, s)

    def check_hooks_unknown(self):
        '''Check if have any unknown hooks'''
        t = 'info'
        n = 'unknown hooks'
        s = 'OK'

        # Verify keys are well-formatted
        for app in self.manifest['hooks']:
            for hook in self.manifest['hooks'][app]:
                t = 'info'
                n = 'hooks_%s_%s_known' % (app, hook)
                s = "OK"
                if hook not in self.known_hooks:
                    t = 'warn'
                    s = "unknown hook '%s' in %s" % (hook, app)
                self._add_result(t, n, s)

    def check_hooks_redflagged(self):
        '''Check if have any redflagged hooks'''
        t = 'info'
        n = 'redflagged hooks'
        s = 'OK'

        for app in self.manifest['hooks']:
            found = []
            t = 'info'
            n = 'hooks_redflag_%s' % (app)
            s = "OK"
            manual_review = False
            for hook in self.manifest['hooks'][app]:
                if hook in self.redflagged_hooks:
                    found.append(hook)
            if len(found) > 0:
                t = 'error'
                s = "(MANUAL REVIEW) '%s' not allowed" % ", ".join(found)
                manual_review = True
            self._add_result(t, n, s, manual_review=manual_review)

    def check_external_symlinks(self):
        '''Check if symlinks in the click package go out to the system.'''
        t = 'info'
        n = 'external_symlinks'
        s = 'OK'

        external_symlinks = list(filter(lambda link: not
                                 os.path.realpath(link).startswith(
                                     self.unpack_dir), self.pkg_files))
        if external_symlinks:
            t = 'error'
            s = 'package contains external symlinks: %s' % \
                ', '.join(external_symlinks)
        self._add_result(t, n, s)

    def check_pkgname(self):
        '''Check package name valid'''
        p = self.manifest['name']
        # http://www.debian.org/doc/debian-policy/ch-controlfields.html
        t = 'info'
        n = 'pkgname_valid'
        s = "OK"
        if not self._verify_pkgname(p):
            t = 'error'
            s = "'%s' not properly formatted" % p
        self._add_result(t, n, s)

    def check_version(self):
        '''Check package version is valid'''
        # deb-version(5)
        t = 'info'
        n = 'version_valid'
        s = "OK"
        # From debian_support.py
        re_valid_version = re.compile(r'^((\d+):)?'              # epoch
                                      '([A-Za-z0-9.+:~-]+?)'     # upstream
                                      '(-([A-Za-z0-9+.~]+))?$')  # debian
        if not re_valid_version.match(self.click_version):
            t = 'error'
            s = "'%s' not properly formatted" % self.click_version
        self._add_result(t, n, s)

    def check_architecture(self):
        '''Check package architecture in DEBIAN/control is valid'''
        t = 'info'
        n = 'control_architecture_valid'
        s = 'OK'
        if self.click_arch not in self.valid_control_architectures:
            t = 'error'
            s = "not a valid architecture: %s" % self.click_arch
        self._add_result(t, n, s)

    def check_architecture_all(self):
        '''Check if actually architecture all'''
        t = 'info'
        n = 'control_architecture_valid_contents'
        s = 'OK'
        if self.click_arch != "all":
            self._add_result(t, n, s)
            return

        # look for compiled code
        x_binaries = []
        for i in self.pkg_bin_files:
            x_binaries.append(os.path.relpath(i, self.unpack_dir))
        if len(x_binaries) > 0:
            t = 'error'
            s = "found binaries for architecture 'all': %s" % \
                ", ".join(x_binaries)
        self._add_result(t, n, s)

    def check_architecture_specified_needed(self):
        '''Check if the specified architecture is actually needed'''
        t = 'info'
        n = 'control_architecture_specified_needed'
        s = 'OK'
        if self.click_arch == "all":
            s = "SKIPPED: architecture is 'all'"
            self._add_result(t, n, s)
            return

        if len(self.pkg_bin_files) == 0:
            t = 'warn'
            s = "Could not find compiled binaries for architecture '%s'" % \
                self.click_arch
        self._add_result(t, n, s)

    def check_maintainer(self):
        '''Check maintainer()'''
        t = 'info'
        n = 'maintainer_present'
        s = 'OK'
        if 'maintainer' not in self.manifest:
            s = 'required maintainer field not specified in manifest'
            self._add_result('error', n, s)
            return
        self._add_result(t, n, s)

        # Simple regex as used by python3-debian. If we wanted to be more
        # thorough we could use email_re from django.core.validators
        t = 'info'
        n = 'maintainer_format'
        s = 'OK'
        if self.manifest['maintainer'] == "":
            self._add_result('error', n, 'invalid maintainer (empty), (should be '
                                         'like "Joe Bloggs <joe.bloggs@isp.com>")',
                             'http://askubuntu.com/questions/417351/what-does-lint-maintainer-format-mean/417352')
            return
        elif not self._verify_maintainer(self.manifest['maintainer']):
            self._add_result('error', n,
                             'invalid format for maintainer: %s (should be '
                             'like "Joe Bloggs <joe.bloggs@isp.com>")' %
                             self.manifest['maintainer'],
                             'http://askubuntu.com/questions/417351/what-does-lint-maintainer-format-mean/417352')
            return
        self._add_result(t, n, s)

    def check_title(self):
        '''Check title()'''
        t = 'info'
        n = 'title_present'
        s = 'OK'
        if 'title' not in self.manifest:
            s = 'required title field not specified in manifest'
            self._add_result('error', n, s)
            return
        self._add_result(t, n, s)

        t = 'info'
        n = 'title'
        s = 'OK'
        pkgname_base = self.click_pkgname.split('.')[-1]
        if len(self.manifest['title']) < len(pkgname_base):
            t = 'info'
            s = "'%s' may be too short" % self.manifest['title']
        self._add_result(t, n, s)

    def check_description(self):
        '''Check description()'''
        t = 'info'
        n = 'description_present'
        s = 'OK'
        if 'description' not in self.manifest:
            s = 'required description field not specified in manifest'
            self._add_result('error', n, s)
            return
        self._add_result(t, n, s)

        t = 'info'
        n = 'description'
        s = 'OK'
        pkgname_base = self.click_pkgname.split('.')[-1]
        if len(self.manifest['description']) < len(pkgname_base):
            t = 'warn'
            if self.is_snap and (self.manifest['description'] == '\n' or
                                 self.manifest['description'] == ''):
                s = "manifest description is empty. Is meta/readme.md " + \
                    "formatted correctly?"
            else:
                s = "'%s' is too short" % self.manifest['description']

        self._add_result(t, n, s)

    def check_framework(self):
        '''Check framework()'''
        n = 'framework'
        l = "http://askubuntu.com/questions/460512/what-framework-should-i-use-in-my-manifest-file"
        framework_overrides = self.overrides.get('framework', {})
        frameworks = Frameworks(overrides=framework_overrides)
        if self.manifest['framework'] in frameworks.AVAILABLE_FRAMEWORKS:
            t = 'info'
            s = 'OK'
            self._add_result(t, n, s)
            # If it's an available framework, we're done checking
            return
        elif self.manifest['framework'] in frameworks.DEPRECATED_FRAMEWORKS:
            t = 'warn'
            s = "'%s' is deprecated. Please use a newer framework" % \
                self.manifest['framework']
            self._add_result(t, n, s, l)
            return
        elif self.manifest['framework'] in frameworks.OBSOLETE_FRAMEWORKS:
            t = 'error'
            s = "'%s' is obsolete. Please use a newer framework" % \
                self.manifest['framework']
            self._add_result(t, n, s, l)
            return
        else:
            # None of the above checks triggered, this is an unknown framework
            t = 'error'
            s = "'%s' is not a supported framework" % \
                self.manifest['framework']
            self._add_result(t, n, s, l)

    def check_click_local_extensions(self):
        '''Report any click local extensions'''
        t = 'info'
        n = 'click_local_extensions'
        s = 'OK'
        found = []
        for k in sorted(self.manifest):
            if k.startswith('x-'):
                found.append(k)

        # Some local extensions are ok for core apps, so just skip them
        if self.is_core_app:
            for i in ['x-source', 'x-test']:
                if i in found:
                    found.remove(i)

        if len(found) > 0:
            t = 'warn'
            plural = ""
            if len(found) > 1:
                plural = "s"
            s = 'found unofficial extension%s: %s' % (plural, ', '.join(found))
        self._add_result(t, n, s)

    def check_package_filename(self):
        '''Check filename of package'''
        tmp = os.path.basename(self.click_package).split('_')
        click_package_bn = os.path.basename(self.click_package)
        t = 'info'
        n = 'package_filename_format'
        s = 'OK'
        if len(tmp) != 3:
            t = 'warn'
            s = "'%s' not of form $pkgname_$version_$arch.[click|snap]" % \
                click_package_bn
        self._add_result(t, n, s)

        #  handle $pkgname.click or $pkgname.snap
        if self.click_package.endswith('.snap'):
            pkgname = tmp[0].partition('.snap')[0]
        else:
            pkgname = tmp[0].partition('.click')[0]
        t = 'info'
        n = 'package_filename_pkgname_match'
        s = 'OK'
        l = None
        if pkgname != self.click_pkgname:
            if pkgname.startswith('com.ubuntu.snappy.') or \
               click_package_bn.startswith('com.ubuntu.snappy.'):
                s = "OK (store snappy workaround)"
            else:
                t = 'error'
                s = "'%s' != '%s' from DEBIAN/control" % (pkgname,
                                                          self.click_pkgname)
                l = 'http://askubuntu.com/questions/417361/what-does-lint-package-filename-pkgname-match-mean'
        self._add_result(t, n, s, l)

        # check if namespaces matches with filename
        t = 'info'
        n = 'package_filename_matches_namespace'
        s = 'OK'
        namespace_bits = self.click_pkgname.split('.')[:-1]
        len_namespace = len(namespace_bits)
        pkgname_bits = pkgname.split('.')[:len_namespace]
        if namespace_bits != pkgname_bits:
            t = 'error'
            s = "Package name '%s' does not match namespace '%s'." % \
                ('.'.join(namespace_bits), '.'.join(pkgname_bits))
        self._add_result(t, n, s)

        t = 'info'
        n = 'package_filename_version_match'
        s = 'OK'
        l = None
        if len(tmp) >= 2:
            #  handle $pkgname_$version.click or $pkgname_$version.snap
            if self.click_package.endswith('.snap'):
                version = tmp[1].partition('.snap')[0]
            else:
                version = tmp[1].partition('.click')[0]
            if version != self.click_version:
                t = 'error'
                s = "'%s' != '%s' from DEBIAN/control" % (version,
                                                          self.click_version)
                l = 'http://askubuntu.com/questions/417384/what-does-lint-package-filename-version-match-mean/417385'
        else:
            t = 'warn'
            s = "could not determine version from '%s'" % \
                os.path.basename(self.click_package)
        self._add_result(t, n, s, l)

        t = 'info'
        n = 'package_filename_arch_valid'
        s = 'OK'
        if len(tmp) >= 3:
            if self.click_package.endswith('.snap'):
                arch = tmp[2].partition('.snap')[0]
            else:
                arch = tmp[2].partition('.click')[0]
            if arch == "unknown":
                # short-circuit here since the appstore doesn't determine
                # the version yet
                t = 'info'
                s = "SKIP: architecture 'unknown'"
                self._add_result(t, n, s)
                return
            if arch not in self.valid_control_architectures:
                t = 'warn'
                s = "not a valid architecture: %s" % arch
        else:
            t = 'warn'
            s = "could not determine architecture from '%s'" % \
                os.path.basename(self.click_package)
        self._add_result(t, n, s)

        t = 'info'
        n = 'package_filename_arch_match'
        s = 'OK'
        if len(tmp) >= 3:
            if self.click_package.endswith('.snap'):
                arch = tmp[2].partition('.snap')[0]
            else:
                arch = tmp[2].partition('.click')[0]
            if arch != self.click_arch:
                t = 'error'
                s = "'%s' != '%s' from DEBIAN/control" % (arch,
                                                          self.click_arch)
        else:
            t = 'warn'
            s = "could not determine architecture from '%s'" % \
                os.path.basename(self.click_package)
        self._add_result(t, n, s)

    def check_vcs(self):
        '''Check for VCS files in the click package'''
        t = 'info'
        n = 'vcs_files'
        s = 'OK'
        found = []
        for d in self.vcs_dirs:
            entries = glob.glob("%s/%s" % (self.unpack_dir, d))
            if len(entries) > 0:
                for i in entries:
                    found.append(os.path.relpath(i, self.unpack_dir))
        if len(found) > 0:
            t = 'warn'
            s = 'found VCS files in package: %s' % ", ".join(found)
        self._add_result(t, n, s)

    def check_click_in_package(self):
        '''Check for *.click files in the toplevel click package'''
        t = 'info'
        n = 'click_files'
        s = 'OK'
        found = []
        entries = glob.glob("%s/*.click" % self.unpack_dir)
        if len(entries) > 0:
            for i in entries:
                found.append(os.path.relpath(i, self.unpack_dir))
        if len(found) > 0:
            t = 'warn'
            s = 'found click packages in toplevel dir: %s' % ", ".join(found)
        self._add_result(t, n, s)

    def check_contents_for_hardcoded_paths(self):
        '''Check for known hardcoded paths.'''
        PATH_BLACKLIST = ["/opt/click.ubuntu.com/"]
        t = 'info'
        n = 'hardcoded_paths'
        s = 'OK'
        for dirpath, dirnames, filenames in os.walk(self.unpack_dir):
            for filename in filenames:
                full_fn = os.path.join(dirpath, filename)
                (rc, out) = cmd(['file', '-b', full_fn])
                if 'text' not in out:
                    continue
                try:
                    lines = open_file_read(full_fn).readlines()
                    for bad_path in PATH_BLACKLIST:
                        if list(filter(lambda line: bad_path in line, lines)):
                            t = 'error'
                            s = "Hardcoded path '%s' found in '%s'." % (
                                bad_path, full_fn)
                except UnicodeDecodeError:
                    pass
        self._add_result(t, n, s)

    def _verify_architecture(self, my_dict, test_str):
        t = 'info'
        n = '%s_architecture_valid' % test_str
        s = 'OK'
        if 'architecture' not in my_dict:
            s = 'OK (architecture not specified)'
            self._add_result(t, n, s)
            return

        archs_list = list(self.valid_control_architectures)
        archs_list.remove("multi")

        if isinstance(my_dict['architecture'], str) and \
           my_dict['architecture'] not in archs_list:
            t = 'error'
            s = "not a valid architecture: %s" % my_dict['architecture']
        elif isinstance(my_dict['architecture'], list):
            archs_list.remove("all")
            bad_archs = []
            for a in my_dict['architecture']:
                if a not in archs_list:
                    bad_archs.append(a)
                if len(bad_archs) > 0:
                    t = 'error'
                    s = "not valid multi architecture: %s" % \
                        ",".join(bad_archs)
        self._add_result(t, n, s)

    def check_manifest_architecture(self):
        '''Check package architecture in manifest is valid'''
        self._verify_architecture(self.manifest, "manifest")

    def _verify_icon(self, my_dict, test_str):
        t = 'info'
        n = '%s_icon_present' % test_str
        s = 'OK'
        if 'icon' not in my_dict:
            s = 'Skipped, optional icon not present'
            self._add_result(t, n, s)
            return
        self._add_result(t, n, s)

        t = 'info'
        n = '%s_icon_empty' % test_str
        s = 'OK'
        if len(my_dict['icon']) == 0:
            t = 'error'
            s = "icon entry is empty"
            return
        self._add_result(t, n, s)

        t = 'info'
        n = '%s_icon_absolute_path' % test_str
        s = 'OK'
        if my_dict['icon'].startswith('/'):
            t = 'error'
            s = "icon entry '%s' should not specify absolute path" % \
                my_dict['icon']
        self._add_result(t, n, s)

    def check_icon(self):
        '''Check icon()'''
        self._verify_icon(self.manifest, "manifest")

    def check_snappy_name(self):
        '''Check package name'''
        if not self.is_snap:
            return

        t = 'info'
        n = 'snappy_name_valid'
        s = 'OK'
        if 'name' not in self.pkg_yaml:
            t = 'error'
            s = "could not find 'name' in yaml"
        elif not self._verify_pkgname(self.pkg_yaml['name']):
            t = 'error'
            s = "malformed 'name': '%s'" % self.pkg_yaml['name']
        self._add_result(t, n, s)

    def check_snappy_version(self):
        '''Check package version'''
        if not self.is_snap:
            return

        t = 'info'
        n = 'snappy_version_valid'
        s = 'OK'
        if 'version' not in self.pkg_yaml:
            t = 'error'
            s = "could not find 'version' in yaml"
        elif not self._verify_pkgversion(self.pkg_yaml['version']):
            t = 'error'
            s = "malformed 'version': '%s'" % self.pkg_yaml['version']
        self._add_result(t, n, s)

    def check_snappy_type(self):
        '''Check type'''
        if not self.is_snap:
            return

        t = 'info'
        n = 'snappy_type_valid'
        s = 'OK'
        if 'type' not in self.pkg_yaml:
            s = 'OK (skip missing)'
        elif self.pkg_yaml['type'] not in self.snappy_valid_types:
            t = 'error'
            s = "unknown 'type': '%s'" % self.pkg_yaml['type']
        self._add_result(t, n, s)

    def check_snappy_type_redflagged(self):
        '''Check if snappy type is redflagged'''
        if not self.is_snap:
            return

        t = 'info'
        n = 'snappy_type_redflag'
        s = "OK"
        manual_review = False
        if 'type' not in self.pkg_yaml:
            s = 'OK (skip missing)'
        elif self.pkg_yaml['type'] in self.snappy_redflagged_types:
            t = 'error'
            s = "(MANUAL REVIEW) type '%s' not allowed" % self.pkg_yaml['type']
            manual_review = True
        self._add_result(t, n, s, manual_review=manual_review)

    def check_snappy_vendor(self):
        '''Check package vendor'''
        if not self.is_snap:
            return

        t = 'info'
        n = 'snappy_vendor_valid'
        s = 'OK'
        if 'vendor' not in self.pkg_yaml:
            s = "OK (skip missing)"
        elif not self._verify_maintainer(self.pkg_yaml['vendor']):
            t = 'error'
            s = "malformed 'vendor': '%s'" % self.pkg_yaml['vendor']
        self._add_result(t, n, s)

    def check_snappy_icon(self):
        '''Check icon()'''
        if not self.is_snap:
            return

        self._verify_icon(self.pkg_yaml, "package_yaml")

    def check_snappy_architecture(self):
        '''Check package architecture in package.yaml is valid'''
        if not self.is_snap:
            return

        self._verify_architecture(self.pkg_yaml, "package yaml")

    def check_snappy_unknown_entries(self):
        '''Check for any unknown fields'''
        if not self.is_snap:
            return

        t = 'info'
        n = 'snappy_unknown'
        s = 'OK'
        unknown = []
        for f in self.pkg_yaml:
            if f not in self.snappy_required + self.snappy_optional:
                unknown.append(f)
        if len(unknown) > 0:
            t = 'warn'
            s = "unknown entries in package.yaml: '%s'" % (",".join(unknown))
            obsoleted = ['maintainer', 'ports']
            tmp = list(set(unknown) & set(obsoleted))
            if len(tmp) > 0:
                t = 'error'
                s += " (%s obsoleted)" % ",".join(tmp)
        self._add_result(t, n, s)

    def _extract_readme_md(self):
        '''Extract meta/readme.md'''
        contents = None
        readme = os.path.join(self.unpack_dir, "meta/readme.md")
        if os.path.exists(readme):
            fh = open_file_read(readme)
            contents = fh.read()
        return contents

    def check_snappy_readme_md(self):
        '''Check package architecture in package.yaml is valid'''
        if not self.is_snap:
            return

        contents = self._extract_readme_md()

        t = 'info'
        n = 'snappy_readme.md'
        s = 'OK'
        if contents is None:
            t = 'error'
            s = 'meta/readme.md does not exist'
            self._add_result(t, n, s)
            return
        self._add_result(t, n, s)

        t = 'info'
        n = 'snappy_readme.md_length'
        s = 'OK'
        pkgname_base = self.pkg_yaml['name'].split('.')[0]
        if len(contents) < len(pkgname_base):
            t = 'warn'
            s = "meta/readme.md is too short"
        self._add_result(t, n, s)
