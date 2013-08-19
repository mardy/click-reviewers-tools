'''cr_lint.py: click lint checks'''
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

from cr_common import ClickReview, open_file_read, cmd
import glob
import os
import re
from debian.deb822 import Deb822

class ClickReviewLint(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "lint")
        self.control_files = dict()
        files = ["control", "manifest", "md5sums", "preinst"]
        for i in files:
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
        fh = open_file_read(self.control_files["control"])
        tmp = list(Deb822.iter_paragraphs(fh.readlines()))
        fh.close()

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
        s = 'OK'
        if control['Package'] != self.click_pkgname:
            t = 'error'
            s = "Package=%s does not match package name=%s" % \
                (control['Package'], self.click_pkgname)
        self._add_result(t, n, s)

        t = 'info'
        n = 'control_version_match'
        s = 'OK'
        if control['Version'] != self.click_version:
            t = 'error'
            s = "Version=%s does not match package version=%s" % \
                (control['Version'], self.click_version)
        self._add_result(t, n, s)

        t = 'info'
        n = 'control_maintainer_match'
        s = 'OK'
        if control['Maintainer'] != self.manifest['maintainer']:
            t = 'error'
            s = "Maintainer=%s does not match manifest maintainer=%s" % \
                (control['Maintainer'], self.manifest['maintainer'])
        self._add_result(t, n, s)

        t = 'info'
        n = 'control_description_match'
        s = 'OK'
        if control['Description'] != self.manifest['title']:
            t = 'error'
            s = "Description=%s does not match manifest title=%s" % \
                (control['Description'], self.manifest['title'])
        self._add_result(t, n, s)

        valid_click_versions = ['0.1', '0.2', '0.3']
        t = 'info'
        n = 'control_click_version'
        s = 'OK'
        if control['Click-Version'] not in valid_click_versions:
            t = 'error'
            s = "invalid Click-Version '%s'" % (control['Click-Version'])
        self._add_result(t, n, s)

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
        for line in fh.readlines():
            (sum, fn) = line.strip().split()
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

        # We don't support multiple apps in 13.10
        if len(self.manifest['hooks'].keys()) != 1:
            self._add_result('error', 'hooks',
                             "more than one app key specified in hooks")
            return

        required = ['apparmor', 'desktop']
        for f in required:
            for app in self.manifest['hooks']:
                t = 'info'
                n = 'hooks_%s_%s' % (app, f)
                s = "OK"
                if f == "apparmor":
                    s = "OK (run check-security for more checks)"
                elif f == "desktop":
                    s = "OK (run check-desktop for more checks)"

                if f not in self.manifest['hooks'][app]:
                    t = 'error'
                    s = "'%s' hook not found for '%s'" % (f, app)
                self._add_result(t, n, s)

    def check_pkgname(self):
        '''Check package name matches manifest'''
        p = self.manifest['name']

        t = 'info'
        n = 'pkgname_match'
        s = "OK"
        if p != self.click_pkgname:
            t = 'error'
            s = "'%s' does not match '%s' from filename '%s'" % \
                (p, self.click_pkgname,
                 os.path.basename(self.click_package))
        self._add_result(t, n, s)

        # http://www.debian.org/doc/debian-policy/ch-controlfields.html
        t = 'info'
        n = 'pkgname_valid'
        s = "OK"
        if not re.search(r'^[a-z0-9][a-z0-9\+\-\.]+$', p):
            t = 'error'
            s = "'%s' not properly formatted" % p
        self._add_result(t, n, s)

    def check_version(self):
        '''Check package version matches manifest'''
        # deb-version(5)
        t = 'info'
        n = 'version_valid'
        s = "OK"
        # This regex isn't perfect, but should be good enough
        if not re.search(r'^[0-9][0-9a-zA-Z+\.~:\-]*$', self.click_version):
            t = 'error'
            s = "'%s' not properly formatted" % self.click_version
        self._add_result(t, n, s)

    def check_maintainer(self):
        '''Check maintainer()'''
        # Simple regex as used by python3-debian. If we wanted to be more
        # thorough we could use email_re from django.core.validators
        t = 'info'
        n = 'maintainer_format'
        s = 'OK'
        if not re.search(r"^(.*)\s+<(.*@.*)>$", self.manifest['maintainer']):
            self._add_result('error', n, 'invalid format for maintainer: %s' %
                             self.manifest['maintainer'])
            return
        self._add_result(t, n, s)

        t = 'info'
        n = 'maintainer_domain'
        s = 'OK'
        default = "com.ubuntu.developer"

        if self.click_pkgname.startswith(default + '.'):
            # com.ubuntu.developer is our appstore-- people can use their own
            # addresses
            s = "OK (package domain=%s)" % default
        else:
            email = self.manifest['maintainer'].partition('<')[2].rstrip('>')
            domain_rev = email.partition('@')[2].split('.')
            domain_rev.reverse()
            print (domain_rev)

            pkg_domain_rev = self.click_pkgname.split('.')
            if len(domain_rev) < 2: # don't impersonate .com
                t = 'error'
                s = "(MANUAL REVIEW) email domain too short: '%s'" % email
            elif len(domain_rev) >= len(pkg_domain_rev): # also '=' to leave
                                                         # room for app name
                t = 'error'
                s = "(MANUAL REVIEW) email domain too long '%s' " % email + \
                    "for app name '%s'" % ".".join(pkg_domain_rev)
            elif domain_rev == pkg_domain_rev[:len(domain_rev)]:
                s = "OK (email=%s, package domain=%s" % (email,
                    ".".join(pkg_domain_rev))
            else:
                t = 'error'
                s = "email=%s does not match package domain=%s" %  (email,
                    ".".join(pkg_domain_rev))
        self._add_result(t, n, s)

    def check_title(self):
        '''Check title()'''
        t = 'info'
        n = 'title'
        s = 'OK'
        pkgname_base = self.click_pkgname.split('.')[-1]
        if len(self.manifest['title']) < len(pkgname_base):
            t = 'warn'
            s = "'%s' is too short" % self.manifest['title']
        self._add_result(t, n, s)

    def check_description(self):
        '''Check description()'''
        t = 'info'
        n = 'description'
        s = 'OK'
        pkgname_base = self.click_pkgname.split('.')[-1]
        if len(self.manifest['description']) < len(pkgname_base):
            t = 'warn'
            s = "'%s' is too short" % self.manifest['description']
        self._add_result(t, n, s)


    def check_framework(self):
        '''Check framework()'''
        # FIXME: autodetect these
        valid_frameworks = ['ubuntu-sdk-13.10']
        t = 'info'
        n = 'framework'
        s = 'OK'
        if self.manifest['framework'] not in valid_frameworks:
            t = 'error'
            s = "'%s' is not a supported framework" % \
                self.manifest['framework']
        self._add_result(t, n, s)

