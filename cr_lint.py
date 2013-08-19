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

from cr_common import ClickReview
import os
import re

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
        self._add_result('warn', 'control_extrafiles', 'TODO')

    def check_manifest(self):
        '''Check click manifest'''
        required = ['name', 'version', 'maintainer', 'title', 'framework']
        for f in required:
            t = 'info'
            n = 'manifest_has_%s' % f
            s = "OK"
            if f not in self.manifest:
                t = 'error'
                s = "'%s' entry not found in manifest" % f
            self._add_result(t, n, s)
        self._add_result('warn', 'manifest_extrakeys', 'TODO')

    def check_control(self):
        '''Check control()'''
        self._add_result('info', 'control', 'TODO')
        # TODO: perform automated checks

    def check_md5sums(self):
        '''Check md5sums()'''
        self._add_result('warn', 'md5sums', 'TODO')
        # TODO: perform automated checks

    def check_preinst(self):
        '''Check preinst()'''
        self._add_result('warn', 'preinst', 'TODO')
        # TODO: perform automated checks

    def check_hooks(self):
        '''Check click manifest hooks'''
        if 'hooks' not in self.manifest:
            self._add_result('error', 'hooks',
                             "could not find 'hooks' in manifest")
            return

        if len(self.manifest['hooks'].keys()) < 0:
            self._add_result('error', 'hooks',
                             "could not find app key in hooks")
            return

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
                elif f == "desktopr":
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
            t =' error'
            s = "'%s' does not match '%s' from filename '%s'" % \
                (p, self.click_pkgname,
                 os.path.basename(self.click_package))
        self._add_result(t, n, s)

        # http://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Source
        t = 'info'
        n = 'pkgname_valid'
        s = "OK"
        if not re.search(r'^[a-z0-9][a-z0-9\+\-\.]+$', p):
            t =' error'
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
            t =' error'
            s = "'%s' not properly formatted" % self.click_version
        self._add_result(t, n, s)

    def check_maintainer(self):
        '''Check maintainer()'''
        self._add_result('warn', 'maintainer_format', 'TODO')
        self._add_result('warn', 'maintainer_domain', 'TODO: non-Ubuntu pkgname matches reverse domain of email')

    def check_title(self):
        '''Check title()'''
        self._add_result('warn', 'title', 'TODO')

    def check_framework(self):
        '''Check framework()'''
        self._add_result('warn', 'framework', 'TODO')
