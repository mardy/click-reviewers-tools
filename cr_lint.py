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

    def verify_control_files(self):
        '''Verify DEBIAN/* files'''
        control = os.path.join(self.unpack_dir, "DEBIAN/control")
        manifest = os.path.join(self.unpack_dir, "DEBIAN/manifest")
        md5sums = os.path.join(self.unpack_dir, "DEBIAN/md5sums")
        preinst = os.path.join(self.unpack_dir, "DEBIAN/preinst")

        for f in [control, manifest, md5sums, preinst]:
            t = 'info'
            n = 'DEBIAN_has_%s' % (os.path.basename(f))
            s = "OK"
            if not os.path.isfile(f):
                t = 'error'
                s = "'%s' not found in DEBIAN/" % (os.path.basename(f))
            self._add_result(t, n, s)
        self._add_result('warn', 'extrafiles', 'TODO')

    def verify_manifest(self):
        '''Verify click manifest'''
        required = ['name', 'version', 'maintainer', 'title', 'framework']
        for f in required:
            t = 'info'
            n = 'manifest_has_%s' % f
            s = "OK"
            if f not in self.manifest:
                t = 'error'
                s = "'%s' entry not found in manifest" % f
            self._add_result(t, n, s)

    def verify_control(self):
        '''Verify control()'''
        self._add_result('warn', 'control', 'TODO')

    def verify_md5sums(self):
        '''Verify md5sums()'''
        self._add_result('warn', 'md5sums', 'TODO')

    def verify_preinst(self):
        '''Verify preinst()'''
        self._add_result('warn', 'preinst', 'TODO')

    def verify_hooks(self):
        '''Verify click manifest hooks'''
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
                if f not in self.manifest['hooks'][app]:
                    t = 'error'
                    s = "'%s' hook not found for '%s'" % (f, app)
                self._add_result(t, n, s)

    def verify_pkgname(self):
        '''Verify package name matches manifest'''
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

    def verify_version(self):
        '''Verify package version matches manifest'''
        # deb-version(5)
        t = 'info'
        n = 'version_valid'
        s = "OK"
        # This regex isn't perfect, but should be good enough
        if not re.search(r'^[0-9][0-9a-zA-Z+\.~:\-]*$', self.click_version):
            t =' error'
            s = "'%s' not properly formatted" % self.click_version
        self._add_result(t, n, s)

    def verify_maintainer(self):
        '''Verify maintainer()'''
        self._add_result('warn', 'maintainer', 'TODO')

    def verify_title(self):
        '''Verify title()'''
        self._add_result('warn', 'title', 'TODO')

    def verify_framework(self):
        '''Verify framework()'''
        self._add_result('warn', 'framework', 'TODO')

    def do_checks(self):
        '''Perform lint checks'''
        self.verify_control_files()
        self.verify_manifest()
        self.verify_md5sums()
        self.verify_control()
        self.verify_preinst()
        self.verify_hooks()
        self.verify_pkgname()
        self.verify_version()
        self.verify_maintainer()
        self.verify_title()
        self.verify_framework()
