'''cr_functional.py: click functional'''
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
import binascii
import os
import re

from clickreviews.cr_common import ClickReview, open_file_read

# TODO: for QML apps, see if i18n.domain('%s') matches X-Ubuntu-Gettext-Domain
#       compiled apps can use organizationName to match X-Ubuntu-Gettext-Domain


class ClickReviewFunctional(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        ClickReview.__init__(self, fn, "functional", overrides=overrides)

        self.qml_files = []
        for i in self.pkg_files:
            if i.endswith(".qml"):
                self.qml_files.append(i)

        self._list_all_compiled_binaries()

    def check_applicationName(self):
        '''Check applicationName matches click manifest'''
        if self.manifest is None:
            return

        t = 'info'
        n = self._get_check_name('qml_applicationName_matches_manifest')
        s = "OK"
        l = None

        # find file with MainView in the QML
        mv = '\s*MainView\s*(\s+{)?'
        pat_mv = re.compile(r'\n%s' % mv)
        qmls = dict()

        for i in self.qml_files:
            qml = open_file_read(i).read()
            if pat_mv.search(qml):
                qmls[i] = qml

        # LP: #1256841 - QML apps with C++ using QSettings shouldn't
        # typically set applicationName in the QML
        for i in self.pkg_bin_files:
            f = open(i, 'rb')
            data = str(binascii.b2a_qp(f.read()))
            f.close()
            if 'QSettings' in data:
                s = "OK (binary uses QSettings)"
                self._add_result(t, n, s)
                return

        if len(self.qml_files) == 0:
            s = "OK (not QML)"
            self._add_result(t, n, s)
            return
        elif len(qmls) == 0:
            s = "SKIP: could not find MainView in QML files"
            self._add_result(t, n, s)
            return

        pat_mvl = re.compile(r'^%s' % mv)
        pat_appname = re.compile(r'^\s*applicationName\s*:\s*["\']')

        ok = False
        appnames = dict()
        for k in qmls.keys():
            in_mainview = False
            for line in qmls[k].splitlines():
                if in_mainview and pat_appname.search(line):
                    appname = line.split(':', 1)[1].strip('"\' \t\n\r\f\v;')
                    appnames[os.path.relpath(k, self.unpack_dir)] = appname
                    if appname == self.click_pkgname:
                        ok = True
                        break
                elif pat_mvl.search(line):
                    in_mainview = True
                if ok:
                    break

        if len(appnames) == 0 or not ok:
            if len(self.pkg_bin_files) == 0:
                t = "warn"
                l = 'http://askubuntu.com/questions/417371/what-does-functional-qml-applicationname-matches-manifest-mean/417372'

            if len(appnames) == 0:
                s = "could not find applicationName in: %s" % \
                    ", ".join(list(map(
                                   lambda x: os.path.relpath(x,
                                                             self.unpack_dir),
                                   qmls)
                                   ))
            else:  # not ok
                s = "click manifest name '%s' not found in: " % \
                    self.click_pkgname + "%s" % \
                    ", ".join(list(map(
                                   lambda x: "%s ('%s')" % (x, appnames[x]),
                                   appnames)
                                   ))

            if len(self.pkg_bin_files) == 0:
                s += ". Application may not work properly when confined."
            else:
                s += ". May be ok (detected as compiled application)."

        self._add_result(t, n, s, l)

    def check_qtwebkit(self):
        '''Check that QML applications don't use QtWebKit'''
        t = 'info'
        n = self._get_check_name('qml_application_uses_QtWebKit')
        s = "OK"
        l = None

        qmls = []
        pat_mv = re.compile(r'\n\s*import\s+QtWebKit')
        for i in self.qml_files:
            qml = open_file_read(i).read()
            if pat_mv.search(qml):
                qmls.append(os.path.relpath(i, self.unpack_dir))

        if len(qmls) > 0:
            t = 'warn'
            s = "Found files that use unsupported QtWebKit (should use " + \
                "UbuntuWebview (Ubuntu.Components.Extras.Browser >= " + \
                "0.2) or Oxide instead): %s" % " ,".join(qmls)
            l = "http://askubuntu.com/questions/417342/what-does-functional-qml-application-uses-qtwebkit-mean/417343"

        self._add_result(t, n, s, l)

        t = 'info'
        n = self._get_check_name('qml_application_uses_UbuntuWebView_0.2')
        s = "OK"
        l = None

        if self.manifest is not None and \
                self.manifest['framework'] == "ubuntu-sdk-13.10":
            s = "SKIPPED (Oxide not available in ubuntu-sdk-13.10)"
        else:
            qmls = []
            pat_mv = re.compile(r'\n\s*import\s+Ubuntu\.Components\.Extras\.Browser\s+0\.1\s*\n')
            for i in self.qml_files:
                qml = open_file_read(i).read()
                if pat_mv.search(qml):
                    qmls.append(os.path.relpath(i, self.unpack_dir))

            if len(qmls) > 0:
                t = 'warn'
                s = "Found files that use unsupported QtWebKit via " + \
                    "'Ubuntu.Components.Extras.Browser 0.1' (should use " + \
                    "Ubuntu.Components.Extras.Browser >= 0.2 or " + \
                    "Oxide instead): %s" % " ,".join(qmls)
                l = "http://askubuntu.com/questions/417342/what-does-functional-qml-application-uses-qtwebkit-mean/417343"

        self._add_result(t, n, s, l)

    def check_friends(self):
        '''Check that QML applications don't use deprecated Friends API'''
        t = 'info'
        n = self._get_check_name('qml_application_uses_friends')
        s = "OK"
        l = None

        qmls = []
        pat_mv = re.compile(r'\n\s*import\s+Friends')
        for i in self.qml_files:
            qml = open_file_read(i).read()
            if pat_mv.search(qml):
                qmls.append(os.path.relpath(i, self.unpack_dir))

        if len(qmls) > 0:
            t = 'error'
            s = "Found files that use deprecated Friends API: %s" % " ,".join(qmls)
            l = "http://askubuntu.com/questions/497551/what-does-functional-qml-application-uses-friends-mean"

        self._add_result(t, n, s, l)
