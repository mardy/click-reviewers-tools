'''cr_functional.py: click functional'''
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
import binascii
import magic
import os
import re

from clickreviews.cr_common import ClickReview, open_file_read

# TODO: for QML apps, see if i18n.domain('%s') matches X-Ubuntu-Gettext-Domain
#       compiled apps can use organizationName to match X-Ubuntu-Gettext-Domain


class ClickReviewFunctional(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "functional")
        self.mime = magic.open(magic.MAGIC_MIME)
        self.mime.load()

        self.qml_files = []
        self.bin_files = []
        for i in self.pkg_files:
            if i.endswith(".qml"):
                self.qml_files.append(i)
            else:
                res = self.mime.file(i)
                if res in ['application/x-executable; charset=binary',
                           'application/x-sharedlib; charset=binary']:
                     self.bin_files.append(i)

    def check_applicationName(self):
        '''Check applicationName matches click manifest'''
        t = 'info'
        n = 'qml_applicationName_matches_manifest'
        s = "OK"

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
        for i in self.bin_files:
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
            if len(self.bin_files) == 0:
                t = "warn"

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

            if len(self.bin_files) == 0:
                s += ". Application may not work properly when confined."
            else:
                s += ". May be ok (detected as compiled application)."

        self._add_result(t, n, s)

    def check_qtwebkit(self):
        '''Check that QML applications don't use QtWebKit'''
        t = 'info'
        n = 'qml_application_uses_QtWebKit'
        s = "OK"

        qmls = []
        pat_mv = re.compile(r'\n\s*import\s+QtWebKit')
        for i in self.qml_files:
            qml = open_file_read(i).read()
            if pat_mv.search(qml):
                qmls.append(os.path.relpath(i, self.unpack_dir))

        if len(qmls) > 0:
            t = 'warn'
            s = "Found files that use unsupported QtWebKit (should use UbuntuWebview instead): %s" % " ,".join(qmls)

        self._add_result(t, n, s)
