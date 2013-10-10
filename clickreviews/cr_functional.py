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
import magic
import os
import re

from clickreviews.cr_common import ClickReview, open_file_read

# TODO: see if i18n.domain('%s') matches X-Ubuntu-Gettext-Domain

class ClickReviewFunctional(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "functional")
        self.mime = magic.open(magic.MAGIC_MIME)
        self.mime.load()

    def check_applicationName(self):
        '''Check applicationName matches click manifest'''
        t = 'info'
        n = 'qml_applicationName_matches_manifest'
        s = "OK"
        if False:
            t = 'error'
            s = "some message"

        # find file with MainView in the QML
        pat_mv = re.compile(r'\n\s*MainView\s+{')
        qmls = dict()
        count = 0
        for i in self.pkg_files:
            if i.endswith(".qml"):
                count += 1
                qml = open_file_read(i).read()
                if pat_mv.search(qml):
                    qmls[i] = qml

        if count == 0:
            s = "OK (not QML)"
            self._add_result(t, n, s)
            return
        elif len(qmls) == 0:
            s = "SKIP: could not find MainView in QML files"
            self._add_result(t, n, s)
            return

        pat_mvl = re.compile(r'^\s*MainView\s+')
        pat_appname = re.compile(r'^\s*applicationName\s*:\s*["\']')

        ok = False
        appnames = dict()
        for k in qmls.keys():
            in_mainview = False
            for line in qmls[k].splitlines():
                if in_mainview and pat_appname.search(line):
                    appname = line.split(':', 1)[1].strip('"\' \t\n\r\f\v')
                    appnames[os.path.relpath(k, self.unpack_dir)] = appname
                    if appname == self.click_pkgname:
                        ok = True
                        break
                elif pat_mvl.search(line):
                    in_mainview = True
                if ok:
                    break

        if len(appnames) == 0:
            t = "warn"
            s = "could not find applicationName in: %s" % \
                ", ".join(list(map(
                               lambda x: os.path.relpath(x, self.unpack_dir),
                               qmls)
                               ))
            s += ". Application may not work properly when confined."
        elif not ok:
            t = "warn"
            s = "click manifest name '%s' not found in: " % \
                self.click_pkgname + "%s" % \
                ", ".join(list(map(
                               lambda x: "%s ('%s')" % (x, appnames[x]),
                               appnames)
                               ))
            s += ". Application may not work properly when confined."

        self._add_result(t, n, s)
