#
#  Copyright (C) 2014 Canonical Ltd.
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 3 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import clickreviews.remote

USER_DATA_FILE = os.path.join(clickreviews.remote.DATA_DIR, 'frameworks.json')
FRAMEWORKS_DATA_URL = \
    "https://myapps.developer.ubuntu.com/dev/api/click-framework/"


def get_frameworks_file(fn):
    if fn is None:
        fn = USER_DATA_FILE
    clickreviews.remote.get_remote_file(fn, FRAMEWORKS_DATA_URL)


class Frameworks(object):
    DEPRECATED_FRAMEWORKS = []
    OBSOLETE_FRAMEWORKS = []
    AVAILABLE_FRAMEWORKS = []

    def __init__(self):
        self.FRAMEWORKS = clickreviews.remote.read_cr_file(USER_DATA_FILE,
                                                           FRAMEWORKS_DATA_URL)

        for k, v in self.FRAMEWORKS.items():
            if v == 'deprecated':
                self.DEPRECATED_FRAMEWORKS.append(k)
            elif v == 'obsolete':
                self.OBSOLETE_FRAMEWORKS.append(k)
            elif v == 'available':
                self.AVAILABLE_FRAMEWORKS.append(k)
