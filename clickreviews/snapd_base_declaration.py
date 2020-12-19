#
#  Copyright (C) 2016 Canonical Ltd.
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

USER_DATA_FILE = os.path.join(clickreviews.remote.DATA_DIR,
                              'snapd-base-declaration.yaml')

BD_DATA_URL = \
    ("https://raw.githubusercontent.com/ubports/click-reviewers-tools/"
     "xenial/data/snapd-base-declaration.yaml")


def get_base_declaration_file(fn):
    if fn is None:
        fn = USER_DATA_FILE
    clickreviews.remote.get_remote_file(fn, BD_DATA_URL)


class SnapdBaseDeclaration(object):
    def __init__(self, local_copy_fn=None):
        self.decl = clickreviews.remote.read_cr_file(USER_DATA_FILE,
                                                     BD_DATA_URL,
                                                     local_copy_fn,
                                                     as_yaml=True)
