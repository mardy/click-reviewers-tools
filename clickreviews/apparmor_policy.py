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

USER_DATA_FILE = os.path.join(clickreviews.remote.DATA_DIR,
                              'apparmor-easyprof-ubuntu.json')

# XXX: This is a hack and will be gone, as soon as myapps has an API for this.
AA_POLICY_DATA_URL = \
    "https://github.com/ubports/click-reviewers-tools/" \
    "raw/xenial/data/apparmor-easyprof-ubuntu.json"


def get_policy_file(fn):
    if fn is None:
        fn = USER_DATA_FILE
    clickreviews.remote.get_remote_file(fn, AA_POLICY_DATA_URL)


class ApparmorPolicy(object):
    def __init__(self, local_copy_fn=None):
        self.policy = clickreviews.remote.read_cr_file(USER_DATA_FILE,
                                                       AA_POLICY_DATA_URL,
                                                       local_copy_fn)
