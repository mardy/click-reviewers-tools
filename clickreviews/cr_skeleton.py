'''cr_skeleton.py: click skeleton'''
#
# Copyright (C) 2014-2015 Canonical Ltd.
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

from clickreviews.cr_common import ClickReview


class ClickReviewSkeleton(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        # Many test classes are for verify click hooks. 'peer_hooks' is used
        # to declare what hooks may be use with my_hook. When using this
        # mechanism, ClickReview.check_peer_hooks() is run for you.
        peer_hooks = dict()
        my_hook = 'skeleton'
        peer_hooks[my_hook] = dict()
        peer_hooks[my_hook]['allowed'] = ["desktop", "apparmor", "urls"]
        peer_hooks[my_hook]['required'] = ["desktop", "apparmor"]

        ClickReview.__init__(self, fn, "skeleton", peer_hooks=peer_hooks,
                             overrides=overrides)

        if not self.is_click and not self.is_snap1:
            return

        # If not a hooks test, skip the above and omit peer_hooks like so:
        # ClickReview.__init__(self, fn, "skeleton")

    def check_foo(self):
        '''Check foo'''
        if not self.is_click and not self.is_snap1:
            return

        t = 'info'
        n = self._get_check_name('foo')
        s = "OK"
        if False:
            t = 'error'
            s = "some message"
        self._add_result(t, n, s)

    def check_bar(self):
        '''Check bar'''
        if not self.is_click and not self.is_snap1:
            return

        t = 'info'
        n = self._get_check_name('bar')
        s = "OK"
        if True:
            t = 'error'
            s = "some message"
        self._add_result(t, n, s)

    def check_baz(self):
        '''Check baz'''
        if not self.is_click and not self.is_snap1:
            return

        n = self._get_check_name('baz')
        self._add_result('warn', n, 'TODO', link="http://example.com")

        # Spawn a shell to pause the script (run 'exit' to continue)
        # import subprocess
        # print(self.unpack_dir)
        # subprocess.call(['bash'])
