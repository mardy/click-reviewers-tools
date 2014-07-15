'''cr_online_accounts.py: click online accounts'''
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

from clickreviews.cr_common import ClickReview, error, open_file_read, msg
import os
import lxml.etree as etree


class ClickReviewAccounts(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn):
        ClickReview.__init__(self, fn, "online_accounts")

        self.accounts_files = dict()
        self.accounts = dict()

        self.account_hooks = ['account-application',
                              'account-provider',
                              'account-qml-plugin',
                              'account-service']
        for app in self.manifest['hooks']:
            for h in self.account_hooks:
                if h not in self.manifest['hooks'][app]:
                    msg("Skipped missing %s hook for '%s'" % (h, app))
                    continue
                if not isinstance(self.manifest['hooks'][app][h], str):
                    error("manifest malformed: hooks/%s/%s is not a str" % (
                          app, h))
                (full_fn, xml) = self._extract_account(app, h)

                if app not in self.accounts_files:
                    self.accounts_files[app] = dict()
                self.accounts_files[app][h] = full_fn

                if app not in self.accounts:
                    self.accounts[app] = dict()
                self.accounts[app][h] = xml

    def _extract_account(self, app, account_type):
        '''Extract accounts'''
        a = self.manifest['hooks'][app][account_type]
        fn = os.path.join(self.unpack_dir, a)

        bn = os.path.basename(fn)
        if not os.path.exists(fn):
            error("Could not find '%s'" % bn)

        try:
            tree = etree.parse(fn)
            xml = tree.getroot()
        except Exception as e:
            error("accounts xml unparseable: %s (%s):\n%s" % (bn, str(e),
                  contents))

        return (fn, xml)

    def check_application(self):
        '''Check application'''
        for app in sorted(self.accounts.keys()):
            account_type = "account-application"

            t = 'info'
            n = '%s_%s_root' % (app, account_type)
            s = "OK"
            if not account_type in self.accounts[app]:
                s = "OK (missing)"
                self._add_result(t, n, s)
                continue

            root_tag = self.accounts[app][account_type].tag.lower()
            if root_tag != "application":
                t = 'error'
                s = "'%s' is not 'application'" % root_tag
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_%s_id' % (app, account_type)
            s = "OK"
            expected_id = "%s_%s" % (self.manifest["name"], app)
            if "id" not in self.accounts[app][account_type].keys():
                t = 'error'
                s = "Could not find 'id' in application tag"
            elif self.accounts[app][account_type].get("id") != expected_id:
                t = 'error'
                s = "id '%s' != '%s'" % (
                    self.accounts[app][account_type].get("id"),
                    expected_id)
            self._add_result(t, n, s)
