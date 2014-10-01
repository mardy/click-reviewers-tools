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
# http://lxml.de/tutorial.html
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
                    # msg("Skipped missing %s hook for '%s'" % (h, app))
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

        # qml-plugin points to a QML file, so just set that we have the
        # the hook present for now
        if account_type == "account-qml-plugin":
            return (fn, True)
        else:
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
            if account_type not in self.accounts[app]:
                s = "OK (missing)"
                self._add_result(t, n, s)
                continue

            # account-application must always appear with apparmor
            t = 'info'
            n = '%s_%s_apparmor' % (app, account_type)
            s = "OK"
            if 'apparmor' not in self.manifest['hooks'][app]:
                t = 'error'
                s = "missing 'apparmor' entry"
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_%s_desktop_or_scope' % (app, account_type)
            s = "OK"
            found = False
            for k in ['desktop', 'scope']:
                if k in self.manifest['hooks'][app]:
                    found = True
                    break
            if not found:
                t = 'error'
                s = "missing 'desktop' or 'scope' entry"
            self._add_result(t, n, s)

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

            t = 'info'
            n = '%s_%s_services' % (app, account_type)
            s = "OK"
            if self.accounts[app][account_type].find("services") is None:
                t = 'error'
                s = "Could not find '<services>' tag"
            self._add_result(t, n, s)

            if t == 'error':
                continue

            t = 'info'
            n = '%s_%s_service' % (app, account_type)
            s = "OK"
            if self.accounts[app][account_type].find("./services/service") \
               is None:
                t = 'error'
                s = "Could not find '<service>' tag under <services>"
            self._add_result(t, n, s)

    def check_service(self):
        '''Check service'''
        for app in sorted(self.accounts.keys()):
            account_type = "account-service"

            t = 'info'
            n = '%s_%s_root' % (app, account_type)
            s = "OK"
            if account_type not in self.accounts[app]:
                s = "OK (missing)"
                self._add_result(t, n, s)
                continue

            #  account service must always appear with account-application
            t = 'info'
            n = '%s_%s_account-application' % (app, account_type)
            s = "OK"
            if 'account-application' not in self.accounts[app]:
                t = 'error'
                s = "missing 'account-application' entry"
            self._add_result(t, n, s)

            # account-service must always appear with apparmor
            t = 'info'
            n = '%s_%s_apparmor' % (app, account_type)
            s = "OK"
            if 'apparmor' not in self.manifest['hooks'][app]:
                t = 'error'
                s = "missing 'apparmor' entry"
            self._add_result(t, n, s)

            root_tag = self.accounts[app][account_type].tag.lower()
            if root_tag != "service":
                t = 'error'
                s = "'%s' is not 'service'" % root_tag
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_%s_id' % (app, account_type)
            s = "OK"
            expected_id = "%s_%s" % (self.manifest["name"], app)
            if "id" not in self.accounts[app][account_type].keys():
                t = 'error'
                s = "Could not find 'id' in service tag"
            elif self.accounts[app][account_type].get("id") != expected_id:
                t = 'error'
                s = "id '%s' != '%s'" % (
                    self.accounts[app][account_type].get("id"),
                    expected_id)
            self._add_result(t, n, s)

            if t == 'error':
                continue

            for tag in ['type', 'name', 'provider']:
                t = 'info'
                n = '%s_%s_%s' % (app, account_type, tag)
                s = "OK"
                if self.accounts[app][account_type].find(tag) is None:
                    t = 'error'
                    s = "Could not find '<%s>' tag" % tag
                self._add_result(t, n, s)

    def check_provider(self):
        '''Check provider'''
        for app in sorted(self.accounts.keys()):
            account_type = "account-provider"

            t = 'info'
            n = '%s_%s' % (app, account_type)
            s = "OK"
            manual_review = False
            if account_type not in self.accounts[app]:
                s = "OK (missing)"
                self._add_result(t, n, s)
                continue
            else:
                t = 'error'
                s = "(MANUAL REVIEW) '%s' not allowed" % account_type
                manual_review = True
            self._add_result(t, n, s, manual_review=manual_review)

            # account-provider must always appear with apparmor
            t = 'info'
            n = '%s_%s_apparmor' % (app, account_type)
            s = "OK"
            if 'apparmor' not in self.manifest['hooks'][app]:
                t = 'error'
                s = "missing 'apparmor' entry"
            self._add_result(t, n, s)

            # account-provider must always appear with account-qml-plugin
            t = 'info'
            n = '%s_%s_account-qml-plugin' % (app, account_type)
            s = "OK"
            if 'account-qml-plugin' not in self.accounts[app]:
                t = 'error'
                s = "missing 'account-qml-plugin' entry"
            self._add_result(t, n, s)

            # account-provider must never appear with account-application or
            # account-service
            t = 'info'
            n = '%s_%s_account-application_or_account-service' % (app,
                                                                  account_type)
            s = "OK"
            found = False
            for i in ['account-application', 'account-service']:
                if i in self.accounts[app]:
                    found = True
            if found:
                t = 'error'
                s = "must not specify account-application or account-service" \
                    "with %s" % account_type
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_%s_root' % (app, account_type)
            s = "OK"
            root_tag = self.accounts[app][account_type].tag.lower()
            if root_tag != "provider":
                t = 'error'
                s = "'%s' is not 'provider'" % root_tag
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_%s_id' % (app, account_type)
            s = "OK"
            expected_id = "%s_%s" % (self.manifest["name"], app)
            if "id" not in self.accounts[app][account_type].keys():
                t = 'error'
                s = "Could not find 'id' in provider tag"
            elif self.accounts[app][account_type].get("id") != expected_id:
                t = 'error'
                s = "id '%s' != '%s'" % (
                    self.accounts[app][account_type].get("id"),
                    expected_id)
            self._add_result(t, n, s)

    def check_qml_plugin(self):
        '''Check qml-plugin'''
        for app in sorted(self.accounts.keys()):
            account_type = "account-qml-plugin"

            t = 'info'
            n = '%s_%s' % (app, account_type)
            s = "OK"
            manual_review = False
            if account_type not in self.accounts[app]:
                s = "OK (missing)"
                self._add_result(t, n, s)
                continue
            else:
                t = 'error'
                s = "(MANUAL REVIEW) '%s' not allowed" % account_type
                manual_review = True
            self._add_result(t, n, s, manual_review=manual_review)

            # account-qml-plugin must always appear with apparmor
            t = 'info'
            n = '%s_%s_apparmor' % (app, account_type)
            s = "OK"
            if 'apparmor' not in self.manifest['hooks'][app]:
                t = 'error'
                s = "missing 'apparmor' entry"
            self._add_result(t, n, s)

            # account-qml-plugin must always appear with account-provider
            t = 'info'
            n = '%s_%s_account-provider' % (app, account_type)
            s = "OK"
            if 'account-provider' not in self.accounts[app]:
                t = 'error'
                s = "missing 'account-provider' entry"
            self._add_result(t, n, s)

            # account-qml-plugin must never appear with account-application or
            # account-service
            t = 'info'
            n = '%s_%s_account-application_or_account-service' % (app,
                                                                  account_type)
            s = "OK"
            found = False
            for i in ['account-application', 'account-service']:
                if i in self.accounts[app]:
                    found = True
            if found:
                t = 'error'
                s = "must not specify account-application or account-service" \
                    "with %s" % account_type
            self._add_result(t, n, s)
