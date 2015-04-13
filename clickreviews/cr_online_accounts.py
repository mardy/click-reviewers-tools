'''cr_online_accounts.py: click online accounts'''
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

from clickreviews.cr_common import ClickReview, error, open_file_read, msg
import os
# http://lxml.de/tutorial.html
import lxml.etree as etree


class ClickReviewAccounts(ClickReview):
    '''This class represents click lint reviews'''
    def __init__(self, fn, overrides=None):
        peer_hooks = dict()
        peer_hooks['account-application'] = dict()
        peer_hooks['account-application']['allowed'] = \
            ClickReview.app_allowed_peer_hooks + \
            ClickReview.scope_allowed_peer_hooks
        peer_hooks['account-application']['required'] = ['apparmor']

        peer_hooks['account-service'] = dict()
        peer_hooks['account-service']['required'] = ['account-application',
                                                     'apparmor'
                                                     ]
        peer_hooks['account-service']['allowed'] = \
            ClickReview.app_allowed_peer_hooks + \
            ClickReview.scope_allowed_peer_hooks

        peer_hooks['account-provider'] = dict()
        peer_hooks['account-provider']['required'] = ['account-qml-plugin',
                                                      # 'apparmor'
                                                      ]
        peer_hooks['account-provider']['allowed'] = \
            peer_hooks['account-provider']['required']

        peer_hooks['account-qml-plugin'] = dict()
        peer_hooks['account-qml-plugin']['required'] = ['account-provider',
                                                        # 'apparmor'
                                                        ]
        peer_hooks['account-qml-plugin']['allowed'] = \
            peer_hooks['account-qml-plugin']['required']

        ClickReview.__init__(self, fn, "online_accounts", peer_hooks=peer_hooks,
                             overrides=overrides)

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
                error("accounts xml unparseable: %s (%s)" % (bn, str(e)))
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

            root_tag = self.accounts[app][account_type].tag.lower()
            if root_tag != "application":
                t = 'error'
                s = "'%s' is not 'application'" % root_tag
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_%s_id' % (app, account_type)
            s = "OK"
            expected_id = "%s_%s" % (self.manifest["name"], app)
            if "id" in self.accounts[app][account_type].keys():
                t = 'warn'
                s = "Found 'id' in application tag"
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

            root_tag = self.accounts[app][account_type].tag.lower()
            if root_tag != "service":
                t = 'error'
                s = "'%s' is not 'service'" % root_tag
            self._add_result(t, n, s)

            t = 'info'
            n = '%s_%s_id' % (app, account_type)
            s = "OK"
            expected_id = "%s_%s" % (self.manifest["name"], app)
            if "id" in self.accounts[app][account_type].keys():
                t = 'warn'
                s = "Found 'id' in service tag"
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
            if "id" in self.accounts[app][account_type].keys():
                t = 'warn'
                s = "Found 'id' in provider tag"
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
