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

from clickreviews.cr_common import ClickReview, error, open_file_read
import json
import os
import re
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

        peer_hooks['accounts'] = dict()
        peer_hooks['accounts']['allowed'] = \
            [h for h in (ClickReview.app_allowed_peer_hooks +
                         ClickReview.scope_allowed_peer_hooks)
             if h != 'account-application' and h != 'account-service']
        peer_hooks['accounts']['required'] = ['apparmor']

        peer_hooks['account-provider'] = dict()
        peer_hooks['account-provider']['required'] = ['account-qml-plugin',
                                                      'apparmor'
                                                      ]
        peer_hooks['account-provider']['allowed'] = \
            peer_hooks['account-provider']['required']

        peer_hooks['account-qml-plugin'] = dict()
        peer_hooks['account-qml-plugin']['required'] = ['account-provider',
                                                        'apparmor'
                                                        ]
        peer_hooks['account-qml-plugin']['allowed'] = \
            peer_hooks['account-qml-plugin']['required']

        ClickReview.__init__(self,
                             fn,
                             "online_accounts",
                             peer_hooks=peer_hooks,
                             overrides=overrides,
                             peer_hooks_link="https://wiki.ubuntu.com/SecurityTeam/Specifications/OnlineAccountsConfinement")

        self.accounts_files = dict()
        self.accounts = dict()

        self.account_hooks = ['accounts',
                              'account-application',
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

                (full_fn, parsed) = self._extract_account(app, h)

                if app not in self.accounts_files:
                    self.accounts_files[app] = dict()
                self.accounts_files[app][h] = full_fn

                if app not in self.accounts:
                    self.accounts[app] = dict()
                self.accounts[app][h] = parsed

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
        elif account_type == "accounts":
            fh = open_file_read(fn)
            contents = ""
            for line in fh.readlines():
                contents += line
            fh.close()

            try:
                jd = json.loads(contents)
            except Exception as e:
                error("accounts json unparseable: %s (%s):\n%s" % (bn,
                      str(e), contents))

            if not isinstance(jd, dict):
                error("accounts json is malformed: %s:\n%s" % (bn, contents))

            return (fn, jd)
        else:
            try:
                tree = etree.parse(fn)
                xml = tree.getroot()
            except Exception as e:
                error("accounts xml unparseable: %s (%s)" % (bn, str(e)))
            return (fn, xml)

    def check_hooks_versions(self):
        '''Check hooks versions'''
        framework = self.manifest['framework']
        if not framework.startswith("ubuntu-sdk"):
            return
        t = "error"
        if framework < "ubuntu-sdk-15.10":
            return
        for app in sorted(self.accounts.keys()):
            for account_type in ["account-application", "account-service"]:
                n = self._get_check_name('%s_hook' % account_type, app=app)
                if account_type in self.accounts[app]:
                    s = "'%s' is disallowed in %s: use 'accounts' hook" % \
                        (account_type, framework)
                    self._add_result(t, n, s)

    def check_manifest(self):
        '''Check manifest'''
        required_service_keys = [
            ('provider', str),
        ]
        allowed_service_keys = [
            ('auth', dict),
            ('name', str),
            ('description', str),
        ]
        provider_re = re.compile('^[a-zA-Z0-9-]+$')

        for app in sorted(self.accounts.keys()):
            account_type = "accounts"

            t = 'info'
            n = self._get_check_name('%s_root' % account_type, app=app)
            s = "OK"
            if account_type not in self.accounts[app]:
                s = "OK (missing)"
                self._add_result(t, n, s)
                continue

            n = self._get_check_name('%s_services' % account_type, app=app)
            if 'services' not in self.accounts[app][account_type]:
                t = "error"
                s = "'services' key is missing"
                self._add_result(t, n, s)
                continue
            services = self.accounts[app][account_type]['services']
            if not isinstance(services, list):
                t = "error"
                s = "'services' is not a list"
            elif len(services) < 1:
                t = "error"
                s = "'services' is empty"
            if t == "error":
                self._add_result(t, n, s)
                continue

            for (i, service) in enumerate(services):
                t = "info"
                n = self._get_check_name('%s_service_#%s' % (account_type, i), app=app)
                s = "OK"
                if not isinstance(service, dict):
                    t = "error"
                    s = "service is not an object"
                    self._add_result(t, n, s)
                    continue

                for (k, vt) in required_service_keys:
                    if k not in service.keys():
                        t = "error"
                        s = "required key '%s' is missing" % k
                        self._add_result(t, n, s)
                if t == "error":
                    continue

                known_keys = required_service_keys + allowed_service_keys
                for (k, v) in service.items():
                    type_list = [kk[1] for kk in known_keys if kk[0] == k]
                    if len(type_list) < 1:
                        t = "error"
                        s = "unrecognized key '%s'" % k
                        self._add_result(t, n, s)
                        continue
                    if not isinstance(v, type_list[0]):
                        t = "error"
                        s = "value for '%s' must be of type %s" % (k, type_list[0])
                        self._add_result(t, n, s)
                        continue
                    if k == 'provider' and not provider_re.match(v):
                        t = "error"
                        s = "'provider' must only consist of alphanumeric characters"
                        self._add_result(t, n, s)
                self._add_result(t, n, s)

    def check_application(self):
        '''Check application'''
        for app in sorted(self.accounts.keys()):
            account_type = "account-application"

            t = 'info'
            n = self._get_check_name('%s_root' % account_type, app=app)
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
            n = self._get_check_name('%s_id' % account_type, app=app)
            s = "OK"
            if "id" in self.accounts[app][account_type].keys():
                t = 'warn'
                s = "Found 'id' in application tag"
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('%s_services' % account_type, app=app)
            s = "OK"
            if self.accounts[app][account_type].find("services") is None:
                t = 'error'
                s = "Could not find '<services>' tag"
            self._add_result(t, n, s)

            if t == 'error':
                continue

            t = 'info'
            n = self._get_check_name('%s_service' % account_type, app=app)
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
            n = self._get_check_name('%s_root' % account_type, app=app)
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
            n = self._get_check_name('%s_id' % account_type, app=app)
            s = "OK"
            if "id" in self.accounts[app][account_type].keys():
                t = 'warn'
                s = "Found 'id' in service tag"
            self._add_result(t, n, s)

            if t == 'error':
                continue

            for tag in ['name', 'provider']:
                t = 'info'
                n = self._get_check_name(
                    '%s_%s' % (account_type, tag), app=app)
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
            n = self._get_check_name(account_type, app=app)
            s = "OK"
            manual_review = False
            if account_type not in self.accounts[app]:
                s = "OK (missing)"
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s, manual_review=manual_review)

            t = 'info'
            n = self._get_check_name('%s_root' % account_type, app=app)
            s = "OK"
            root_tag = self.accounts[app][account_type].tag.lower()
            if root_tag != "provider":
                t = 'error'
                s = "'%s' is not 'provider'" % root_tag
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('%s_id' % account_type, app=app)
            s = "OK"
            if "id" in self.accounts[app][account_type].keys():
                t = 'warn'
                s = "Found 'id' in provider tag"
            self._add_result(t, n, s)

    def check_qml_plugin(self):
        '''Check qml-plugin'''
        for app in sorted(self.accounts.keys()):
            account_type = "account-qml-plugin"

            t = 'info'
            n = self._get_check_name(account_type, app=app)
            s = "OK"
            manual_review = False
            if account_type not in self.accounts[app]:
                s = "OK (missing)"
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s, manual_review=manual_review)
