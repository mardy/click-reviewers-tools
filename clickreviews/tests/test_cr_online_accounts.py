'''test_cr_online_accounts.py: tests for the cr_online accounts module'''
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

from clickreviews.cr_online_accounts import ClickReviewAccounts
import clickreviews.cr_tests as cr_tests
import json
import lxml.etree as etree


class TestClickReviewAccounts(cr_tests.TestClickReview):
    """Tests for the lint review tool."""

    def _stub_application(self, root=None, id=None, do_subtree=True):
        '''Stub application xml'''
        if root is None:
            root = "application"
        if id == "" or id is None:
            xml = etree.Element(root)
        else:
            xml = etree.Element(root, id="%s" % id)
        if do_subtree:
            services = etree.SubElement(xml, "services")
            if id is None:
                elem1 = etree.SubElement(services, "service")
            else:
                elem1 = etree.SubElement(services, "service", id="element1")
            desc1 = etree.SubElement(elem1, "description")
            desc1.text = "elem1 description"
            if id is None:
                elem2 = etree.SubElement(services, "service")
            else:
                elem2 = etree.SubElement(services, "service", id="element2")
            desc2 = etree.SubElement(elem2, "description")
            desc2.text = "elem2 description"
        return xml

    def _stub_service(self, root=None, id=None, do_subtree=True):
        '''Stub service xml'''
        if root is None:
            root = "service"
        if id == "" or id is None:
            xml = etree.Element(root)
        else:
            xml = etree.Element(root, id="%s" % id)
        if do_subtree:
            service_name = etree.SubElement(xml, "name")
            service_name.text = "Foo"
            service_provider = etree.SubElement(xml, "provider")
            service_provider.text = "some-provider"
        return xml

    def _stub_provider(self, root=None, id=None, do_subtree=True):
        '''Stub provider xml'''
        if root is None:
            root = "provider"
        if id == "" or id is None:
            xml = etree.Element(root)
        else:
            xml = etree.Element(root, id="%s" % id)
        if do_subtree:
            service_name = etree.SubElement(xml, "name")
            service_name.text = "Foo"
            service_plugin = etree.SubElement(xml, "plugin")
            service_plugin.text = "generic-oauth"
            service_domains = etree.SubElement(xml, "domains")
            service_domains.text = r".*\.example\.com"
            # More can go here, see /usr/share/accounts/providers/*
        return xml

    def test_check_hooks_versions_new(self):
        '''Test check_hooks_versions() - new hook'''
        self.set_test_manifest("framework", "ubuntu-sdk-15.04.1")
        self.set_test_account(self.default_appname, "accounts", dict())
        c = ClickReviewAccounts(self.test_name)
        c.check_hooks_versions()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_hooks_versions_deprecated_service(self):
        '''Test check_hooks_versions() - deprecated -service hook'''
        self.set_test_manifest("framework", "ubuntu-sdk-15.10")
        self.set_test_account(self.default_appname, "account-service", dict())
        c = ClickReviewAccounts(self.test_name)
        c.check_hooks_versions()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_hooks_versions_disallowed_service(self):
        '''Test check_hooks_versions() - deprecated -service hook'''
        self.set_test_manifest("framework", "ubuntu-sdk-16.10")
        self.set_test_account(self.default_appname, "account-service", dict())
        c = ClickReviewAccounts(self.test_name)
        c.check_hooks_versions()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_hooks_versions_deprecated_application(self):
        '''Test check_hooks_versions() - deprecated -application hook'''
        self.set_test_manifest("framework", "ubuntu-sdk-15.10")
        self.set_test_account(self.default_appname,
                              "account-application", dict())
        c = ClickReviewAccounts(self.test_name)
        c.check_hooks_versions()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_hooks_versions_old_framework(self):
        '''Test check_hooks_versions() - deprecated -application hook'''
        self.set_test_manifest("framework", "ubuntu-sdk-15.04")
        self.set_test_account(self.default_appname,
                              "account-application", dict())
        self.set_test_account(self.default_appname, "account-service", dict())
        c = ClickReviewAccounts(self.test_name)
        c.check_hooks_versions()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest(self):
        '''Test check_manifest()'''
        data = json.loads('''{
          "translations": "my-app",
          "services": [
            {
              "name": "Example",
              "provider": "myapp.com_example",
              "description": "publish my photos in example.com",
              "auth": {
                "oauth2/web_server": {
                  "ClientId": "foo",
                  "ClientSecret": "bar",
                  "UseSSL": false,
                  "Scopes": ["one scope","and another"]
                }
              }
            },
            {
              "provider": "becool"
            }
          ],
          "plugin": {
              "name": "Example site",
              "icon": "example.png",
              "qml": "qml_files"
          }
        }''')
        self.set_test_account(self.default_appname, "accounts", data)
        c = ClickReviewAccounts(self.test_name)
        c.check_manifest()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_not_specified(self):
        '''Test check_manifest() - not specified'''
        c = ClickReviewAccounts(self.test_name)
        c.check_manifest()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_manifest_missing_services(self):
        '''Test check_manifest() - missing services'''
        data = json.loads('''{ "translations": "my-app" }''')
        self.set_test_account(self.default_appname, "accounts", data)
        c = ClickReviewAccounts(self.test_name)
        c.check_manifest()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_invalid_services(self):
        '''Test check_manifest() - invalid services'''
        data = json.loads('''{ "services": 12 }''')
        self.set_test_account(self.default_appname, "accounts", data)
        c = ClickReviewAccounts(self.test_name)
        c.check_manifest()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_empty_services(self):
        '''Test check_manifest() - empty services'''
        data = json.loads('''{ "services": [] }''')
        self.set_test_account(self.default_appname, "accounts", data)
        c = ClickReviewAccounts(self.test_name)
        c.check_manifest()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_empty_service(self):
        '''Test check_manifest() - empty services'''
        data = json.loads('''{ "services": [{}] }''')
        self.set_test_account(self.default_appname, "accounts", data)
        c = ClickReviewAccounts(self.test_name)
        c.check_manifest()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_no_provider(self):
        '''Test check_manifest() - no provider'''
        data = json.loads('''{ "services": [{
          "name": "Example",
          "description": "Hello world"
        }] }''')
        self.set_test_account(self.default_appname, "accounts", data)
        c = ClickReviewAccounts(self.test_name)
        c.check_manifest()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_invalid_provider(self):
        '''Test check_manifest() - invalid provider'''
        data = json.loads('''{ "services": [{
          "name": "Example",
          "provider": "no/slashes.please",
          "description": "Hello world"
        }] }''')
        self.set_test_account(self.default_appname, "accounts", data)
        c = ClickReviewAccounts(self.test_name)
        c.check_manifest()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_manifest_unknown_key(self):
        '''Test check_manifest() - unknown key'''
        data = json.loads('''{ "services": [{
          "name": "Example",
          "provider": "example",
          "description": "Hello world",
          "intruder": "Who, me?"
        }] }''')
        self.set_test_account(self.default_appname, "accounts", data)
        c = ClickReviewAccounts(self.test_name)
        c.check_manifest()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_application(self):
        '''Test check_application()'''
        xml = self._stub_application()
        # print(etree.tostring(xml))
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_application_snappy_1504(self):
        '''Test check_application() - snappy 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        xml = self._stub_application()
        # print(etree.tostring(xml))
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_application_not_specified(self):
        '''Test check_application() - not specified'''
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_application_has_id(self):
        '''Test check_application() - has id'''
        xml = self._stub_application(id="%s_%s" % (self.test_manifest["name"],
                                                   self.default_appname))
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_application_wrong_root(self):
        '''Test check_application() - wrong root'''
        xml = self._stub_application(root="wrongroot")
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_application_missing_services(self):
        '''Test check_application() - missing services'''
        xml = self._stub_application(do_subtree=False)

        sometag = etree.SubElement(xml, "sometag")
        elem1 = etree.SubElement(sometag, "something", id="element1")
        desc1 = etree.SubElement(elem1, "description")
        desc1.text = "elem1 description"

        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_application_missing_service(self):
        '''Test check_application() - missing service'''
        xml = self._stub_application(do_subtree=False)

        services = etree.SubElement(xml, "services")
        elem1 = etree.SubElement(services, "somesubtag", id="element1")
        desc1 = etree.SubElement(elem1, "description")
        desc1.text = "elem1 description"

        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service(self):
        '''Test check_service()'''
        xml = self._stub_service()
        self.set_test_account(self.default_appname, "account-service", xml)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_not_specified(self):
        '''Test check_service() - not specified'''
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_has_id(self):
        '''Test check_service() - has id'''
        xml = self._stub_service(id="%s_%s" % (self.test_manifest["name"],
                                               self.default_appname))
        self.set_test_account(self.default_appname, "account-service", xml)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_wrong_root(self):
        '''Test check_service() - wrong root'''
        xml = self._stub_service(root="wrongroot")
        self.set_test_account(self.default_appname, "account-service", xml)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_missing_name(self):
        '''Test check_service() - missing name'''
        xml = self._stub_service(do_subtree=False)
        service_provider = etree.SubElement(xml, "provider")
        service_provider.text = "some-provider"
        self.set_test_account(self.default_appname, "account-service", xml)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_missing_provider(self):
        '''Test check_service() - missing provider'''
        xml = self._stub_service(do_subtree=False)
        service_name = etree.SubElement(xml, "name")
        service_name.text = "Foo"
        self.set_test_account(self.default_appname, "account-service", xml)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_provider(self):
        '''Test check_provider()'''
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        c = ClickReviewAccounts(self.test_name)
        c.check_provider()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_provider_has_id(self):
        '''Test check_provider() - has id'''
        xml = self._stub_provider(id="%s_%s" % (self.test_manifest["name"],
                                                self.default_appname))
        self.set_test_account(self.default_appname, "account-provider", xml)
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        c = ClickReviewAccounts(self.test_name)
        c.check_provider()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_qml_plugin(self):
        '''Test check_qml_plugin()'''
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_qml_plugin()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_application(self):
        '''Test check_peer_hooks() - application'''
        c = ClickReviewAccounts(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["account-application"] = "foo.application"

        # add any required peer hooks
        tmp["apparmor"] = "foo.apparmor"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks(["account-application"])
        r = c.click_report
        # We should end up with 8 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_application_disallowed(self):
        '''Test check_peer_hooks() - disallowed (application)'''
        c = ClickReviewAccounts(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["account-application"] = "foo.application"

        # add any required peer hooks
        tmp["apparmor"] = "foo.apparmor"

        # add something not allowed
        tmp["nonexistent"] = "nonexistent-hook"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks(["account-application"])
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_application_required(self):
        '''Test check_peer_hooks() - required (application)'''
        c = ClickReviewAccounts(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["account-application"] = "foo.application"

        # skip adding required hooks

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks(["account-application"])
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_service(self):
        '''Test check_peer_hooks() - service'''
        c = ClickReviewAccounts(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["account-service"] = "foo.service"

        # add any required peer hooks
        tmp["account-application"] = "foo.application"
        tmp["apparmor"] = "foo.apparmor"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks(["account-service"])
        r = c.click_report
        # We should end up with 8 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_service_disallowed(self):
        '''Test check_peer_hooks() - disallowed (service)'''
        c = ClickReviewAccounts(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["account-service"] = "foo.service"

        # add any required peer hooks
        tmp["account-application"] = "foo.application"
        tmp["apparmor"] = "foo.apparmor"

        # add something not allowed
        tmp["nonexistent"] = "nonexistent-hook"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks(["account-service"])
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_service_required(self):
        '''Test check_peer_hooks() - required (service)'''
        c = ClickReviewAccounts(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["account-service"] = "foo.service"

        # skip adding required hooks

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks(["account-service"])
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_provider(self):
        '''Test check_peer_hooks() - provider'''
        c = ClickReviewAccounts(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["account-provider"] = "foo.provider"

        # add any required peer hooks
        tmp["account-qml-plugin"] = "foo.qml_plugin"
        tmp["apparmor"] = "foo.apparmor"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks(["account-provider"])
        r = c.click_report
        # We should end up with 8 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_provider_disallowed(self):
        '''Test check_peer_hooks() - disallowed (provider)'''
        c = ClickReviewAccounts(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["account-provider"] = "foo.provider"

        # add any required peer hooks
        tmp["account-qml-plugin"] = "foo.qml_plugin"
        tmp["apparmor"] = "foo.apparmor"

        # add something not allowed
        tmp["nonexistent"] = "nonexistent-hook"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks(["account-provider"])
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_provider_required(self):
        '''Test check_peer_hooks() - required (provider)'''
        c = ClickReviewAccounts(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["account-provider"] = "foo.provider"

        # skip adding required hooks

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks(["account-provider"])
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
