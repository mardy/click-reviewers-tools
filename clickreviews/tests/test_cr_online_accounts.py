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
import lxml.etree as etree


class TestClickReviewAccounts(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

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
            service_type = etree.SubElement(xml, "type")
            service_type.text = "webapps"
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
            service_domains.text = ".*\.example\.com"
            # More can go here, see /usr/share/accounts/providers/*
        return xml

    def test_check_application(self):
        '''Test check_application()'''
        xml = self._stub_application()
        # print(etree.tostring(xml))
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_application_missing_apparmor(self):
        '''Test check_application() - missing apparmor'''
        xml = self._stub_application()
        # print(etree.tostring(xml))
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        del c.manifest['hooks'][self.default_appname]['apparmor']
        c.check_application()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_application_missing_desktop_and_scope(self):
        '''Test check_application() - missing desktop and scope'''
        xml = self._stub_application()
        # print(etree.tostring(xml))
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        # The stub manifest doesn't have scope already
        del c.manifest['hooks'][self.default_appname]['desktop']
        c.check_application()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_application_missing_desktop_and_scope_with_payui(self):
        '''Test check_application() - missing desktop and scope with pay-ui'''
        xml = self._stub_application()
        # print(etree.tostring(xml))
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        # The stub manifest doesn't have scope already
        del c.manifest['hooks'][self.default_appname]['desktop']
        c.manifest['hooks'][self.default_appname]['pay-ui'] = "foo.desktop"
        c.check_application()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
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
        expected_counts = {'info': 6, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_missing_application(self):
        '''Test check_service() - missing account-application'''
        xml = self._stub_service()
        self.set_test_account(self.default_appname, "account-service", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_missing_apparmor(self):
        '''Test check_service() - missing apparmor'''
        xml = self._stub_service()
        self.set_test_account(self.default_appname, "account-service", xml)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        del c.manifest['hooks'][self.default_appname]['apparmor']
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
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

    def test_check_service_missing_type(self):
        '''Test check_service() - missing type'''
        xml = self._stub_service(do_subtree=False)
        service_name = etree.SubElement(xml, "name")
        service_name.text = "Foo"
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

    def test_check_service_missing_name(self):
        '''Test check_service() - missing name'''
        xml = self._stub_service(do_subtree=False)
        service_type = etree.SubElement(xml, "type")
        service_type.text = "webapps"
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
        service_type = etree.SubElement(xml, "type")
        service_type.text = "webapps"
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
        # provider prompts manual review, so for now, need to have error as 1
        expected_counts = {'info': 4, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-provider" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

# TODO: when apparmor has policy for account-provider, undo this
    def _test_check_provider_missing_apparmor(self):
        '''Test check_provider() - missing apparmor'''
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        c = ClickReviewAccounts(self.test_name)
        del c.manifest['hooks'][self.default_appname]['apparmor']
        c.check_provider()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 2
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-provider" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_provider_missing_qml_plugin(self):
        '''Test check_provider() - missing account-qml-plugin'''
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_provider()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 2
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-provider" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_provider_with_application(self):
        '''Test check_provider() - with account-application'''
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_provider()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 2
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-provider" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_provider_with_service(self):
        '''Test check_provider() - with account-service'''
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        xml = self._stub_service()
        self.set_test_account(self.default_appname, "account-service", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_provider()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 2
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-provider" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_provider_with_application_and_service(self):
        '''Test check_provider() - with account-application/account-service'''
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        xml = self._stub_service()
        self.set_test_account(self.default_appname, "account-service", xml)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_provider()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 2
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-provider" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_provider_not_specified(self):
        '''Test check_provider() - not specified'''
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        c = ClickReviewAccounts(self.test_name)
        c.check_provider()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
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
        # provider prompts manual review, so for now, need to have error as +1
        expected_counts = {'info': None, 'warn': 1, 'error': 1}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-provider" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_qml_plugin(self):
        '''Test check_qml_plugin()'''
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_qml_plugin()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 1
        expected_counts = {'info': 2, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-qml-plugin" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

# TODO: when apparmor has policy for account-qml-plugin, undo this
    def _test_check_qml_plugin_missing_apparmor(self):
        '''Test check_qml_plugin() - missing apparmor'''
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        c = ClickReviewAccounts(self.test_name)
        del c.manifest['hooks'][self.default_appname]['apparmor']
        c.check_qml_plugin()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 2
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-qml-plugin" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_qml_plugin_missing_provider(self):
        '''Test check_qml_plugin() - missing account-provider'''
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        c = ClickReviewAccounts(self.test_name)
        c.check_qml_plugin()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 2
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-qml-plugin" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_qml_plugin_with_application(self):
        '''Test check_qml_plugin() - with account-application'''
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_qml_plugin()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 2
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-qml-plugin" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_qml_plugin_with_service(self):
        '''Test check_qml_plugin() - with account-service'''
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        xml = self._stub_service()
        self.set_test_account(self.default_appname, "account-service", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_qml_plugin()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 2
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-qml-plugin" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_qml_plugin_with_application_and_service(self):
        '''Test check_qml_plugin() - with account-application/account-service'''
        self.set_test_account(self.default_appname, "account-qml-plugin", True)
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        xml = self._stub_service()
        self.set_test_account(self.default_appname, "account-service", xml)
        xml = self._stub_application()
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_qml_plugin()
        r = c.click_report
        # provider prompts manual review, so for now, need to have error as 1
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)
        check_name = "%s_%s_account-qml-plugin" % (c.review_type, self.default_appname)
        self.check_manual_review(r, check_name)

    def test_check_qml_plugin_not_specified(self):
        '''Test check_qml_plugin() - not specified'''
        xml = self._stub_provider()
        self.set_test_account(self.default_appname, "account-provider", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_qml_plugin()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)
