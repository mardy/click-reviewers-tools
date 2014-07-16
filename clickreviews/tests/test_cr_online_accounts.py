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
        if id is None:
            id = "%s_%s" % (self.test_manifest["name"], self.default_appname)
        if root is None:
            root = "application"
        if id == "":
            xml = etree.Element(root)
        else:
            xml = etree.Element(root, id="%s" % id)
        if do_subtree:
            services = etree.SubElement(xml, "services")
            elem1 = etree.SubElement(services, "service", id="element1")
            desc1 = etree.SubElement(elem1, "description")
            desc1.text = "elem1 description"
            elem2 = etree.SubElement(services, "service", id="element2")
            desc2 = etree.SubElement(elem2, "description")
            desc2.text = "elem2 description"
        return xml

    def _stub_service(self, root=None, id=None, do_subtree=True):
        '''Stub service xml'''
        if id is None:
            id = "%s_%s" % (self.test_manifest["name"], self.default_appname)
        if root is None:
            root = "service"
        if id == "":
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

    def test_check_application(self):
        '''Test check_application()'''
        xml = self._stub_application()
        print(etree.tostring(xml))
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_application_wrong_id(self):
        '''Test check_application() - wrong id'''
        xml = self._stub_application(id="nomatch")
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_application_missing_id(self):
        '''Test check_application() - missing id'''
        xml = self._stub_application(id="")
        self.set_test_account(self.default_appname, "account-application", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
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

    def test_check_application_wrong_missing_services(self):
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

    def test_check_application_wrong_missing_service(self):
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
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_wrong_id(self):
        '''Test check_service() - wrong id'''
        xml = self._stub_service(id="nomatch")
        self.set_test_account(self.default_appname, "account-service", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_missing_id(self):
        '''Test check_service() - missing id'''
        xml = self._stub_service(id="")
        self.set_test_account(self.default_appname, "account-service", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_wrong_root(self):
        '''Test check_service() - wrong root'''
        xml = self._stub_service(root="wrongroot")
        self.set_test_account(self.default_appname, "account-service", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_wrong_missing_type(self):
        '''Test check_service() - missing type'''
        xml = self._stub_service(do_subtree=False)
        service_name = etree.SubElement(xml, "name")
        service_name.text = "Foo"
        service_provider = etree.SubElement(xml, "provider")
        service_provider.text = "some-provider"
        self.set_test_account(self.default_appname, "account-service", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_wrong_missing_name(self):
        '''Test check_service() - missing name'''
        xml = self._stub_service(do_subtree=False)
        service_type = etree.SubElement(xml, "type")
        service_type.text = "webapps"
        service_provider = etree.SubElement(xml, "provider")
        service_provider.text = "some-provider"
        self.set_test_account(self.default_appname, "account-service", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_wrong_missing_provider(self):
        '''Test check_service() - missing provider'''
        xml = self._stub_service(do_subtree=False)
        service_type = etree.SubElement(xml, "type")
        service_type.text = "webapps"
        service_name = etree.SubElement(xml, "name")
        service_name.text = "Foo"
        self.set_test_account(self.default_appname, "account-service", xml)
        c = ClickReviewAccounts(self.test_name)
        c.check_service()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
