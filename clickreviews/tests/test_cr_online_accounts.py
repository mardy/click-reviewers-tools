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

    def _stub_application(self):
        '''Stub application xml'''
        id = "%s_%s" % (self.test_manifest["name"], self.default_appname)
        xml = etree.Element("application", id="%s" % id)
        services = etree.SubElement(xml, "services")
        elem1 = etree.SubElement(services, "service", id="element1")
        desc1 = etree.SubElement(elem1, "description")
        desc1.text = "elem1 description"
        elem2 = etree.SubElement(services, "service", id="element2")
        desc2 = etree.SubElement(elem2, "description")
        desc2.text = "elem2 description"
        return xml

    def test_check_application(self):
        '''Test check_application()'''
        self.set_test_account(self.default_appname, "account-application",
                              self._stub_application())
        c = ClickReviewAccounts(self.test_name)
        c.check_application()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)
