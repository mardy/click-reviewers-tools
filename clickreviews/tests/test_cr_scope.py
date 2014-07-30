'''test_cr_scope.py: tests for the cr_scope module'''
#
# Copyright (C) 2014 Canonical Ltd.
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

from clickreviews.cr_scope import ClickReviewScope
import clickreviews.cr_tests as cr_tests
import configparser


class TestClickReviewScope(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def _create_scope(self, config_dict=None):
        '''Create a scope to pass to tests'''
        scope = dict()
        scope["dir_rel"] = "scope-directory"
        scope["ini_file_rel"] = "%s/%s_%s.ini" % (scope["dir_rel"],
                                               self.default_appname,
                                               'foo')
        scope["scope_config"] = configparser.ConfigParser()
        scope["scope_config"]['ScopeConfig'] = config_dict

        return scope

    def _stub_config(self):
        '''Stub configparser file'''
        config_dict = {
            'ScopeRunner': "%s" % self.default_appname,
            'DisplayName': 'Foo',
            'Description': 'Some description',
            'Author': 'Foo Ltd.',
            'Art': '',
            'Icon': 'foo.svg',
            'SearchHint': 'Search Foo',
        }

        return config_dict

    def test_check_scope_ini(self):
        '''Test check_scope_ini()'''
        scope = self._create_scope(self._stub_config())

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_missing_required1(self):
        '''Test check_scope_ini() - missing ScopeRunner'''
        config = self._stub_config()
        del config['ScopeRunner']
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_missing_required2(self):
        '''Test check_scope_ini() - missing DisplayName'''
        config = self._stub_config()
        del config['DisplayName']
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_missing_required3(self):
        '''Test check_scope_ini() - missing Icon'''
        config = self._stub_config()
        del config['Icon']
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_missing_required4(self):
        '''Test check_scope_ini() - missing SearchHint'''
        config = self._stub_config()
        del config['SearchHint']
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_missing_required5(self):
        '''Test check_scope_ini() - missing multiple'''
        config = self._stub_config()
        del config['ScopeRunner']
        del config['DisplayName']
        del config['Icon']
        del config['SearchHint']
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_nonexistent_field(self):
        '''Test check_scope_ini() - non-existent field'''
        config = self._stub_config()
        config['nonexistent'] = "foo"
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)
