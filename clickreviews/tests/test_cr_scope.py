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
            'ChildScopes': 'Child1',
            'DisplayName': 'Foo',
            'Description': 'Some description',
            'Author': 'Foo Ltd.',
            'Art': '',
            'Icon': 'foo.svg',
            'SearchHint': 'Search Foo',
            'HotKey': 'h',
            'IdleTimeout': '1234',
            'Invisible': 'false',
            'LocationDataNeeded': 'false',
            'ResultsTtlType': 'small',
        }

        return config_dict

    def test_check_scope_ini(self):
        '''Test check_scope_ini()'''
        scope = self._create_scope(self._stub_config())

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_missing_required1(self):
        '''Test check_scope_ini() - missing Description'''
        config = self._stub_config()
        del config['Description']
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
        '''Test check_scope_ini() - missing Author'''
        config = self._stub_config()
        del config['Author']
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_missing_required4(self):
        '''Test check_scope_ini() - missing multiple'''
        config = self._stub_config()
        del config['Description']
        del config['DisplayName']
        del config['Author']
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_translated_field(self):
        '''Test check_scope_ini() - translated field - es'''
        config = self._stub_config()
        config['searchhint[es]'] = "foo"
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_translated_field2(self):
        '''Test check_scope_ini() - translated field - pt_br'''
        config = self._stub_config()
        config['searchhint[pt_br]'] = "foo"
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_translated_field3(self):
        '''Test check_scope_ini() - translated field - ast'''
        config = self._stub_config()
        config['searchhint[ast]'] = "foo"
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_bad_translated_field(self):
        '''Test check_scope_ini() - bad translated field'''
        config = self._stub_config()
        config['searchhint[ba;r]'] = "foo"
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_bad_translated_field2(self):
        '''Test check_scope_ini() - translated field - de_DE'''
        config = self._stub_config()
        config['searchhint[de_DE]'] = "foo"
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
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

    def test_check_scope_ini_forbidden_field(self):
        '''Test check_scope_ini() - forbidden field'''
        config = self._stub_config()
        config['debugmode'] = "true"
        scope = self._create_scope(config)

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks(self):
        '''Test check_peer_hooks()'''
        c = ClickReviewScope(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["scope"] = "scope.ini"

        # add any required peer hooks
        tmp["apparmor"] = "foo.apparmor"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        # We should end up with 2 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_disallowed(self):
        '''Test check_peer_hooks() - disallowed'''
        c = ClickReviewScope(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["scope"] = "scope.ini"

        # add any required peer hooks
        tmp["apparmor"] = "foo.apparmor"

        # add something not allowed
        tmp["desktop"] = "foo.desktop"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_required(self):
        '''Test check_peer_hooks() - required'''
        c = ClickReviewScope(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["scope"] = "scope.ini"

        # skip adding required hooks

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_scope_ini_snappy_1504(self):
        '''Test check_scope_ini() - snappy 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        scope = self._create_scope(self._stub_config())

        self.set_test_scope(self.default_appname, scope)
        c = ClickReviewScope(self.test_name)
        c.check_scope_ini()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)
