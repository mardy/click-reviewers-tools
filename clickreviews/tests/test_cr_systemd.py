'''test_cr_systemd.py: tests for the cr_systemd module'''
#
# Copyright (C) 2015 Canonical Ltd.
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

from clickreviews.cr_systemd import ClickReviewSystemd
import clickreviews.cr_tests as cr_tests


class TestClickReviewSystemd(cr_tests.TestClickReview):
    """Tests for the lint review tool."""
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def _create_ports(self, hook=False):
        port = "port"
        negotiable = "negotiable"
        if hook:  # handle weird formatting in .snappy-systemd
            port = "Port"
            negotiable = "Negotiable"
        ports = {'internal': {'int1': {port: '8081/tcp', negotiable: True}},
                 'external': {'ext1': {port: '80/tcp', negotiable: False},
                              'ext2': {port: '88/udp'}
                              }
                 }
        return ports

    def _set_service(self, entries, name=None):
        d = dict()
        if name is None:
            d['name'] = self.default_appname
        else:
            d['name'] = name
        for (key, value) in entries:
            d[key] = value
        self.set_test_pkg_yaml("services", [d])
        self.set_test_systemd(d['name'], 'name', d['name'])

    def test_check_required(self):
        '''Test check_required() - has start and description'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        c = ClickReviewSystemd(self.test_name)
        c.check_required()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_required_empty_value(self):
        '''Test check_required() - empty start'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        c = ClickReviewSystemd(self.test_name)
        c.check_required()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_required_bad_value(self):
        '''Test check_required() - bad start'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value=[])
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        c = ClickReviewSystemd(self.test_name)
        c.check_required()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_required_multiple(self):
        '''Test check_required() - multiple'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value="/bin/foo-stop")
        c = ClickReviewSystemd(self.test_name)
        c.check_required()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_required_multiple2(self):
        '''Test check_required() - multiple with nonexistent'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        self.set_test_systemd(self.default_appname,
                              key="nonexistent",
                              value="foo")
        c = ClickReviewSystemd(self.test_name)
        c.check_required()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_optional_none(self):
        '''Test check_optional() - start only'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        c = ClickReviewSystemd(self.test_name)
        c.check_optional()
        r = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_optional_stop_empty(self):
        '''Test check_optional() - with empty stop'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value="")
        c = ClickReviewSystemd(self.test_name)
        c.check_optional()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_optional_stop_bad(self):
        '''Test check_optional() - with bad stop'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value=[])
        c = ClickReviewSystemd(self.test_name)
        c.check_optional()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_optional_stop_nonexistent(self):
        '''Test check_optional() - with stop plus nonexistent'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value="bin/bar")
        self.set_test_systemd(self.default_appname,
                              key="nonexistent",
                              value="foo")
        c = ClickReviewSystemd(self.test_name)
        c.check_optional()
        r = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_optional_stop_without_start(self):
        '''Test check_optional() - with stop, no start'''
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value="/bin/bar")
        c = ClickReviewSystemd(self.test_name)
        c.check_optional()
        r = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_optional_stop_without_start2(self):
        '''Test check_optional() - with stop, nonexistent, no start'''
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value="/bin/bar")
        self.set_test_systemd(self.default_appname,
                              key="nonexistent",
                              value="example.com")
        c = ClickReviewSystemd(self.test_name)
        c.check_optional()
        r = c.click_report
        expected_counts = {'info': 5, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_unknown(self):
        '''Test check_unknown()'''
        self.set_test_systemd(self.default_appname,
                              key="nonexistent",
                              value="foo")
        c = ClickReviewSystemd(self.test_name)
        c.check_unknown()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_unknown_multiple(self):
        '''Test check_unknown() - multiple with nonexistent'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value="bin/bar")
        self.set_test_systemd(self.default_appname,
                              key="nonexistent",
                              value="foo")
        c = ClickReviewSystemd(self.test_name)
        c.check_unknown()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks(self):
        '''Test check_peer_hooks()'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        c = ClickReviewSystemd(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["snappy-systemd"] = "meta/foo.snappy-systemd"

        # add required hooks
        tmp["apparmor"] = "meta/foo.apparmor"

        # update the manifest and test_manifest
        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        # We should end up with 2 info
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks2(self):
        '''Test check_peer_hooks() - apparmor-profile'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        c = ClickReviewSystemd(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["snappy-systemd"] = "meta/foo.snappy-systemd"

        # add required hooks
        tmp["apparmor-profile"] = "meta/foo.profile"

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
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        c = ClickReviewSystemd(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["snappy-systemd"] = "meta/foo.snappy-systemd"

        # add required hooks
        tmp["apparmor"] = "meta/foo.apparmor"

        # add something not allowed
        tmp["bin-path"] = "bin/bar"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_disallowed2(self):
        '''Test check_peer_hooks() - disallowed (nonexistent)'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        c = ClickReviewSystemd(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["snappy-systemd"] = "meta/foo.snappy-systemd"

        # add required hooks
        tmp["apparmor"] = "meta/foo.apparmor"

        # add something not allowed
        tmp["nonexistent"] = "nonexistent-hook"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_description(self):
        '''Test check_service_description()'''
        self.set_test_systemd(self.default_appname,
                              "description",
                              "some description")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_description()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_description_unspecified(self):
        '''Test check_service_description() - unspecified'''
        self.set_test_systemd(self.default_appname,
                              "description",
                              None)
        c = ClickReviewSystemd(self.test_name)
        c.check_service_description()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_description_empty(self):
        '''Test check_service_description() - empty'''
        self.set_test_systemd(self.default_appname,
                              "description",
                              "")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_description()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_start(self):
        '''Test check_service_start()'''
        self.set_test_systemd(self.default_appname,
                              "start",
                              "some/start")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_start()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_start_unspecified(self):
        '''Test check_service_start() - unspecified'''
        self.set_test_systemd(self.default_appname,
                              "start",
                              None)
        c = ClickReviewSystemd(self.test_name)
        c.check_service_start()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_start_empty(self):
        '''Test check_service_start() - empty'''
        self.set_test_systemd(self.default_appname,
                              "start",
                              "")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_start()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_start_absolute_path(self):
        '''Test check_service_start() - absolute path'''
        self.set_test_systemd(self.default_appname,
                              "start",
                              "/foo/bar/some/start")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_start()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_stop(self):
        '''Test check_service_stop()'''
        self.set_test_systemd(self.default_appname,
                              "stop",
                              "some/stop")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_stop_unspecified(self):
        '''Test check_service_stop() - unspecified'''
        self.set_test_systemd(self.default_appname,
                              "stop",
                              None)
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_stop_empty(self):
        '''Test check_service_stop() - empty'''
        self.set_test_systemd(self.default_appname,
                              "stop",
                              "")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_stop_absolute_path(self):
        '''Test check_service_stop() - absolute path'''
        self.set_test_systemd(self.default_appname,
                              "stop",
                              "/foo/bar/some/stop")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_poststop(self):
        '''Test check_service_poststop()'''
        self.set_test_systemd(self.default_appname,
                              "poststop",
                              "some/poststop")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_poststop()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_poststop_unspecified(self):
        '''Test check_service_poststop() - unspecified'''
        self.set_test_systemd(self.default_appname,
                              "poststop",
                              None)
        c = ClickReviewSystemd(self.test_name)
        c.check_service_poststop()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_poststop_empty(self):
        '''Test check_service_poststop() - empty'''
        self.set_test_systemd(self.default_appname,
                              "poststop",
                              "")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_poststop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_poststop_absolute_path(self):
        '''Test check_service_poststop() - absolute path'''
        self.set_test_systemd(self.default_appname,
                              "poststop",
                              "/foo/bar/some/poststop")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_poststop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_stop_timeout(self):
        '''Test check_service_stop_timeout()'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        self.set_test_systemd(self.default_appname,
                              key="stop-timeout",
                              value=30)
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_stop_timeout2(self):
        '''Test check_service_stop_timeout() - with granularity'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        self.set_test_systemd(self.default_appname,
                              key="stop-timeout",
                              value="30s")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_service_stop_timeout_empty(self):
        '''Test check_service_stop_timeout() - empty'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        self.set_test_systemd(self.default_appname,
                              key="stop-timeout",
                              value="")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_stop_timeout_bad(self):
        '''Test check_service_stop_timeout() - bad'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        self.set_test_systemd(self.default_appname,
                              key="stop-timeout",
                              value="a")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_stop_timeout_bad2(self):
        '''Test check_service_stop_timeout() - bad with granularity'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        self.set_test_systemd(self.default_appname,
                              key="stop-timeout",
                              value="30a")
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_stop_timeout_range_low(self):
        '''Test check_service_stop_timeout() - out of range (low)'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        self.set_test_systemd(self.default_appname,
                              key="stop-timeout",
                              value=-1)
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_service_stop_timeout_range_high(self):
        '''Test check_service_stop_timeout() - out of range (high)'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        self.set_test_systemd(self.default_appname,
                              key="stop-timeout",
                              value=61)
        c = ClickReviewSystemd(self.test_name)
        c.check_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_description(self):
        '''Test check_snappy_service_description()'''
        self._set_service([("description", "some description")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_description()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_description_unspecified(self):
        '''Test check_snappy_service_description() - unspecified'''
        # self._set_service([("description", None)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_description()
        r = c.click_report
        # required check is done elsewhere, so no error
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_description_empty(self):
        '''Test check_snappy_service_description() - empty'''
        self._set_service([("description", "")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_description()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_start(self):
        '''Test check_snappy_service_start()'''
        self._set_service([("start", "some/start")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_start()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_start_unspecified(self):
        '''Test check_snappy_service_start() - unspecified'''
        # self._set_service([("start", None)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_start()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_start_empty(self):
        '''Test check_snappy_service_start() - empty'''
        self._set_service([("start", "")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_start()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_start_absolute_path(self):
        '''Test check_snappy_service_start() - absolute path'''
        self._set_service([("start", "/foo/bar/some/start")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_start()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop(self):
        '''Test check_snappy_service_stop()'''
        self._set_service([("stop", "some/stop")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_stop()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_unspecified(self):
        '''Test check_snappy_service_stop() - unspecified'''
        # self._set_service([("stop", None)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_stop()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_empty(self):
        '''Test check_snappy_service_stop() - empty'''
        self._set_service([("stop", "")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_stop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_absolute_path(self):
        '''Test check_snappy_service_stop() - absolute path'''
        self._set_service([("stop", "/foo/bar/some/stop")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_stop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_poststop(self):
        '''Test check_snappy_service_poststop()'''
        self._set_service([("poststop", "some/poststop")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_poststop()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_poststop_unspecified(self):
        '''Test check_snappy_service_poststop() - unspecified'''
        # self._set_service([("poststop", None)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_poststop()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_poststop_empty(self):
        '''Test check_snappy_service_poststop() - empty'''
        self._set_service([("poststop", "")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_poststop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_poststop_absolute_path(self):
        '''Test check_snappy_service_poststop() - absolute path'''
        self._set_service([("poststop", "/foo/bar/some/poststop")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_poststop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_timeout(self):
        '''Test check_snappy_service_stop_timeout()'''
        self._set_service([("start", "bin/foo"),
                           ("description", "something"),
                           ("stop-timeout", 30)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_timeout_empty(self):
        '''Test check_snappy_service_stop_timeout() - empty'''
        self._set_service([("start", "bin/foo"),
                           ("description", "something"),
                           ("stop-timeout", "")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_timeout_bad(self):
        '''Test check_snappy_service_stop_timeout() - bad'''
        self._set_service([("start", "bin/foo"),
                           ("description", "something"),
                           ("stop-timeout", "a")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_timeout_range_low(self):
        '''Test check_snappy_service_stop_timeout() - out of range (low)'''
        self._set_service([("start", "bin/foo"),
                           ("description", "something"),
                           ("stop-timeout", -1)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_timeout_range_high(self):
        '''Test check_snappy_service_stop_timeout() - out of range (high)'''
        self._set_service([("start", "bin/foo"),
                           ("description", "something"),
                           ("stop-timeout", 61)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['foo'] = "meta/foo.snappy-systemd"
        c.check_snappy_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_pkgname(self):
        '''Test check_snappy_service_bus_name() - pkgname'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", name)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_appname(self):
        '''Test check_snappy_service_bus_name() - appname'''
        name = self.test_name.split('_')[0]
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "%s.%s" % (name, "test-app"))])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_pkgname_vendor(self):
        '''Test check_snappy_service_bus_name() - pkgname with vendor'''
        name = "foo"
        self.set_test_pkg_yaml("name", name)
        self.set_test_pkg_yaml("vendor", "f <f@isp.com>")
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "com.isp.%s" % name)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.is_snap = True
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_appname_vendor(self):
        '''Test check_snappy_service_bus_name() - appname with vendor'''
        name = "foo"
        self.set_test_pkg_yaml("name", name)
        self.set_test_pkg_yaml("vendor", "f <f@isp.com>")
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "com.isp.%s.%s" % (name, "test-app"))])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.is_snap = True
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': 3, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_pkgname_bad(self):
        '''Test check_snappy_service_bus_name() - bad pkgname'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", name + "-bad")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_appname_bad(self):
        '''Test check_snappy_service_bus_name() - bad appname'''
        name = self.test_name.split('_')[0]
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "%s.%s-bad" % (name, "test-app"))])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_pkgname_vendor_bad(self):
        '''Test check_snappy_service_bus_name() - bad pkgname with vendor'''
        name = "foo"
        self.set_test_pkg_yaml("name", name)
        self.set_test_pkg_yaml("vendor", "f <f@isp.com>")
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "com.isp.%s-bad" % name)])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.is_snap = True
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_appname_vendor_bad(self):
        '''Test check_snappy_service_bus_name() - bad appname with vendor'''
        name = "foo"
        self.set_test_pkg_yaml("name", name)
        self.set_test_pkg_yaml("vendor", "f <f@isp.com>")
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "com.isp.%s.%s-bad" % (name,
                                                               "test-app"))])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.is_snap = True
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_empty(self):
        '''Test check_snappy_service_bus_name() - bad (empty)'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_bad_regex(self):
        '''Test check_snappy_service_bus_name() - bad (regex)'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "name$")])
        c = ClickReviewSystemd(self.test_name)
        c.systemd_files['test-app'] = "meta/test-app.snappy-systemd"
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

    def test_check_service_ports(self):
        '''Test check_service_ports()'''
        ports = self._create_ports(hook=True)
        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_service_ports()
        r = c.click_report
        expected_counts = {'info': 8, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports(self):
        '''Test check_snappy_service_ports()'''
        ports = self._create_ports()
        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': 8, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_internal(self):
        '''Test check_snappy_service_ports() - internal'''
        ports = self._create_ports()
        del ports['internal']
        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': 6, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_external(self):
        '''Test check_snappy_service_ports() - external'''
        ports = self._create_ports()
        del ports['external']
        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_empty(self):
        '''Test check_snappy_service_ports() - empty'''
        ports = self._create_ports()
        del ports['internal']
        del ports['external']
        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_bad_key(self):
        '''Test check_snappy_service_ports() - bad key'''
        ports = self._create_ports()
        ports['xternal'] = ports['external']
        del ports['external']

        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_missing_internal(self):
        '''Test check_snappy_service_ports() - missing internal'''
        ports = self._create_ports()
        del ports['internal']['int1']

        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_missing_external(self):
        '''Test check_snappy_service_ports() - missing external'''
        ports = self._create_ports()
        del ports['external']['ext1']
        del ports['external']['ext2']

        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_missing_external_subkey(self):
        '''Test check_snappy_service_ports() - missing external subkey'''
        ports = self._create_ports()
        del ports['external']['ext2']['port']

        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_invalid_internal_subkey(self):
        '''Test check_snappy_service_ports() - invalid internal subkey'''
        ports = self._create_ports()
        ports['internal']['int1']['prt'] = ports['internal']['int1']['port']
        del ports['internal']['int1']['port']
        del ports['internal']['int1']['negotiable']

        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_invalid_internal_port(self):
        '''Test check_snappy_service_ports() - invalid internal port'''
        ports = self._create_ports()
        ports['internal']['int1']['port'] = "bad/8080"

        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_invalid_internal_low_port(self):
        '''Test check_snappy_service_ports() - invalid internal low port'''
        ports = self._create_ports()
        ports['internal']['int1']['port'] = "0/tcp"

        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_invalid_internal_high_port(self):
        '''Test check_snappy_service_ports() - invalid internal high port'''
        ports = self._create_ports()
        ports['internal']['int1']['port'] = "65536/tcp"

        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_ports_invalid_internal_negotiable(self):
        '''Test check_snappy_service_ports() - invalid internal negotiable'''
        ports = self._create_ports()
        ports['internal']['int1']['negotiable'] = -99999999

        self.set_test_systemd(self.default_appname, "ports", ports)
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_ports()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
