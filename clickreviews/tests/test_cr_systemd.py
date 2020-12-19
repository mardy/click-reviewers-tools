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
        super().setUp()
        self.set_test_pkgfmt("snap", "15.04")

    def _create_ports(self):
        ports = {
            'internal': {'int1': {"port": '8081/tcp', "negotiable": True}},
            'external': {
                'ext1': {"port": '80/tcp', "negotiable": False},
                'ext2': {"port": '88/udp'}
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

    def test_check_snappy_required(self):
        '''Test check_required() - has start and description'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_required_empty_value(self):
        '''Test check_snappy_required() - empty start'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="")
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_required_bad_value(self):
        '''Test check_snappy_required() - bad start'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value=[])
        self.set_test_systemd(self.default_appname,
                              key="description",
                              value="something")
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_required()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_required_multiple(self):
        '''Test check_snappy_required() - multiple'''
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
        c.check_snappy_required()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_required_multiple2(self):
        '''Test check_snappy_required() - multiple with nonexistent'''
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
        c.check_snappy_required()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_optional_none(self):
        '''Test check_snappy_optional() - start only'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': 9, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_optional_stop_empty(self):
        '''Test check_snappy_optional() - with empty stop'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value="")
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_optional_stop_bad(self):
        '''Test check_snappy_optional() - with bad stop'''
        self.set_test_systemd(self.default_appname,
                              key="start",
                              value="/bin/foo")
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value=[])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_optional_stop_nonexistent(self):
        '''Test check_snappy_optional() - with stop plus nonexistent'''
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
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': 9, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_optional_stop_without_start(self):
        '''Test check_snappy_optional() - with stop, no start'''
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value="/bin/bar")
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': 9, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_optional_stop_without_start2(self):
        '''Test check_snappy_optional() - with stop, nonexistent, no start'''
        self.set_test_systemd(self.default_appname,
                              key="stop",
                              value="/bin/bar")
        self.set_test_systemd(self.default_appname,
                              key="nonexistent",
                              value="example.com")
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_optional()
        r = c.click_report
        expected_counts = {'info': 9, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_unknown(self):
        '''Test check_snappy_unknown()'''
        self.set_test_systemd(self.default_appname,
                              key="nonexistent",
                              value="foo")
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_unknown()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_unknown_multiple(self):
        '''Test check_snappy_unknown() - multiple with nonexistent'''
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
        c.check_snappy_unknown()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_description(self):
        '''Test check_snappy_service_description()'''
        self._set_service([("description", "some description")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_description()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_description_unspecified(self):
        '''Test check_snappy_service_description() - unspecified'''
        # self._set_service([("description", None)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_description()
        r = c.click_report
        # required check is done elsewhere, so no error
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_description_empty(self):
        '''Test check_snappy_service_description() - empty'''
        self._set_service([("description", "")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_description()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_start(self):
        '''Test check_snappy_service_start()'''
        self._set_service([("start", "some/start")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_start()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_start_unspecified(self):
        '''Test check_snappy_service_start() - unspecified'''
        # self._set_service([("start", None)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_start()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_start_empty(self):
        '''Test check_snappy_service_start() - empty'''
        self._set_service([("start", "")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_start()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_start_absolute_path(self):
        '''Test check_snappy_service_start() - absolute path'''
        self._set_service([("start", "/foo/bar/some/start")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_start()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop(self):
        '''Test check_snappy_service_stop()'''
        self._set_service([("stop", "some/stop")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_stop()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_unspecified(self):
        '''Test check_snappy_service_stop() - unspecified'''
        # self._set_service([("stop", None)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_stop()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_empty(self):
        '''Test check_snappy_service_stop() - empty'''
        self._set_service([("stop", "")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_stop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_absolute_path(self):
        '''Test check_snappy_service_stop() - absolute path'''
        self._set_service([("stop", "/foo/bar/some/stop")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_stop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_poststop(self):
        '''Test check_snappy_service_poststop()'''
        self._set_service([("poststop", "some/poststop")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_poststop()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_poststop_unspecified(self):
        '''Test check_snappy_service_poststop() - unspecified'''
        # self._set_service([("poststop", None)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_poststop()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_poststop_empty(self):
        '''Test check_snappy_service_poststop() - empty'''
        self._set_service([("poststop", "")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_poststop()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_poststop_absolute_path(self):
        '''Test check_snappy_service_poststop() - absolute path'''
        self._set_service([("poststop", "/foo/bar/some/poststop")])
        c = ClickReviewSystemd(self.test_name)
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
        c.check_snappy_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_timeout_granularity(self):
        '''Test check_snappy_service_stop_timeout()'''
        self._set_service([("start", "bin/foo"),
                           ("description", "something"),
                           ("stop-timeout", '30s')])
        c = ClickReviewSystemd(self.test_name)
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
        c.check_snappy_service_stop_timeout()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_stop_timeout_bad_granularity(self):
        '''Test check_snappy_service_stop_timeout() - bad with granularity'''
        self._set_service([("start", "bin/foo"),
                           ("description", "something"),
                           ("stop-timeout", "30a")])
        c = ClickReviewSystemd(self.test_name)
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
        self.set_test_pkg_yaml("type", 'framework')
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_appname(self):
        '''Test check_snappy_service_bus_name() - appname'''
        name = self.test_name.split('_')[0]
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "%s.%s" % (name, "test-app"))])
        self.set_test_pkg_yaml("type", 'framework')
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': 4, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_missing_framework_app(self):
        '''Test check_snappy_service_bus_name() - missing framework (app)'''
        name = self.test_name.split('_')[0]
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "%s.%s" % (name, "test-app"))])
        self.set_test_pkg_yaml("type", 'app')
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_missing_framework_oem(self):
        '''Test check_snappy_service_bus_name() - missing framework (oem)'''
        name = self.test_name.split('_')[0]
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", "%s.%s" % (name, "test-app"))])
        self.set_test_pkg_yaml("type", 'oem')
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_bus_name_pkgname_bad(self):
        '''Test check_snappy_service_bus_name() - bad pkgname'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("bus-name", name + "-bad")])
        self.set_test_pkg_yaml("type", 'framework')
        c = ClickReviewSystemd(self.test_name)
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
        self.set_test_pkg_yaml("type", 'framework')
        c = ClickReviewSystemd(self.test_name)
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
        self.set_test_pkg_yaml("type", 'framework')
        c = ClickReviewSystemd(self.test_name)
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
        self.set_test_pkg_yaml("type", 'framework')
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_bus_name()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
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

    def test_check_snappy_service_listen_stream_abspkgname(self):
        '''Test check_snappy_service_listen_stream() - @pkgname'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", '@%s' % name)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_listen_stream()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_listen_stream_abspkgname2(self):
        '''Test check_snappy_service_listen_stream() - @pkgname_'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", '@%s_something' % name)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_listen_stream()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_listen_stream_bad_abstract(self):
        '''Test check_snappy_service_listen_stream() - bad (wrong name)'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", '@%s/nomatch' % name)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_listen_stream()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_listen_stream_bad_relative(self):
        '''Test check_snappy_service_listen_stream() - bad (not / or @)'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", name)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_listen_stream()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_listen_stream_empty(self):
        '''Test check_snappy_service_listen_stream() - empty'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", "")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_listen_stream()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_socket_user(self):
        '''Test check_snappy_service_socket_user()'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", '@%s' % name),
                           ("socket-user", name)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_socket_user()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_socket_user_no_listen_stream(self):
        '''Test check_snappy_service_socket_user() - missing listen-stream'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("socket-user", name)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_socket_user()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_socket_user_bad(self):
        '''Test check_snappy_service_socket_user() - bad user'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", '@%s' % name),
                           ("socket-user", name + "nomatch")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_socket_user()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_socket_group(self):
        '''Test check_snappy_service_socket_group()'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", '@%s' % name),
                           ("socket-group", name)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_socket_group()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_socket_group_no_listen_stream(self):
        '''Test check_snappy_service_socket_group() - missing listen-stream'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("socket-group", name)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_socket_group()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_socket_group_bad(self):
        '''Test check_snappy_service_socket_group() - bad group'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", '@%s' % name),
                           ("socket-group", name + "nomatch")])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_socket_group()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 2}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_socket(self):
        '''Test check_snappy_service_socket()'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("listen-stream", '@%s' % name),
                           ("socket", True)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_socket()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_snappy_service_socket_no_listen_stream(self):
        '''Test check_snappy_service_socket() - missing listen-stream'''
        name = self.test_name.split('_')[0]
        self.set_test_pkg_yaml("name", name)
        self._set_service([("start", "bin/test-app"),
                           ("description", "something"),
                           ("socket", True)])
        c = ClickReviewSystemd(self.test_name)
        c.check_snappy_service_socket()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)
