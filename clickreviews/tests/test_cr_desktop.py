'''test_cr_desktop.py: tests for the cr_desktop module'''
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

from clickreviews.cr_desktop import ClickReviewDesktop
import clickreviews.cr_tests as cr_tests


class TestClickReviewDesktop(cr_tests.TestClickReview):
    """Tests for the desktop review tool."""

    def test_check_desktop_file(self):
        '''Test check_desktop_file()'''
        c = ClickReviewDesktop(self.test_name)
        c.check_desktop_file()
        r = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        name = c._get_check_name('files_usable')
        expected['info'][name] = {"text": "OK"}
        self.check_results(r, expected=expected)

    def test_check_desktop_file_valid(self):
        '''Test check_desktop_file_valid()'''
        c = ClickReviewDesktop(self.test_name)
        c.check_desktop_file_valid()
        r = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        name = c._get_check_name('validates', app=self.default_appname)
        expected['info'][name] = {"text": "OK"}
        self.check_results(r, expected=expected)

    def test_check_desktop_file_valid_missing_exec(self):
        '''Test check_desktop_file_valid() - missing Exec'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec", None)
        c.check_desktop_file_valid()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_has_deprecated_exec(self):
        '''Test check_desktop_exec() - Exec has deprecated exec'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec", "cordova-ubuntu-2.8 .")
        c.check_desktop_exec()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_file_has_valid_exec(self):
        '''Test check_desktop_exec() - Exec has valid exec'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec", "qmlscene   $@ myApp.qml")
        c.check_desktop_exec()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_latest_version(self):
        '''Test check_desktop_version()'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Version", "1.5")
        c.check_desktop_version()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_unsupported_version(self):
        '''Test check_desktop_version() - unsupported Version'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Version", "2.0")
        c.check_desktop_version()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_file_valid_empty_name(self):
        '''Test check_desktop_file_valid() - empty Name'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Name", "")
        c.check_desktop_file_valid()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_required_keys(self):
        '''Test check_desktop_required_keys()'''
        c = ClickReviewDesktop(self.test_name)
        c.check_desktop_required_keys()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_required_keys_missing(self):
        '''Test check_desktop_required_keys()'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Name", None)
        c.check_desktop_required_keys()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_x_ubuntu_gettext_domain_missing(self):
        '''Test check_desktop_x_ubuntu_gettext_domain when missing'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "X-Ubuntu-Gettext-Domain", None)
        c.check_desktop_x_ubuntu_gettext_domain()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_x_ubuntu_gettext_domain_empty(self):
        '''Test check_desktop_x_ubuntu_gettext_domain when empty'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "X-Ubuntu-Gettext-Domain", "")
        c.check_desktop_x_ubuntu_gettext_domain()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_x_ubuntu_gettext_domain_valid(self):
        '''Test check_desktop_x_ubuntu_gettext_domain valid'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "X-Ubuntu-Gettext-Domain",
                              self.test_control['Package'])
        c.check_desktop_x_ubuntu_gettext_domain()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_x_ubuntu_gettext_domain_mismatch(self):
        '''Test check_desktop_x_ubuntu_gettext_domain doesn't match'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "X-Ubuntu-Gettext-Domain",
                              "com.example.mismatch")
        c.check_desktop_x_ubuntu_gettext_domain()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_args_with_url_patterns(self):
        '''Test check_desktop_exec_webapp_args with --webappUrlPatterns'''
        for exe in ['webbrowser-app --webapp', 'webapp-container']:
            c = ClickReviewDesktop(self.test_name)
            ex = "%s --enable-back-forward --webapp " % exe + \
                 "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
                 "http://mobile.twitter.com"
            self.set_test_desktop(self.default_appname,
                                  "Exec",
                                  ex)
            c.check_desktop_exec_webapp_args()
            r = c.click_report
            expected_counts = {'info': None, 'warn': 0, 'error': 0}
            self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_args_with_model_search_path(self):
        '''Test check_desktop_exec_webapp_args with --webappModelSearchPath'''
        c = ClickReviewDesktop(self.test_name)
        for exe in ['webbrowser-app --webapp', 'webapp-container']:
            ex = "%s --enable-back-forward " % exe + \
                 "--webappModelSearchPath=. " + \
                 "http://mobile.twitter.com"
            self.set_test_desktop(self.default_appname,
                                  "Exec",
                                  ex)
            c.check_desktop_exec_webapp_args()
            r = c.click_report
            expected_counts = {'info': None, 'warn': 0, 'error': 0}
            self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_args_without_required(self):
        '''Test check_desktop_exec_webapp_args without required'''
        for exe in ['webbrowser-app --webapp', 'webapp-container']:
            c = ClickReviewDesktop(self.test_name)
            ex = "%s --enable-back-forward " % exe + \
                 "http://mobile.twitter.com"
            self.set_test_desktop(self.default_appname,
                                  "Exec",
                                  ex)
            c.check_desktop_exec_webapp_args()
            r = c.click_report
            expected_counts = {'info': None, 'warn': 0, 'error': 1}
            self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_args_without_optional(self):
        '''Test check_desktop_exec_webapp_args without optional
           --enable-back-forward'''
        for exe in ['webbrowser-app --webapp', 'webapp-container']:
            c = ClickReviewDesktop(self.test_name)
            ex = "%s " % exe + \
                 "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
                 "http://mobile.twitter.com"
            self.set_test_desktop(self.default_appname,
                                  "Exec",
                                  ex)
            c.check_desktop_exec_webapp_args()
            r = c.click_report
            expected_counts = {'info': 2, 'warn': 0, 'error': 0}
            self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_args_with_both_required(self):
        '''Test check_desktop_exec_webbrowser with both required'''
        for exe in ['webbrowser-app --webapp', 'webapp-container']:
            c = ClickReviewDesktop(self.test_name)
            ex = "%s --enable-back-forward " % exe + \
                 "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
                 "--webappModelSearchPath=. " + \
                 "http://mobile.twitter.com"
            self.set_test_desktop(self.default_appname,
                                  "Exec",
                                  ex)
            c.check_desktop_exec_webapp_args()
            r = c.click_report
            expected_counts = {'info': None, 'warn': 0, 'error': 0}
            self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_missing_exec(self):
        '''Test check_desktop_exec_webbrowser - missing exec'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              None)
        c.check_desktop_exec_webbrowser()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_missing_webapp(self):
        '''Test check_desktop_exec_webbrowser - missing --webapp'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_non1310(self):
        '''Test check_desktop_exec_webbrowser without 13.10'''
        self.set_test_manifest("framework", "not-ubuntu-sdk-13.10")
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --webapp --enable-back-forward " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_container_has_webapp(self):
        '''Test check_desktop_exec_webapp_container - has --webapp'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webapp-container --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_container()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_container_1310a(self):
        '''Test check_desktop_exec_webapp_container on 13.10 framework'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webapp-container --enable-back-forward " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_container()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_container_1310b(self):
        '''Test check_desktop_exec_webapp_container on non-13.10 framework'''
        self.set_test_manifest("framework", "not-ubuntu-sdk-13.10")
        c = ClickReviewDesktop(self.test_name)
        ex = "webapp-container --enable-back-forward " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_container()
        r = c.click_report
        expected_counts = {'info': 2, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_container_html5_launcher_1410(self):
        '''Test check_desktop_exec_webapp_container - html5 launcher 14.10'''
        self.set_test_manifest("framework", "ubuntu-sdk-14.10")
        ex = "ubuntu-html5-app-launcher $@ --www=www"
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_container()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_container_html5_launcher_1510(self):
        '''Test check_desktop_exec_webapp_container - html5 launcher 15.10'''
        self.set_test_manifest("framework", "ubuntu-sdk-15.10")
        ex = "ubuntu-html5-app-launcher $@ --www=www"
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_container()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webapp_container_missing_exec(self):
        '''Test check_desktop_exec_webapp_container - missing exec'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              None)
        c.check_desktop_exec_webapp_container()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_valid(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() valid'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_missing_exec(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() - missing exec'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              None)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_missing_arg(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() missing arg'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_multiple_args(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() multiple args'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_no_https(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() missing https?'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=http://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_no_trailing_glob(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() no trailing glob'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/ " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_trailing_glob1(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() - trailing glob1'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_trailing_glob2(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() - trailing glob2'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://m.bbc.co.uk/sport* " + \
             "http://m.bbc.co.uk/sport"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_trailing_glob3(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() - trailing glob3'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://*.bbc.co.uk/sport* " + \
             "http://*.bbc.co.uk/sport"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_trailing_glob4(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() - trailing glob4'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://www.bbc.co.uk* " + \
             "http://www.bbc.co.uk"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_embedded_glob(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() embedded glob'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com*/* " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 2, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_leading_glob(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() leading glob'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://*.twitter.com/* " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_target_mismatch(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() target mismatch'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.net"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_target_mismatch2(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() target mismatch2'''
        c = ClickReviewDesktop(self.test_name)
        # this shouldn't error or warn, but should give info
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "ftp://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_target_mismatch3(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() target mismatch3'''
        c = ClickReviewDesktop(self.test_name)
        # this shouldn't error or warn, but should give info
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/*," + \
             "https?://nonmatch.twitter.com/* " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_urlpatterns_target_missing(self):
        '''Test check_desktop_exec_webbrowser_urlpatterns() target missing'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/*"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_urlpatterns()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_valid(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath() valid'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "name", "foo")
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "includes",
                                      ['https?://mobile.twitter.com/*'])
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath=. http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_missing_exec(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath - missing exec'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              None)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_missing_arg(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath() missing arg'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_multiple_args(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath multiple args'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath=. " + \
             "--webappModelSearchPath=. " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_empty(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath() empty'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath= http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': 0, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_no_manifest(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath() no manifest'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath=. http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_bad_manifest(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath() bad manifest'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      None, None)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath=. http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_mult_manifest(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath mult manifest'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "name", "foo")
        self.set_test_webapp_manifest("unity-webapps-bar/manifest.json",
                                      "name", "bar")
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath=. http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_bad_includes(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath() bad includes'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "name", "foo")
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "includes", "not list")
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath=. http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_no_includes(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath() no includes'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "name", "foo")
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath=. http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_modelsearchpath_mismatch(self):
        '''Test check_desktop_exec_webbrowser_modelsearchpath() no includes'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "name", "foo")
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "includes",
                                      ['https?://mobile.twitter.net/*'])
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath=. http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser_modelsearchpath()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 1, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_local_app(self):
        '''Test test_check_desktop_exec_webbrowser_local_app() local app'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webapp-container ./www/index.html"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_args()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_no_homepage(self):
        '''Test check_desktop_exec_webbrowser_no_homepage() not local app'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "name", "foo")
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "includes",
                                      ['https?://mobile.twitter.net/*'])
        ex = "webapp-container --webapp='Zm9v' " + \
             "--enable-back-forward --webappModelSearchPath=."
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_args()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_field_code(self):
        '''Test check_desktop_exec_webbrowser_field_code() with field code'''
        c = ClickReviewDesktop(self.test_name)
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "name", "foo")
        self.set_test_webapp_manifest("unity-webapps-foo/manifest.json",
                                      "includes",
                                      ['https?://mobile.twitter.net/*'])
        ex = "webapp-container --webapp='Zm9v' " + \
             "--enable-back-forward --webappModelSearchPath=. %u"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_args()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_local_pattern(self):
        '''Test test_check_desktop_exec_webbrowser_local_pattern() invalid
        pattern'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webapp-container " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "./www/index.html"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_args()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_local_webapp(self):
        '''Test test_check_desktop_exec_webbrowser_local_webapp() invalid
        webapp cli'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webapp-container " + \
             "--webapp=DEADBEEF " + \
             "./www/index.html"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_args()
        r = c.click_report
        expected_counts = {'info': 1, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_local_model(self):
        '''Test test_check_desktop_exec_webbrowser_local_model() invalid
        model'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webapp-container " + \
             "--webappModelSearchPath=. " + \
             "./www/index.html"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webapp_args()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks(self):
        '''Test check_peer_hooks()'''
        c = ClickReviewDesktop(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["desktop"] = "foo.desktop"

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
        c = ClickReviewDesktop(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["desktop"] = "foo.desktop"

        # add any required peer hooks
        tmp["desktop"] = "foo.desktop"
        tmp["apparmor"] = "foo.apparmor"

        # add something not allowed
        tmp["nonexistent"] = "nonexistent-hook"

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_peer_hooks_required(self):
        '''Test check_peer_hooks() - required'''
        c = ClickReviewDesktop(self.test_name)

        # create a new hooks database for our peer hooks tests
        tmp = dict()

        # add our hook
        tmp["desktop"] = "foo.desktop"

        # skip adding required hooks

        c.manifest["hooks"][self.default_appname] = tmp
        self._update_test_manifest()

        # do the test
        c.check_peer_hooks()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_file_snappy_1504(self):
        '''Test check_desktop_file() - snappy 15.04'''
        self.set_test_pkgfmt("snap", "15.04")
        c = ClickReviewDesktop(self.test_name)
        c.check_desktop_file()
        r = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        name = c._get_check_name('files_usable')
        expected['info'][name] = {"text": "OK"}
        self.check_results(r, expected=expected)
