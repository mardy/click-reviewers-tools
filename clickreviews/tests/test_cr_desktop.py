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
    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()

    def test_check_desktop_file(self):
        '''Test check_desktop_file()'''
        c = ClickReviewDesktop(self.test_name)
        c.check_desktop_file()
        r = c.click_report
        expected = dict()
        expected['info'] = dict()
        expected['warn'] = dict()
        expected['error'] = dict()
        expected['info']['desktop_files_usable'] = "OK"
        expected['info']['desktop_files_available'] = "OK"
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
        expected['info']['desktop_validates (%s)' %
                         self.default_appname] = "OK"
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

    def test_check_desktop_exec_webbrowser_with_url_patterns(self):
        '''Test check_desktop_exec_webbrowser with --webappUrlPatterns'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_with_model_search_path(self):
        '''Test check_desktop_exec_webbrowser with --webappModelSearchPath'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappModelSearchPath=. " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 0}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_without_required(self):
        '''Test check_desktop_exec_webbrowser without required'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_without_minimal(self):
        '''Test check_desktop_exec_webbrowser without minimal'''
        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
        self.check_results(r, expected_counts)

    def test_check_desktop_exec_webbrowser_with_both_required(self):
        '''Test check_desktop_exec_webbrowser with both required'''

        c = ClickReviewDesktop(self.test_name)
        ex = "webbrowser-app --enable-back-forward --webapp " + \
             "--webappUrlPatterns=https?://mobile.twitter.com/* " + \
             "--webappModelSearchPath=. " + \
             "http://mobile.twitter.com"
        self.set_test_desktop(self.default_appname,
                              "Exec",
                              ex)
        c.check_desktop_exec_webbrowser()
        r = c.click_report
        expected_counts = {'info': None, 'warn': 0, 'error': 1}
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
