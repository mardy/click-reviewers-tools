'''cr_tests.py: common setup and tests for test modules'''
#
# Copyright (C) 2013-2015 Canonical Ltd.
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

import io
import json
import os
import tempfile
from xdg.DesktopEntry import DesktopEntry
import yaml

from unittest.mock import patch
from unittest import TestCase

from clickreviews.cr_lint import MINIMUM_CLICK_FRAMEWORK_VERSION
import clickreviews.common as common

# These should be set in the test cases
TEST_CONTROL = ""
TEST_MANIFEST = ""
TEST_PKG_YAML = ""
TEST_HASHES_YAML = ""
TEST_README_MD = ""
TEST_SECURITY = dict()
TEST_SECURITY_PROFILES = dict()
TEST_DESKTOP = dict()
TEST_WEBAPP_MANIFESTS = dict()
TEST_URLS = dict()
TEST_SCOPES = dict()
TEST_CONTENT_HUB = dict()
TEST_ACCOUNTS_MANIFEST = dict()
TEST_ACCOUNTS_APPLICATION = dict()
TEST_ACCOUNTS_PROVIDER = dict()
TEST_ACCOUNTS_QML_PLUGIN = dict()
TEST_ACCOUNTS_SERVICE = dict()
TEST_PUSH_HELPER = dict()
TEST_BIN_PATH = dict()
TEST_FRAMEWORK = dict()
TEST_FRAMEWORK_POLICY = dict()
TEST_FRAMEWORK_POLICY_UNKNOWN = []
TEST_PKGFMT_TYPE = "click"
TEST_PKGFMT_VERSION = "0.4"


#
# Mock override functions
#
def _mock_func(self):
    '''Fake test function'''
    return


def _extract_control_file(self):
    '''Pretend we read the control file'''
    return io.StringIO(TEST_CONTROL)


def _extract_manifest_file(self):
    '''Pretend we read the manifest file'''
    return io.StringIO(TEST_MANIFEST)


def _extract_package_yaml(self):
    '''Pretend we read the package.yaml file'''
    return io.StringIO(TEST_PKG_YAML)


def _extract_hashes_yaml(self):
    '''Pretend we read the hashes.yaml file'''
    return io.StringIO(TEST_HASHES_YAML)


def _path_join(self, d, fn):
    '''Pretend we have a tempdir'''
    return os.path.join("/fake", fn)


def _get_sha512sum(self, fn):
    '''Pretend we found performed a sha512'''
    (rc, out) = common.cmd(['sha512sum', os.path.realpath(__file__)])
    if rc != 0:
        return None
    return out.split()[0]


def _extract_statinfo(self, fn):
    '''Pretend we found performed an os.stat()'''
    return os.stat(os.path.realpath(__file__))


def _extract_readme_md(self):
    '''Pretend we read the meta/readme.md file'''
    return TEST_README_MD


def _check_innerpath_executable(self, fn):
    '''Pretend we a file'''
    if '.nonexec' in fn:
        return False
    return True


def _extract_click_frameworks(self):
    '''Pretend we enumerated the click frameworks'''
    return ["ubuntu-sdk-13.10",
            "ubuntu-sdk-14.04-dev1",
            "ubuntu-sdk-14.04-html-dev1",
            "ubuntu-sdk-14.04-papi-dev1",
            "ubuntu-sdk-14.04-qml-dev1",
            "ubuntu-sdk-14.04",
            "ubuntu-sdk-14.04-html",
            "ubuntu-sdk-14.04-papi",
            "ubuntu-sdk-14.04-qml",
            "ubuntu-sdk-14.10-dev1",
            "ubuntu-sdk-14.10-html-dev1",
            "ubuntu-sdk-14.10-papi-dev1",
            "ubuntu-sdk-14.10-qml-dev1",
            "ubuntu-sdk-14.10-dev2",
            "ubuntu-sdk-14.10-html-dev2",
            "ubuntu-sdk-14.10-papi-dev2",
            "ubuntu-sdk-14.10-qml-dev2",
            ]


def _extract_security_manifest(self, app):
    '''Pretend we read the security manifest file'''
    return io.StringIO(TEST_SECURITY[app])


def _get_security_manifest(self, app):
    '''Pretend we read the security manifest file'''
    return ("%s.apparmor" % app, json.loads(TEST_SECURITY[app]))


def _extract_security_profile(self, app):
    '''Pretend we read the security profile'''
    return io.StringIO(TEST_SECURITY_PROFILES[app])


def _get_security_profile(self, app):
    '''Pretend we read the security profile'''
    return ("%s.profile" % app, TEST_SECURITY_PROFILES[app])


def _get_security_supported_policy_versions(self):
    '''Pretend we read the contens of /usr/share/apparmor/easyprof'''
    return [1.0, 1.1, 1.2, 1.3]


def _extract_desktop_entry(self, app):
    '''Pretend we read the desktop file'''
    return ("%s.desktop" % app, TEST_DESKTOP[app])


def _get_desktop_entry(self, app):
    '''Pretend we read the desktop file'''
    return TEST_DESKTOP[app]


def _extract_webapp_manifests(self):
    '''Pretend we read the webapp manifest files'''
    return TEST_WEBAPP_MANIFESTS


def _extract_url_dispatcher(self, app):
    '''Pretend we read the url dispatcher file'''
    return ("%s.url-dispatcher" % app, TEST_URLS[app])


def _extract_scopes(self, app):
    '''Pretend we found and read the files in the scope directories'''
    return TEST_SCOPES[app]


def _extract_content_hub(self, app):
    '''Pretend we read the content-hub file'''
    return ("%s.content.json" % app, TEST_CONTENT_HUB[app])


def _extract_account(self, app, account_type):
    '''Pretend we read the accounts file'''
    f = app
    val = None
    if account_type == "accounts":
        f += ".accounts"
        val = TEST_ACCOUNTS_MANIFEST[app]
    elif account_type == "account-application":
        f += ".application"
        val = TEST_ACCOUNTS_APPLICATION[app]
    elif account_type == "account-provider":
        f += ".provider"
        val = TEST_ACCOUNTS_PROVIDER[app]
    elif account_type == "account-qml-plugin":
        f += ".qml-plugin"
        val = TEST_ACCOUNTS_QML_PLUGIN[app]
    elif account_type == "account-service":
        f += ".service"
        val = TEST_ACCOUNTS_SERVICE[app]
    else:  # should never get here
        raise ValueError("Unknown account_type '%s'" % account_type)

    return (f, val)


def _extract_push_helper(self, app):
    '''Pretend we read the push-helper file'''
    return ("%s.push-helper.json" % app, TEST_PUSH_HELPER[app])


def _extract_bin_path(self, app):
    '''Pretend we found the bin-path file'''
    return ("%s" % TEST_BIN_PATH[app])


def _check_bin_path_executable(self, app):
    '''Pretend we found the bin-path file'''
    if TEST_BIN_PATH[app].endswith('.nonexec'):
        return False
    return True


def _extract_framework(self, app):
    '''Pretend we found the framework file'''
    return ("%s.framework" % app, TEST_FRAMEWORK[app])


def _extract_framework_policy(self):
    '''Pretend we found the framework policy files'''
    return (TEST_FRAMEWORK_POLICY, TEST_FRAMEWORK_POLICY_UNKNOWN)


def _has_framework_in_metadir(self):
    '''Pretend we found the framework file'''
    return True


def _pkgfmt_type(self):
    '''Pretend we found the pkgfmt type'''
    return TEST_PKGFMT_TYPE


def _pkgfmt_version(self):
    '''Pretend we found the pkgfmt version'''
    return TEST_PKGFMT_VERSION


def _detect_package(self, fn):
    '''Pretend we detected the package'''
    ver = 1
    if TEST_PKGFMT_TYPE == "snap" and TEST_PKGFMT_VERSION != "15.04":
        ver = 2
    return (TEST_PKGFMT_TYPE, ver)


def create_patches():
    # http://docs.python.org/3.4/library/unittest.mock-examples.html
    # Mock patching. Don't use decorators but instead patch in setUp() of the
    # child.
    patches = []
    patches.append(patch('clickreviews.common.Review._check_package_exists',
                   _mock_func))
    patches.append(patch(
        'clickreviews.cr_common.ClickReview._extract_control_file',
        _extract_control_file))
    patches.append(patch(
        'clickreviews.cr_common.ClickReview._extract_manifest_file',
        _extract_manifest_file))
    patches.append(patch(
        'clickreviews.cr_common.ClickReview._extract_package_yaml',
        _extract_package_yaml))
    patches.append(patch(
        'clickreviews.cr_common.ClickReview._extract_hashes_yaml',
        _extract_hashes_yaml))
    patches.append(patch('clickreviews.common.Review._path_join', _path_join))
    patches.append(patch(
        'clickreviews.common.Review._get_sha512sum', _get_sha512sum))
    patches.append(patch(
        'clickreviews.common.Review._extract_statinfo', _extract_statinfo))
    patches.append(patch(
        'clickreviews.cr_common.ClickReview._extract_click_frameworks',
        _extract_click_frameworks))
    patches.append(patch('clickreviews.common.unpack_pkg', _mock_func))
    patches.append(patch('clickreviews.common.raw_unpack_pkg', _mock_func))
    patches.append(patch('clickreviews.common.detect_package',
                   _detect_package))
    patches.append(patch('clickreviews.common.Review._list_all_files',
                   _mock_func))
    patches.append(patch(
        'clickreviews.common.Review._list_all_compiled_binaries', _mock_func))

    # lint overrides
    patches.append(patch(
                   'clickreviews.cr_lint.ClickReviewLint._list_control_files',
                   _mock_func))
    patches.append(patch(
        'clickreviews.cr_lint.ClickReviewLint._extract_readme_md',
        _extract_readme_md))
    patches.append(patch(
        'clickreviews.common.Review._check_innerpath_executable',
        _check_innerpath_executable))

    # security overrides
    patches.append(patch('clickreviews.cr_security.ClickReviewSecurity.'
                         '_extract_security_manifest',
                         _extract_security_manifest))
    patches.append(patch(
        'clickreviews.cr_security.ClickReviewSecurity._get_security_manifest',
        _get_security_manifest))
    patches.append(patch('clickreviews.cr_security.ClickReviewSecurity.'
                         '_extract_security_profile',
                         _extract_security_profile))
    patches.append(patch(
        'clickreviews.cr_security.ClickReviewSecurity._get_security_profile',
        _get_security_profile))

    # desktop overrides
    patches.append(patch(
        'clickreviews.cr_desktop.ClickReviewDesktop._extract_desktop_entry',
        _extract_desktop_entry))
    patches.append(patch(
        'clickreviews.cr_desktop.ClickReviewDesktop._get_desktop_entry',
        _get_desktop_entry))
    patches.append(patch(
        'clickreviews.cr_desktop.ClickReviewDesktop._extract_webapp_manifests',
        _extract_webapp_manifests))

    # url-dispatcher overrides
    patches.append(patch('clickreviews.cr_url_dispatcher.'
                         'ClickReviewUrlDispatcher._extract_url_dispatcher',
                         _extract_url_dispatcher))

    # scope overrides
    patches.append(patch(
        'clickreviews.cr_scope.ClickReviewScope._extract_scopes',
        _extract_scopes))

    # content-hub overrides
    patches.append(patch('clickreviews.cr_content_hub.ClickReviewContentHub.'
                         '_extract_content_hub',
                         _extract_content_hub))

    # online accounts overrides
    patches.append(patch(
        'clickreviews.cr_online_accounts.ClickReviewAccounts._extract_account',
        _extract_account))

    # push-helper overrides
    patches.append(patch('clickreviews.cr_push_helper.ClickReviewPushHelper.'
                         '_extract_push_helper',
                         _extract_push_helper))

    # bin-path overrides
    patches.append(patch(
        'clickreviews.cr_bin_path.ClickReviewBinPath._extract_bin_path',
        _extract_bin_path))
    patches.append(patch('clickreviews.cr_bin_path.ClickReviewBinPath.'
                         '_check_bin_path_executable',
                         _check_bin_path_executable))

    # framework overrides
    patches.append(patch(
        'clickreviews.cr_framework.ClickReviewFramework._extract_framework',
        _extract_framework))
    patches.append(patch('clickreviews.cr_framework.ClickReviewFramework.'
                         '_extract_framework_policy',
                         _extract_framework_policy))
    patches.append(patch('clickreviews.cr_framework.ClickReviewFramework.'
                         '_has_framework_in_metadir',
                         _has_framework_in_metadir))

    # pkgfmt
    patches.append(patch("clickreviews.common.Review._pkgfmt_type",
                   _pkgfmt_type))
    patches.append(patch("clickreviews.common.Review._pkgfmt_version",
                   _pkgfmt_version))

    return patches


class TestClickReview(TestCase):
    """Tests for the lint review tool."""
    def __init__(self, *args):
        if not hasattr(self, 'desktop_tmpdir'):
            self.desktop_tmpdir = \
                tempfile.mkdtemp(prefix="clickreview-test-desktop-")
        TestCase.__init__(self, *args)
        self._reset_test_data()

    def _reset_test_data(self):
        # dictionary representing DEBIAN/control
        self.test_control = dict()
        self.set_test_control('Package',
                              "com.ubuntu.developer.someuser.testapp")
        self.set_test_control('Version', "1.0")
        self.set_test_control('Click-Version', MINIMUM_CLICK_FRAMEWORK_VERSION)
        self.set_test_control('Architecture', "all")
        self.set_test_control('Maintainer',
                              "Some User <some.user@example.com>")
        self.set_test_control('Installed-Size', "111")
        self.set_test_control('Description', "My Test App")

        # dictionary representing DEBIAN/manifest
        self.test_manifest = dict()
        self.set_test_manifest("description",
                               "Some longish description of My Test App")
        self.set_test_manifest("framework", "ubuntu-sdk-13.10")
        self.set_test_manifest("maintainer", self.test_control['Maintainer'])
        self.set_test_manifest("name", self.test_control['Package'])
        self.set_test_manifest("title", self.test_control['Description'])
        self.set_test_manifest("version", self.test_control['Version'])
        self.test_manifest["hooks"] = dict()
        self.default_appname = "test-app"
        self.test_manifest["hooks"][self.default_appname] = dict()
        self.test_manifest["hooks"][self.default_appname]["apparmor"] = \
            "%s.apparmor" % self.default_appname
        self.test_manifest["hooks"][self.default_appname]["desktop"] = \
            "%s.desktop" % self.default_appname
        self.test_manifest["hooks"][self.default_appname]["urls"] = \
            "%s.url-dispatcher" % self.default_appname
        self._update_test_manifest()

        self.test_pkg_yaml = dict()
        self.set_test_pkg_yaml("name", self.test_control['Package'])
        self.set_test_pkg_yaml("version", self.test_control['Version'])
        self.set_test_pkg_yaml("architectures",
                               [self.test_control['Architecture']])
        self._update_test_pkg_yaml()

        self.test_hashes_yaml = dict()
        self._update_test_hashes_yaml()

        self.test_readme_md = self.test_control['Description']
        self._update_test_readme_md()

        self.set_test_pkgfmt("click", "0.4")

        # hooks
        self.test_security_manifests = dict()
        self.test_security_profiles = dict()
        self.test_desktop_files = dict()
        self.test_url_dispatcher = dict()
        self.test_scopes = dict()
        self.test_content_hub = dict()
        self.test_accounts_manifest = dict()
        self.test_accounts_application = dict()
        self.test_accounts_provider = dict()
        self.test_accounts_qml_plugin = dict()
        self.test_accounts_service = dict()
        self.test_push_helper = dict()
        self.test_bin_path = dict()
        self.test_framework = dict()
        self.test_framework_policy = dict()
        self.test_framework_policy_unknown = []

        for app in self.test_manifest["hooks"].keys():
            # setup security manifest for each app
            self.set_test_security_manifest(app, 'policy_groups',
                                            ['networking'])
            self.set_test_security_manifest(app, 'policy_version', 1.0)

            # setup desktop file for each app
            self.set_test_desktop(app, 'Name',
                                  self.default_appname,
                                  no_update=True)
            self.set_test_desktop(app, 'Comment', '%s test comment' % app,
                                  no_update=True)
            self.set_test_desktop(app, 'Exec', 'qmlscene %s.qml' % app,
                                  no_update=True)
            self.set_test_desktop(app, 'Icon', '%s.png' % app, no_update=True)
            self.set_test_desktop(app, 'Terminal', 'false', no_update=True)
            self.set_test_desktop(app, 'Type', 'Application', no_update=True)
            self.set_test_desktop(app, 'X-Ubuntu-Touch', 'true',
                                  no_update=True)

            self.set_test_url_dispatcher(app, None, None)

            # Ensure we have no scope entries since they conflict with desktop.
            # Scope tests will have to add them as part of their tests.
            self.set_test_scope(app, None)

            # Reset to no content-hub entries in manifest
            self.set_test_content_hub(app, None, None)

            # Reset to no accounts entries in manifest
            self.set_test_account(app, "accounts", None)
            self.set_test_account(app, "account-application", None)
            self.set_test_account(app, "account-provider", None)
            self.set_test_account(app, "account-qml-plugin", None)
            self.set_test_account(app, "account-service", None)

            # Reset to no push-helper entries in manifest
            self.set_test_push_helper(app, None, None)

            # Reset to no bin-path entries in manifest
            self.set_test_bin_path(app, None)

            # Reset to no framework entries in manifest
            self.set_test_framework(app, None, None)

            # Reset to no framework entries in manifest
            self.set_test_framework_policy(None)
            self.set_test_framework_policy_unknown([])

            # Reset to no security profiles
            self.set_test_security_profile(app, None)

        self._update_test_security_manifests()
        self._update_test_security_profiles()
        self._update_test_desktop_files()
        self._update_test_url_dispatcher()
        self._update_test_scopes()
        self._update_test_content_hub()
        self._update_test_accounts_manifest()
        self._update_test_accounts_application()
        self._update_test_accounts_provider()
        self._update_test_accounts_qml_plugin()
        self._update_test_accounts_service()
        self._update_test_push_helper()
        self._update_test_bin_path()
        self._update_test_framework()
        self._update_test_framework_policy()
        self._update_test_framework_policy_unknown()

        # webapps manifests (leave empty for now)
        self.test_webapp_manifests = dict()
        self._update_test_webapp_manifests()

        # mockup a click package name based on the above
        self._update_test_name()

    def _update_test_control(self):
        global TEST_CONTROL
        TEST_CONTROL = ""
        for k in self.test_control.keys():
            TEST_CONTROL += "%s: %s\n" % (k, self.test_control[k])

    def _update_test_manifest(self):
        global TEST_MANIFEST
        TEST_MANIFEST = json.dumps(self.test_manifest)

    def _update_test_pkg_yaml(self):
        global TEST_PKG_YAML
        TEST_PKG_YAML = yaml.dump(self.test_pkg_yaml,
                                  default_flow_style=False,
                                  indent=4)

    def _update_test_hashes_yaml(self):
        global TEST_HASHES_YAML
        TEST_HASHES_YAML = yaml.dump(self.test_hashes_yaml,
                                     default_flow_style=False,
                                     indent=4)

    def _update_test_readme_md(self):
        global TEST_README_MD
        TEST_README_MD = self.test_readme_md

    def _update_test_security_manifests(self):
        global TEST_SECURITY
        TEST_SECURITY = dict()
        for app in self.test_security_manifests.keys():
            TEST_SECURITY[app] = json.dumps(self.test_security_manifests[app])

    def _update_test_security_profiles(self):
        global TEST_SECURITY_PROFILES
        TEST_SECURITY_PROFILES = dict()
        for app in self.test_security_profiles.keys():
            TEST_SECURITY_PROFILES[app] = self.test_security_profiles[app]
            self.test_manifest["hooks"][app]["apparmor-profile"] = \
                "%s.profile" % app
        self._update_test_manifest()

    def _update_test_desktop_files(self):
        global TEST_DESKTOP
        TEST_DESKTOP = dict()
        for app in self.test_desktop_files.keys():
            contents = '''[Desktop Entry]'''
            for k in self.test_desktop_files[app].keys():
                contents += '\n%s=%s' % (k, self.test_desktop_files[app][k])
            contents += "\n"

            fn = os.path.join(self.desktop_tmpdir, "%s.desktop" % app)
            with open(fn, "w") as f:
                f.write(contents)
            f.close()
            TEST_DESKTOP[app] = DesktopEntry(fn)

    def _update_test_webapp_manifests(self):
        global TEST_WEBAPP_MANIFESTS
        TEST_WEBAPP_MANIFESTS = dict()
        for i in self.test_webapp_manifests.keys():
            TEST_WEBAPP_MANIFESTS[i] = self.test_webapp_manifests[i]

    def _update_test_url_dispatcher(self):
        global TEST_URLS
        TEST_URLS = dict()
        for app in self.test_url_dispatcher.keys():
            TEST_URLS[app] = self.test_url_dispatcher[app]

    def _update_test_scopes(self):
        global TEST_SCOPES
        TEST_SCOPES = dict()
        for app in self.test_scopes.keys():
            TEST_SCOPES[app] = self.test_scopes[app]
            self.test_manifest["hooks"][app]["scope"] = \
                TEST_SCOPES[app]["dir_rel"]
        self._update_test_manifest()

    def _update_test_content_hub(self):
        global TEST_CONTENT_HUB
        TEST_CONTENT_HUB = dict()
        for app in self.test_content_hub.keys():
            TEST_CONTENT_HUB[app] = self.test_content_hub[app]
            self.test_manifest["hooks"][app]["content-hub"] = \
                "%s.content.json" % app
        self._update_test_manifest()

    def _update_test_accounts_manifest(self):
        global TEST_ACCOUNTS_MANIFEST
        TEST_ACCOUNTS_MANIFEST = dict()
        for app in self.test_accounts_manifest.keys():
            TEST_ACCOUNTS_MANIFEST[app] = self.test_accounts_manifest[app]
            self.test_manifest["hooks"][app]["accounts"] = \
                "%s.accounts" % app
        self._update_test_manifest()

    def _update_test_accounts_application(self):
        global TEST_ACCOUNTS_APPLICATION
        TEST_ACCOUNTS_APPLICATION = dict()
        for app in self.test_accounts_application.keys():
            TEST_ACCOUNTS_APPLICATION[app] = \
                self.test_accounts_application[app]
            self.test_manifest["hooks"][app]["account-application"] = \
                "%s.application" % app
        self._update_test_manifest()

    def _update_test_accounts_provider(self):
        global TEST_ACCOUNTS_PROVIDER
        TEST_ACCOUNTS_PROVIDER = dict()
        for app in self.test_accounts_provider.keys():
            TEST_ACCOUNTS_PROVIDER[app] = self.test_accounts_provider[app]
            self.test_manifest["hooks"][app]["account-provider"] = \
                "%s.provider" % app
        self._update_test_manifest()

    def _update_test_accounts_qml_plugin(self):
        global TEST_ACCOUNTS_QML_PLUGIN
        TEST_ACCOUNTS_QML_PLUGIN = dict()
        for app in self.test_accounts_qml_plugin.keys():
            TEST_ACCOUNTS_QML_PLUGIN[app] = self.test_accounts_qml_plugin[app]
            self.test_manifest["hooks"][app]["account-qml-plugin"] = \
                "%s.qml_plugin" % app
        self._update_test_manifest()

    def _update_test_accounts_service(self):
        global TEST_ACCOUNTS_SERVICE
        TEST_ACCOUNTS_SERVICE = dict()
        for app in self.test_accounts_service.keys():
            TEST_ACCOUNTS_SERVICE[app] = self.test_accounts_service[app]
            self.test_manifest["hooks"][app]["account-service"] = \
                "%s.service" % app
        self._update_test_manifest()

    def _update_test_push_helper(self):
        global TEST_PUSH_HELPER
        TEST_PUSH_HELPER = dict()
        for app in self.test_push_helper.keys():
            TEST_PUSH_HELPER[app] = self.test_push_helper[app]
            self.test_manifest["hooks"][app]["push-helper"] = \
                "%s.push-helper.json" % app
        self._update_test_manifest()

    def _update_test_bin_path(self):
        global TEST_BIN_PATH
        TEST_BIN_PATH = dict()
        for app in self.test_bin_path.keys():
            TEST_BIN_PATH[app] = self.test_bin_path[app]
            self.test_manifest["hooks"][app]["bin-path"] = \
                "%s" % TEST_BIN_PATH[app]
        self._update_test_manifest()

    def _update_test_framework(self):
        global TEST_FRAMEWORK
        TEST_FRAMEWORK = dict()
        for app in self.test_framework.keys():
            TEST_FRAMEWORK[app] = self.test_framework[app]
            if app not in self.test_manifest["hooks"]:
                self.test_manifest["hooks"][app] = dict()
            self.test_manifest["hooks"][app]["framework"] = \
                "%s.framework" % TEST_FRAMEWORK[app]
        self._update_test_manifest()

    def _update_test_framework_policy(self):
        global TEST_FRAMEWORK_POLICY
        TEST_FRAMEWORK_POLICY = self.test_framework_policy

    def _update_test_framework_policy_unknown(self):
        global TEST_FRAMEWORK_POLICY_UNKNOWN
        TEST_FRAMEWORK_POLICY_UNKNOWN = self.test_framework_policy_unknown

    def _update_test_name(self):
        self.test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                             self.test_control['Version'],
                                             self.test_control['Architecture'])

    def check_results(self, report,
                      expected_counts={'info': 1, 'warn': 0, 'error': 0},
                      expected=None):
        common.check_results(self, report, expected_counts, expected)

    def check_manual_review(self, report, check_name,
                            result_type='error', manual_review=True):
        result = report[result_type][check_name]
        self.assertEqual(result['manual_review'], manual_review)

    def set_test_control(self, key, value):
        '''Set key in DEBIAN/control to value. If value is None, remove key'''
        if value is None:
            if key in self.test_control:
                self.test_control.pop(key, None)
        else:
            self.test_control[key] = value
        self._update_test_control()

    def set_test_manifest(self, key, value):
        '''Set key in DEBIAN/manifest to value. If value is None, remove key'''
        if value is None:
            if key in self.test_manifest:
                self.test_manifest.pop(key, None)
        else:
            self.test_manifest[key] = value
        self._update_test_manifest()

    def set_test_pkg_yaml(self, key, value):
        '''Set key in meta/package.yaml to value. If value is None, remove
           key'''
        if value is None:
            if key in self.test_pkg_yaml:
                self.test_pkg_yaml.pop(key, None)
        else:
            self.test_pkg_yaml[key] = value
        self._update_test_pkg_yaml()

    def set_test_hashes_yaml(self, yaml):
        '''Set hashes.yaml to yaml'''
        self.test_hashes_yaml = yaml
        self._update_test_hashes_yaml()

    def set_test_readme_md(self, contents):
        '''Set contents of meta/readme.md'''
        if contents is None:
            self.test_readme_md = None
        else:
            self.test_readme_md = contents
        self._update_test_readme_md()

    def set_test_security_manifest(self, app, key, value):
        '''Set key in security manifest and package.yaml to value. If value is
           None, remove key, if key is None, remove app.
        '''
        # package.yaml - we don't know if it is a service or a binary with
        # these values, so just use 'binaries'
        if key is None:
            if 'binaries' in self.test_pkg_yaml:
                for b in self.test_pkg_yaml['binaries']:
                    if 'name' in b and b['name'] == app:
                        self.test_pkg_yaml['binaries'].remove(b)
                        break
        elif value is None:
            if 'binaries' in self.test_pkg_yaml:
                found = False
                for b in self.test_pkg_yaml['binaries']:
                    if 'name' in b and b['name'] == app:
                        if key in b:
                            b.remove(key)
                            found = True
                            break
        else:
            found = False
            k = key
            if key == 'template':
                k = 'security-template'
            elif key == 'policy_groups':
                k = 'caps'
            if 'binaries' in self.test_pkg_yaml:
                for b in self.test_pkg_yaml['binaries']:
                    if 'name' in b and b['name'] == app:
                        # Found the entry, so update key/value
                        b[k] = value
                        found = True
                        break
            # Did not find the entry, so create one
            if not found:
                if 'binaries' not in self.test_pkg_yaml:
                    self.test_pkg_yaml['binaries'] = []
                self.test_pkg_yaml['binaries'].append({'name': app,
                                                       k: value})
        self._update_test_pkg_yaml()

        # click manifest
        if app not in self.test_security_manifests:
            self.test_security_manifests[app] = dict()

        if key is None:
            if app in self.test_security_manifests:
                del self.test_security_manifests[app]
                del self.test_manifest["hooks"][app]
        elif value is None:
            if key in self.test_security_manifests[app]:
                self.test_security_manifests[app].pop(key, None)
        else:
            self.test_security_manifests[app][key] = value
        self._update_test_security_manifests()

    def set_test_security_profile(self, app, policy):
        '''Set policy in security profile'''
        if policy is None:
            if app in self.test_security_profiles:
                self.test_security_profiles.pop(app)
        else:
            if app not in self.test_security_profiles:
                self.test_security_profiles[app] = dict()
            self.test_security_profiles[app] = policy
        self._update_test_security_profiles()

    def set_test_pkgfmt(self, t, v):
        global TEST_PKGFMT_TYPE
        global TEST_PKGFMT_VERSION
        TEST_PKGFMT_TYPE = t
        TEST_PKGFMT_VERSION = v

    def set_test_desktop(self, app, key, value, no_update=False):
        '''Set key in desktop file to value. If value is None, remove key'''
        if app not in self.test_desktop_files:
            self.test_desktop_files[app] = dict()

        if value is None:
            if key in self.test_desktop_files[app]:
                self.test_desktop_files[app].pop(key, None)
        else:
            self.test_desktop_files[app][key] = value
        if not no_update:
            self._update_test_desktop_files()

    def set_test_webapp_manifest(self, fn, key, value):
        '''Set key in webapp manifest to value. If value is None, remove
           key'''
        if key is None and value is None:
            self.test_webapp_manifests[fn] = None
            self._update_test_webapp_manifests()
            return

        if fn not in self.test_webapp_manifests:
            self.test_webapp_manifests[fn] = dict()

        if value is None:
            if key in self.test_webapp_manifests[fn]:
                self.test_webapp_manifests[fn].pop(key, None)
        else:
            self.test_webapp_manifests[fn][key] = value
        self._update_test_webapp_manifests()

    def set_test_url_dispatcher(self, app, key, value, append=False):
        '''Set url-dispatcher entries. If value is None, remove'''
        if app not in self.test_url_dispatcher:
            self.test_url_dispatcher[app] = []

        if value is None:
            self.test_url_dispatcher[app] = []
        else:
            if not append:
                self.test_url_dispatcher[app] = []
            self.test_url_dispatcher[app].append({key: value})
        self._update_test_url_dispatcher()

    def set_test_scope(self, app, scope):
        '''Set scope for app. If it is None, remove'''
        if scope is None:
            if app in self.test_scopes:
                self.test_scopes.pop(app)
            if 'scope' in self.test_manifest['hooks'][app]:
                self.test_manifest['hooks'][app].pop('scope', None)
        else:
            self.test_scopes[app] = scope
        self._update_test_scopes()

    def set_test_content_hub(self, app, key, value):
        '''Set content-hub entries. If value is None, remove key, if key is
           None, remove content-hub from manifest'''
        if key is None:
            if app in self.test_content_hub:
                self.test_content_hub.pop(app)
        elif value is None:
            if key in self.test_content_hub[app]:
                self.test_content_hub[app].pop(key)
        else:
            if app not in self.test_content_hub:
                self.test_content_hub[app] = dict()
            if key not in self.test_content_hub[app]:
                self.test_content_hub[app][key] = []
            self.test_content_hub[app][key].append(value)
        self._update_test_content_hub()

    def set_test_account(self, app, account_type, value):
        '''Set accounts XML. If value is None, remove from manifest'''
        if account_type == "accounts":
            d = self.test_accounts_manifest
        elif account_type == "account-application":
            d = self.test_accounts_application
        elif account_type == "account-provider":
            d = self.test_accounts_provider
        elif account_type == "account-qml-plugin":
            d = self.test_accounts_qml_plugin
        elif account_type == "account-service":
            d = self.test_accounts_service
        else:  # should never get here
            raise ValueError("Unknown account_type '%s'" % account_type)

        if value is None:
            if app in d:
                d[app] = None
        else:
            d[app] = value

        if account_type == "accounts":
            self._update_test_accounts_manifest()
        elif account_type == "account-application":
            self._update_test_accounts_application()
        elif account_type == "account-provider":
            self._update_test_accounts_provider()
        elif account_type == "account-qml-plugin":
            self._update_test_accounts_qml_plugin()
        elif account_type == "account-service":
            self._update_test_accounts_service()

    def set_test_push_helper(self, app, key, value):
        '''Set push-helper entries. If value is None, remove key, if key is
           None, remove push-helper from manifest'''
        if key is None:
            if app in self.test_push_helper:
                self.test_push_helper.pop(app)
        elif value is None:
            if key in self.test_push_helper[app]:
                self.test_push_helper[app].pop(key)
        else:
            if app not in self.test_push_helper:
                self.test_push_helper[app] = dict()
            self.test_push_helper[app][key] = value
        self._update_test_push_helper()

    def set_test_bin_path(self, app, value):
        '''Set bin-path entries. If value is None, remove bin-path from
           manifest and yaml. If app != value, set 'exec' in the yaml

           Note the click manifest and the package.yaml use different
           storage types. pkg_yaml['binaries'] is a list of dictionaries where
           manifest['hooks'] is a dictionary of dictionaries. This function
           sets the manifest entry and then a yaml entry with 'name' and 'exec'
           fields.

             manifest['hooks'][app]['bin-path'] = value
             pkg_yaml['binaries'][*]['name'] = app
             pkg_yaml['binaries'][*]['exec'] = value
        '''

        # Update the package.yaml
        if value is None:
            if 'binaries' in self.test_pkg_yaml:
                for b in self.test_pkg_yaml['binaries']:
                    if 'name' in b and b['name'] == app:
                        self.test_pkg_yaml['binaries'].remove(b)
                        break
        else:
            found = False
            if 'binaries' in self.test_pkg_yaml:
                for b in self.test_pkg_yaml['binaries']:
                    if 'name' in b and b['name'] == app:
                        found = True
                        break
            if not found:
                if 'binaries' not in self.test_pkg_yaml:
                    self.test_pkg_yaml['binaries'] = []
                if value == app:
                    self.test_pkg_yaml['binaries'].append({'name': app})
                else:
                    self.test_pkg_yaml['binaries'].append({'name': app,
                                                           'exec': value})
        self._update_test_pkg_yaml()

        # Update the click manifest (we still support click format)
        if value is None:
            if app in self.test_bin_path:
                self.test_bin_path.pop(app)
        else:
            if app not in self.test_bin_path:
                self.test_bin_path[app] = dict()
            self.test_bin_path[app] = value

        # Now update TEST_BIN_PATH
        self._update_test_bin_path()

    def set_test_framework(self, app, key, value):
        '''Set framework entries. If value is None, remove key, if key is
           None, remove framework from manifest'''
        if key is None:
            if app in self.test_framework:
                self.test_framework.pop(app)
        elif value is None:
            if key in self.test_framework[app]:
                self.test_framework[app].pop(key)
        else:
            if app not in self.test_framework:
                self.test_framework[app] = dict()
            self.test_framework[app][key] = value
        self._update_test_framework()

    def set_test_framework_policy(self, policy_dict=None):
        '''Set framework policy'''
        if policy_dict is None:  # Reset
            self.test_framework_policy = dict()
            for i in ['apparmor', 'seccomp']:
                self.test_framework_policy[i] = dict()
                for j in ['templates', 'policygroups']:
                    self.test_framework_policy[i][j] = dict()
                    for k in ['-common', '-reserved']:
                        n = "%s%s" % (j.rstrip('s'), k)
                        self.test_framework_policy[i][j][n] = \
                            '''# Description: %s
# Usage: %s
''' % (n, k.lstrip('-'))
        else:
            self.test_framework_policy = policy_dict
        self._update_test_framework_policy()

    def set_test_framework_policy_unknown(self, unknown=[]):
        '''Set framework policy unknown'''
        self.test_framework_policy_unknown = unknown
        self._update_test_framework_policy_unknown()

    def set_test_systemd(self, app, key, value):
        '''Set systemd entries. If key is None, remove snappy-systemd from
           yaml.

           pkg_yaml['services'][*]['name'] = app
           pkg_yaml['services'][*][key] = value
        '''

        # Update the package.yaml
        if key is None:
            if 'services' in self.test_pkg_yaml:
                for s in self.test_pkg_yaml['services']:
                    if 'name' in s and s['name'] == app:
                        self.test_pkg_yaml['services'].remove(s)
                        break
        else:
            found = False
            if 'services' in self.test_pkg_yaml:
                for s in self.test_pkg_yaml['services']:
                    if 'name' in s and s['name'] == app:
                        # Found the entry, so update key/value
                        s[key] = value
                        found = True
                        break
            # Did not find the entry, so create one
            if not found:
                if 'services' not in self.test_pkg_yaml:
                    self.test_pkg_yaml['services'] = []
                self.test_pkg_yaml['services'].append({'name': app,
                                                       key: value})
        self._update_test_pkg_yaml()

    def setUp(self):
        '''Make sure our patches are applied everywhere'''
        patches = create_patches()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        '''Make sure we reset everything to known good values'''
        global TEST_CONTROL
        TEST_CONTROL = ""
        global TEST_MANIFEST
        TEST_MANIFEST = ""
        global TEST_PKG_YAML
        TEST_PKG_YAML = ""
        global TEST_HASHES_YAML
        TEST_HASHES_YAML = ""
        global TEST_README_MD
        TEST_README_MD = ""
        global TEST_SECURITY
        TEST_SECURITY = dict()
        global TEST_SECURITY_PROFILES
        TEST_SECURITY_PROFILES = dict()
        global TEST_DESKTOP
        TEST_DESKTOP = dict()
        global TEST_URLS
        TEST_URLS = dict()
        global TEST_SCOPES
        TEST_SCOPES = dict()
        global TEST_CONTENT_HUB
        TEST_CONTENT_HUB = dict()
        global TEST_ACCOUNTS_MANIFEST
        TEST_ACCOUNTS_MANIFEST = dict()
        global TEST_ACCOUNTS_APPLICATION
        TEST_ACCOUNTS_APPLICATION = dict()
        global TEST_ACCOUNTS_PROVIDER
        TEST_ACCOUNTS_PROVIDER = dict()
        global TEST_ACCOUNTS_QML_PLUGIN
        TEST_ACCOUNTS_QML_PLUGIN = dict()
        global TEST_ACCOUNTS_SERVICE
        TEST_ACCOUNTS_SERVICE = dict()
        global TEST_PUSH_HELPER
        TEST_PUSH_HELPER = dict()
        global TEST_BIN_PATH
        TEST_BIN_PATH = dict()
        global TEST_FRAMEWORK
        TEST_FRAMEWORK = dict()
        global TEST_FRAMEWORK_POLICY
        TEST_FRAMEWORK_POLICY = dict()
        global TEST_FRAMEWORK_POLICY_UNKNOWN
        TEST_FRAMEWORK_POLICY_UNKNOWN = []
        global TEST_PKGFMT_TYPE
        TEST_PKGFMT_TYPE = "click"
        global TEST_PKGFMT_VERSION
        TEST_PKGFMT_VERSION = "0.4"

        self._reset_test_data()
        common.recursive_rm(self.desktop_tmpdir)
