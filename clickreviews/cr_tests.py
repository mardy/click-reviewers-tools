'''cr_tests.py: common setup and tests for test modules'''
#
# Copyright (C) 2013-2014 Canonical Ltd.
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

from unittest.mock import patch
from unittest import TestCase

from clickreviews.cr_lint import MINIMUM_CLICK_FRAMEWORK_VERSION
import clickreviews.cr_common as cr_common

# These should be set in the test cases
TEST_CONTROL = ""
TEST_MANIFEST = ""
TEST_SECURITY = dict()
TEST_DESKTOP = dict()
TEST_WEBAPP_MANIFESTS = dict()
TEST_URLS = dict()
TEST_SCOPES = dict()
TEST_CONTENT_HUB = dict()
TEST_ACCOUNTS_APPLICATION = dict()
TEST_ACCOUNTS_PROVIDER = dict()
TEST_ACCOUNTS_QML_PLUGIN = dict()
TEST_ACCOUNTS_SERVICE = dict()
TEST_PUSH_HELPER = dict()


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
    return ("%s.json" % app, json.loads(TEST_SECURITY[app]))


def _get_security_supported_policy_versions(self):
    '''Pretend we read the contens of /usr/share/apparmor/easyprof'''
    return [1.0, 1.1, 1.2]


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
    if account_type == "account-application":
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


# http://docs.python.org/3.4/library/unittest.mock-examples.html
# Mock patching. Don't use decorators but instead patch in setUp() of the
# child. Set up a list of patches, but don't start them. Create the helper
# method mock_patch() to start all the patches. The child can do this in a
# setUp() like so:
#   import clickreviews.cr_tests as cr_tests
#   class TestClickReviewFoo(cr_tests.TestClickReview):
#       def setUp(self):
#           # Monkey patch various file access classes. stop() is handled with
#           # addCleanup in super()
#           cr_tests.mock_patch()
#           super()
patches = []
patches.append(patch('clickreviews.cr_common.ClickReview._check_path_exists',
               _mock_func))
patches.append(patch(
    'clickreviews.cr_common.ClickReview._extract_control_file',
    _extract_control_file))
patches.append(patch(
    'clickreviews.cr_common.ClickReview._extract_manifest_file',
    _extract_manifest_file))
patches.append(patch(
    'clickreviews.cr_common.ClickReview._extract_click_frameworks',
    _extract_click_frameworks))
patches.append(patch('clickreviews.cr_common.unpack_click', _mock_func))
patches.append(patch('clickreviews.cr_common.ClickReview._list_all_files',
               _mock_func))
patches.append(patch(
    'clickreviews.cr_common.ClickReview._list_all_compiled_binaries',
    _mock_func))

# lint overrides
patches.append(patch(
               'clickreviews.cr_lint.ClickReviewLint._list_control_files',
               _mock_func))
patches.append(patch('clickreviews.cr_lint.ClickReviewLint._list_all_files',
               _mock_func))
patches.append(patch(
    'clickreviews.cr_lint.ClickReview._list_all_compiled_binaries',
    _mock_func))

# security overrides
patches.append(patch(
    'clickreviews.cr_security.ClickReviewSecurity._extract_security_manifest',
    _extract_security_manifest))
patches.append(patch(
    'clickreviews.cr_security.ClickReviewSecurity._get_security_manifest',
    _get_security_manifest))

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
patches.append(patch(
    'clickreviews.cr_url_dispatcher.ClickReviewUrlDispatcher._extract_url_dispatcher',
    _extract_url_dispatcher))

# scope overrides
patches.append(patch(
    'clickreviews.cr_scope.ClickReviewScope._extract_scopes',
    _extract_scopes))

# content-hub overrides
patches.append(patch(
    'clickreviews.cr_content_hub.ClickReviewContentHub._extract_content_hub',
    _extract_content_hub))

# online accounts overrides
patches.append(patch(
    'clickreviews.cr_online_accounts.ClickReviewAccounts._extract_account',
    _extract_account))

# push-helper overrides
patches.append(patch(
    'clickreviews.cr_push_helper.ClickReviewPushHelper._extract_push_helper',
    _extract_push_helper))


def mock_patch():
    '''Call in setup of child'''
    global patches
    for p in patches:
        try:
            p.start()
        except ImportError:
            # This is only needed because we are importing ClickReviewLint
            # in the security tests and ClickReviewSecurity in the lint tests.
            # If we move those patches outside of this file, then we can
            # remove this.
            pass


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
            "%s.json" % self.default_appname
        self.test_manifest["hooks"][self.default_appname]["desktop"] = \
            "%s.desktop" % self.default_appname
        self.test_manifest["hooks"][self.default_appname]["urls"] = \
            "%s.url-dispatcher" % self.default_appname
        self._update_test_manifest()

        # hooks
        self.test_security_manifests = dict()
        self.test_desktop_files = dict()
        self.test_url_dispatcher = dict()
        self.test_scopes = dict()
        self.test_content_hub = dict()
        self.test_accounts_application = dict()
        self.test_accounts_provider = dict()
        self.test_accounts_qml_plugin = dict()
        self.test_accounts_service = dict()
        self.test_push_helper = dict()
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

            # Reset to no content-hub entries in manifest
            self.set_test_account(app, "account-application", None)
            self.set_test_account(app, "account-provider", None)
            self.set_test_account(app, "account-qml-plugin", None)
            self.set_test_account(app, "account-service", None)

            # Reset to no content-hub entries in manifest
            self.set_test_push_helper(app, None, None)

        self._update_test_security_manifests()
        self._update_test_desktop_files()
        self._update_test_url_dispatcher()
        self._update_test_scopes()
        self._update_test_content_hub()
        self._update_test_accounts_application()
        self._update_test_accounts_provider()
        self._update_test_accounts_qml_plugin()
        self._update_test_accounts_service()
        self._update_test_push_helper()

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

    def _update_test_security_manifests(self):
        global TEST_SECURITY
        TEST_SECURITY = dict()
        for app in self.test_security_manifests.keys():
            TEST_SECURITY[app] = json.dumps(self.test_security_manifests[app])

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

    def _update_test_accounts_application(self):
        global TEST_ACCOUNTS_APPLICATION
        TEST_ACCOUNTS_APPLICATION = dict()
        for app in self.test_accounts_application.keys():
            TEST_ACCOUNTS_APPLICATION[app] = self.test_accounts_application[app]
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

    def _update_test_name(self):
        self.test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                             self.test_control['Version'],
                                             self.test_control['Architecture'])

    #
    # check_results(report, expected_counts, expected)
    # Verify exact counts of types
    #   expected_counts={'info': 1, 'warn': 0, 'error': 0}
    #   self.check_results(report, expected_counts)
    # Verify counts of warn and error types
    #   expected_counts={'info': None, 'warn': 0, 'error': 0}
    #   self.check_results(report, expected_counts)
    # Verify exact messages:
    #   expected = dict()
    #   expected['info'] = dict()
    #   expected['warn'] = dict()
    #   expected['warn']['skeleton_baz'] = "TODO"
    #   expected['error'] = dict()
    #   self.check_results(r, expected=expected)
    #
    def check_results(self, report,
                      expected_counts={'info': 1, 'warn': 0, 'error': 0},
                      expected=None):
        if expected is not None:
            for t in expected.keys():
                for r in expected[t]:
                    self.assertTrue(r in report[t],
                                    "Could not find '%s' (%s) in:\n%s" %
                                    (r, t, json.dumps(report, indent=2)))
                    for k in expected[t][r]:
                        self.assertTrue(k in report[t][r],
                                        "Could not find '%s' (%s) in:\n%s" %
                                        (k, r, json.dumps(report, indent=2)))
                    self.assertEqual(expected[t][r][k], report[t][r][k])
        else:
            for k in expected_counts.keys():
                if expected_counts[k] is None:
                    continue
                self.assertEqual(len(report[k]), expected_counts[k],
                                 "(%s not equal)\n%s" %
                                 (k, json.dumps(report, indent=2)))

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

    def set_test_security_manifest(self, app, key, value):
        '''Set key in security manifest to value. If value is None, remove
           key'''
        if app not in self.test_security_manifests:
            self.test_security_manifests[app] = dict()

        if value is None:
            if key in self.test_security_manifests[app]:
                self.test_security_manifests[app].pop(key, None)
        else:
            self.test_security_manifests[app][key] = value
        self._update_test_security_manifests()

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
        if account_type == "account-application":
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

        if account_type == "account-application":
            self._update_test_accounts_application()
        elif account_type == "account-provider":
            self._update_test_accounts_provider()
        elif account_type == "account-qml-plugin":
            self._update_test_accounts_qml_plugin()
        elif account_type == "account-service":
            self._update_test_accounts_service()

    def set_test_push_helper(self, app, key, value):
        '''Set push-helper entries. If value is None, remove key, if key is
           None, remove content-hub from manifest'''
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

    def setUp(self):
        '''Make sure our patches are applied everywhere'''
        global patches
        for p in patches:
            self.addCleanup(p.stop())

    def tearDown(self):
        '''Make sure we reset everything to known good values'''
        global TEST_CONTROL
        TEST_CONTROL = ""
        global TEST_MANIFEST
        TEST_MANIFEST = ""
        global TEST_SECURITY
        TEST_SECURITY = dict()
        global TEST_DESKTOP
        TEST_DESKTOP = dict()
        global TEST_URLS
        TEST_URLS = dict()
        global TEST_SCOPES
        TEST_SCOPES = dict()
        global TEST_CONTENT_HUB
        TEST_CONTENT_HUB = dict()
        global TEST_ACCOUNTS_APPLICATION
        TEST_ACCOUNTS_APPLICATION = dict()
        global TEST_ACCOUNTS_PROVIDER
        TEST_ACCOUNTS_PROVIDER = dict()
        global TEST_ACCOUNTS_QML_PLUGIN
        TEST_ACCOUNTS_QML_PLUGIN = dict()
        global TEST_ACCOUNTS_SERVICE
        TEST_ACCOUNTS_APPLICATION = dict()
        global TEST_PUSH_HELPER
        TEST_PUSH_HELPER = dict()

        self._reset_test_data()
        cr_common.recursive_rm(self.desktop_tmpdir)
