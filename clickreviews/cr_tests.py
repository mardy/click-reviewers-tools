'''cr_tests.py: common setup and tests for test modules'''
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

import io
import json

from unittest.mock import patch
from unittest import TestCase

from clickreviews.cr_lint import MINIMUM_CLICK_FRAMEWORK_VERSION

# These should be set in the test cases
TEST_CONTROL = ""
TEST_MANIFEST = ""
TEST_SECURITY = dict()

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

def _extract_security_manifest(self, app):
    '''Pretend we read the security manifest file'''
    return io.StringIO(TEST_SECURITY[app])

def _get_security_manifest(self, app):
    '''Pretend we read the security manifest file'''
    return ("%s.json" % app, json.loads(TEST_SECURITY[app]))

# http://docs.python.org/3.4/library/unittest.mock-examples.html#applying-the-same-patch-to-every-test-method
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
patches.append(patch('clickreviews.cr_common.ClickReview._extract_control_file',
    _extract_control_file))
patches.append(patch('clickreviews.cr_common.ClickReview._extract_manifest_file',
    _extract_manifest_file))
patches.append(patch('clickreviews.cr_common.unpack_click', _mock_func))
patches.append(patch('clickreviews.cr_common.ClickReview.__del__', _mock_func))
patches.append(patch('clickreviews.cr_common.ClickReview._list_all_files',
    _mock_func))

# lint overrides
patches.append(patch('clickreviews.cr_lint.ClickReviewLint._list_control_files',
    _mock_func))
patches.append(patch('clickreviews.cr_lint.ClickReviewLint._list_all_files',
    _mock_func))

# security overrides
patches.append(patch('clickreviews.cr_security.ClickReviewSecurity._extract_security_manifest',
    _extract_security_manifest))
patches.append(patch('clickreviews.cr_security.ClickReviewSecurity._get_security_manifest',
    _get_security_manifest))


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
        TestCase.__init__(self, *args)

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
        self.test_hook_default_appname = "test-app"
        self.test_manifest["hooks"][self.test_hook_default_appname] = dict()
        self.test_manifest["hooks"][self.test_hook_default_appname]["apparmor"] = "%s.json" % self.test_hook_default_appname
        self.test_manifest["hooks"][self.test_hook_default_appname]["desktop"] = "%s.desktop" % self.test_hook_default_appname
        self._update_test_manifest()

        # hooks
        self.test_security_manifests = dict()
        self.test_desktop_files = dict()
        for app in self.test_manifest["hooks"].keys():
            # setup security manifest for each app
            self.set_test_security_manifest(app, 'policy_groups', 'networking')
            self.set_test_security_manifest(app, 'policy_version', 1.0)

            # TODO: setup desktop file for each app
        self._update_test_security_manifests()

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
        for app in self.test_security_manifests.keys():
            TEST_SECURITY[app] = json.dumps(self.test_security_manifests[app])

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
                for k in expected[t]:
                    self.assertTrue(k in report[t],
                                    "Could not find '%s (%s)' in:\n%s" % \
                                    (k, t, json.dumps(report, indent=2)))
                    self.assertEquals(expected[t][k], report[t][k])
        else:
            for k in expected_counts.keys():
                if expected_counts[k] is None:
                    continue
                self.assertEquals(len(report[k]), expected_counts[k],
                                 "(%s not equal)\n%s" % (k,
                                 json.dumps(report, indent=2)))

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

    def setUp(self):
        '''Make sure our patches are applied everywhere'''
        global patches
        for p in patches:
            self.addCleanup(p.stop())

