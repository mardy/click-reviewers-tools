'''test_cr_lint.py: tests for the cr_lint module'''
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

def mock_patch():
    '''Call in setup of child'''
    global patches
    for p in patches:
        p.start()


class TestClickReview(TestCase):
    """Tests for the lint review tool."""
    def __init__(self, *args):
        TestCase.__init__(self, *args)

        # dictionary representing DEBIAN/control
        self.test_control = dict()
        self.test_control['Package'] = "com.ubuntu.developer.someuser.testapp"
        self.test_control['Version'] = "1.0"
        self.test_control['Click-Version'] = MINIMUM_CLICK_FRAMEWORK_VERSION
        self.test_control['Architecture'] = "all"
        self.test_control['Maintainer'] = "Some User <some.user@example.com>"
        self.test_control['Installed-Size'] = "111"
        self.test_control['Description'] = "My Test App"
        self._update_test_control()

        # dictionary representing DEBIAN/manifest
        self.test_manifest = dict()
        self.test_manifest["description"] = "Some longish description of My Test App"
        self.test_manifest["framework"] = "ubuntu-sdk-13.10"
        self.test_manifest["maintainer"] = self.test_control['Maintainer']
        self.test_manifest["name"] = self.test_control['Package']
        self.test_manifest["hooks"] = dict()
        self.test_manifest["hooks"]["test-app"] = dict()
        self.test_manifest["hooks"]["test-app"]["apparmor"] = "apparmor/test-app.json"
        self.test_manifest["hooks"]["test-app"]["desktop"] = "test-app.desktop"
        self.test_manifest["title"] = self.test_control['Description']
        self.test_manifest["version"] = self.test_control['Version']
        self._update_test_manifest()

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

    def _update_test_name(self):
        self.test_name = "%s_%s_%s.click" % (self.test_control['Package'],
                                             self.test_control['Version'],
                                             self.test_control['Architecture'])

    def setUp(self):
        '''Make sure our patches are applied everywhere'''
        global patches
        for p in patches:
            self.addCleanup(p.stop())
