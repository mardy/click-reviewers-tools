'''sr_tests.py: common setup and tests for test modules'''
#
# Copyright (C) 2013-2016 Canonical Ltd.
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
import yaml

from unittest.mock import patch
from unittest import TestCase

# These should be set in the test cases
TEST_SNAP_YAML = ""
TEST_PKGFMT_TYPE = "snap"
TEST_PKGFMT_VERSION = "16.04"
TEST_UNPACK_DIR = ""

#
# Mock override functions
#
def _mock_func(self):
    '''Fake test function'''
    return


def _extract_snap_yaml(self):
    '''Pretend we read the package.yaml file'''
    return io.StringIO(TEST_SNAP_YAML)


def _path_join(self, d, fn):
    '''Pretend we have a tempdir'''
    return os.path.join("/fake", fn)


def _extract_statinfo(self, fn):
    '''Pretend we found performed an os.stat()'''
    return os.stat(os.path.realpath(__file__))


def _check_innerpath_executable(self, fn):
    '''Pretend we a file'''
    if '.nonexec' in fn:
        return False
    return True


def _pkgfmt_type(self):
    '''Pretend we found the pkgfmt type'''
    return TEST_PKGFMT_TYPE


def _pkgfmt_version(self):
    '''Pretend we found the pkgfmt version'''
    return TEST_PKGFMT_VERSION


def _is_squashfs(self):
    '''Pretend we discovered if it is a squashfs or not'''
    return (TEST_PKGFMT_TYPE == "snap" and float(TEST_PKGFMT_VERSION) > 15.04)


def _detect_package(self, fn):
    '''Pretend we detected the package'''
    ver = 2
    if TEST_PKGFMT_VERSION == "15.04":
        ver = 1
    return (TEST_PKGFMT_TYPE, ver)


def __get_unpack_dir(self):
    '''Pretend we found the unpack dir'''
    return TEST_UNPACK_DIR


def create_patches():
    # http://docs.python.org/3.4/library/unittest.mock-examples.html
    # Mock patching. Don't use decorators but instead patch in setUp() of the
    # child.
    patches = []
    patches.append(patch('clickreviews.common.Review._check_package_exists',
                   _mock_func))
    patches.append(patch(
        'clickreviews.sr_common.SnapReview._extract_snap_yaml',
        _extract_snap_yaml))
    patches.append(patch(
        'clickreviews.sr_common.SnapReview._path_join',
        _path_join))
    patches.append(patch(
        'clickreviews.sr_common.SnapReview._extract_statinfo',
        _extract_statinfo))
    patches.append(patch('clickreviews.common.unpack_pkg', _mock_func))
    patches.append(patch('clickreviews.common.raw_unpack_pkg', _mock_func))
    patches.append(patch('clickreviews.common.detect_package',
                   _detect_package))
    patches.append(patch('clickreviews.sr_common.SnapReview._list_all_files',
                   _mock_func))
    patches.append(patch(
        'clickreviews.sr_common.SnapReview._list_all_compiled_binaries',
        _mock_func))

    patches.append(patch('clickreviews.common.Review._list_all_files',
                   _mock_func))
    patches.append(patch(
        'clickreviews.common.Review._list_all_compiled_binaries',
        _mock_func))
    patches.append(patch(
        'clickreviews.common.Review._check_innerpath_executable',
        _check_innerpath_executable))

    #  sr_common
    patches.append(patch('clickreviews.sr_common.SnapReview._get_unpack_dir',
                   __get_unpack_dir))

    # pkgfmt
    patches.append(patch("clickreviews.sr_common.SnapReview._pkgfmt_type",
                   _pkgfmt_type))
    patches.append(patch("clickreviews.sr_common.SnapReview._pkgfmt_version",
                   _pkgfmt_version))
    patches.append(patch("clickreviews.common.is_squashfs", _is_squashfs))

    return patches


class TestSnapReview(TestCase):
    """Tests for the snap review tool."""
    def __init__(self, *args):
        TestCase.__init__(self, *args)
        self._reset_test_data()

    def _reset_test_data(self):
        self.test_snap_yaml = dict()
        self.set_test_pkgfmt("snap", "16.04")

        self.set_test_snap_yaml("name", "foo")
        self.set_test_snap_yaml("version", "0.1")
        self.set_test_snap_yaml("description", "Test description")
        self.set_test_snap_yaml("summary", "Test summary")
        self.set_test_snap_yaml("architectures", ["all"])
        apps = dict()
        apps["bar"] = dict()
        apps["bar"]["command"] = "bin/bar"
        self.set_test_snap_yaml("apps", apps)

        # mockup a package name
        self._update_test_name()

        self.set_test_unpack_dir("/fake")

    def _update_test_snap_yaml(self):
        global TEST_SNAP_YAML
        TEST_SNAP_YAML = yaml.dump(self.test_snap_yaml,
                                   default_flow_style=False,
                                   indent=4)

    def _update_test_name(self):
        self.test_name = "%s.origin_%s_%s.snap" % (
            self.test_snap_yaml["name"],
            self.test_snap_yaml["version"],
            self.test_snap_yaml["architectures"][0])

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

    def set_test_snap_yaml(self, key, value):
        '''Set key in meta/snap.yaml to value. If value is None, remove
           key'''
        if value is None:
            if key in self.test_snap_yaml:
                self.test_snap_yaml.pop(key, None)
        else:
            self.test_snap_yaml[key] = value
        self._update_test_snap_yaml()

    def set_test_pkgfmt(self, t, v):
        global TEST_PKGFMT_TYPE
        global TEST_PKGFMT_VERSION
        TEST_PKGFMT_TYPE = t
        TEST_PKGFMT_VERSION = v

    def set_test_unpack_dir(self, d):
        global TEST_UNPACK_DIR
        TEST_UNPACK_DIR = d

    def setUp(self):
        '''Make sure our patches are applied everywhere'''
        patches = create_patches()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        '''Make sure we reset everything to known good values'''
        global TEST_SNAP_YAML
        TEST_SNAP_YAML = ""
        global TEST_PKGFMT_TYPE
        TEST_PKGFMT_TYPE = "snap"
        global TEST_PKGFMT_VERSION
        TEST_PKGFMT_VERSION = "16.04"
        global TEST_UNPACK_DIR
        TEST_UNPACK_DIR = ""

        self._reset_test_data()
