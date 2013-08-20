'''common.py: common classes and functions'''
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

from __future__ import print_function
import codecs
import inspect
import json
import os
import subprocess
import sys
import tempfile
import types

DEBUGGING = False


#
# Utility classes
#
class ClickReviewException(Exception):
    '''This class represents ClickReview exceptions'''
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ClickReview(object):
    '''This class represents click reviews'''
    def __init__(self, fn, review_type):
        if not os.path.exists(fn):
            error("Could not find '%s'" % fn)
        self.click_package = fn

        tmp = os.path.basename(fn).split('_')
        if len(tmp) != 3 or not tmp[2].endswith(".click"):
            error("filename not of form: $pkgname_$version_$arch.click")
        self.click_pkgname = tmp[0]
        self.click_version = tmp[1]

        self.click_arch = tmp[2].split('.')[0]
        # LP: #1214380 - we only support 'all' for now
        # valid_architectures = ['amd64', 'i386', 'armhf', 'powerpc', 'all']
        valid_architectures = ['all']
        if self.click_arch not in valid_architectures:
            error("not a valid architecture: %s" % self.click_arch)

        self.review_type = review_type
        self.click_report = dict()

        self.result_types = ['info', 'warn', 'error']
        for r in self.result_types:
            self.click_report[r] = dict()

        self.click_report_output = "json"

        self.unpack_dir = unpack_click(fn)

        m = os.path.join(self.unpack_dir, "DEBIAN/manifest")
        if not os.path.isfile(m):
            error("Could not find manifest file")
        self.manifest = json.load(open_file_read(m))
        self._verify_manifest_structure(self.manifest)

    def _verify_manifest_structure(self, manifest):
        '''Verify manifest has the expected structure'''
        # lp:click doc/file-format.rst
        if not isinstance(manifest, dict):
            error("manifest malformed")

        required = ["name", "version", "framework",        # click required
                    "title", "description", "maintainer"]  # appstore required
        for f in required:
            if f not in manifest:
                error("could not find required '%s' in manifest" % f)
            elif not isinstance(manifest[f], str):
                error("manifest malformed: '%s' is not str" % f)

        optional = []  # add appstore optional fields here
        for f in optional:
            if f in manifest and not isinstance(manifest[f], str):
                error("manifest malformed: '%s' is not str" % f)

        # Not required by click, but required by appstore. 'hooks' is assumed
        # to be present in other checks
        if 'hooks' not in manifest:
            error("could not find required '%s' in manifest" % f)
        if not isinstance(manifest['hooks'], dict):
            error("manifest malformed: 'hooks' is not dict")
        # 'hooks' is assumed to be present and non-empty in other checks
        if len(manifest['hooks']) < 1:
            error("manifest malformed: 'hooks' is empty")
        for app in manifest['hooks']:
            if not isinstance(manifest['hooks'][app], dict):
                error("manifest malformed: hooks/%s is not dict" % app)
            # let cr_lint.py handle required hooks
            if len(manifest['hooks'][app]) < 1:
                error("manifest malformed: hooks/%s is empty" % app)

        for k in sorted(manifest):
            if k not in required + optional + ['hooks']:
                error("manifest malformed: unsupported field '%s'" % k)

    def __del__(self):
        '''Cleanup'''
        if hasattr(self, 'unpack_dir') and os.path.isdir(self.unpack_dir):
            recursive_rm(self.unpack_dir)

    def set_review_type(self, name):
        '''Set review name'''
        self.review_type = name

    #
    # click_report[<result_type>][<review_name>] = <review>
    #   result_type: info, warn, error
    #   review_name: name of the check (prefixed with self.review_type)
    #   review: contents of the review
    def _add_result(self, result_type, review_name, result):
        '''Add result to report'''
        if result_type not in self.result_types:
            error("Invalid result type '%s'" % result_type)

        name = "%s_%s" % (self.review_type, review_name)
        if name not in self.click_report[result_type]:
            self.click_report[result_type][name] = dict()

        self.click_report[result_type][name] = result

    def do_report(self):
        '''Print report'''
        if self.click_report_output == "console":
            # TODO: format better
            import pprint
            pprint.pprint(self.click_report)
        elif self.click_report_output == "json":
            import json
            msg(json.dumps(self.click_report,
                           sort_keys=True,
                           indent=2,
                           separators=(',', ': ')))

        rc = 0
        if len(self.click_report['error']):
            rc = 2
        elif len(self.click_report['warn']):
            rc = 1
        return rc

    def do_checks(self):
        '''Run all methods that start with check_'''
        methodList = [name for name, member in
                      inspect.getmembers(self, inspect.ismethod)
                      if isinstance(member, types.MethodType)]
        for methodname in methodList:
            if not methodname.startswith("check_"):
                continue
            func = getattr(self, methodname)
            func()


#
# Utility functions
#
def error(out, exit_code=1, do_exit=True):
    '''Print error message and exit'''
    try:
        print("ERROR: %s" % (out), file=sys.stderr)
    except IOError:
        pass

    if do_exit:
        sys.exit(exit_code)


def warn(out):
    '''Print warning message'''
    try:
        print("WARN: %s" % (out), file=sys.stderr)
    except IOError:
        pass


def msg(out, output=sys.stdout):
    '''Print message'''
    try:
        print("%s" % (out), file=output)
    except IOError:
        pass


def debug(out):
    '''Print debug message'''
    global DEBUGGING
    if DEBUGGING:
        try:
            print("DEBUG: %s" % (out), file=sys.stderr)
        except IOError:
            pass


def cmd(command):
    '''Try to execute the given command.'''
    debug(command)
    try:
        sp = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    except OSError as ex:
        return [127, str(ex)]

    if sys.version_info[0] >= 3:
        out = sp.communicate()[0].decode('ascii', 'ignore')
    else:
        out = sp.communicate()[0]

    return [sp.returncode, out]


def cmd_pipe(command1, command2):
    '''Try to pipe command1 into command2.'''
    try:
        sp1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
        sp2 = subprocess.Popen(command2, stdin=sp1.stdout)
    except OSError as ex:
        return [127, str(ex)]

    if sys.version_info[0] >= 3:
        out = sp2.communicate()[0].decode('ascii', 'ignore')
    else:
        out = sp2.communicate()[0]

    return [sp2.returncode, out]


def unpack_click(fn, dest=None):
    '''Unpack click package'''
    if not os.path.isfile(fn):
        error("Could not find '%s'" % fn)
    click_pkg = fn
    if not click_pkg.startswith('/'):
        click_pkg = os.path.absname(click_pkg)
    if dest is None:
        dest = tempfile.mkdtemp(prefix='clickreview-')
    else:
        if not os.path.isdir(dest):
            error("Could not find '%s'" % dest)

    os.chdir(dest)
    (rc, out) = cmd(['dpkg-deb', '-R', click_pkg, dest])
    if rc != 0:
        error("dpkg-deb -R failed with '%d':\n%s" % (rc, out))

    return dest


def open_file_read(path):
    '''Open specified file read-only'''
    try:
        orig = codecs.open(path, 'r', "UTF-8")
    except Exception:
        raise

    return orig


def recursive_rm(dirPath, contents_only=False):
    '''recursively remove directory'''
    names = os.listdir(dirPath)
    for name in names:
        path = os.path.join(dirPath, name)
        if os.path.islink(path) or not os.path.isdir(path):
            os.unlink(path)
        else:
            recursive_rm(path)
    if contents_only is False:
        os.rmdir(dirPath)
