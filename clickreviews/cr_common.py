'''common.py: common classes and functions'''
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

from __future__ import print_function
import codecs
from debian.deb822 import Deb822
import glob
import inspect
import json
import magic
import os
import pprint
import shutil
import subprocess
import sys
import tempfile
import types

DEBUGGING = False
UNPACK_DIR = None

# cleanup
import atexit


def cleanup_unpack():
    if UNPACK_DIR is not None and os.path.isdir(UNPACK_DIR):
        recursive_rm(UNPACK_DIR)
atexit.register(cleanup_unpack)


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
        self.click_package = fn
        self._check_path_exists()
        if not self.click_package.endswith(".click"):
            if self.click_package.endswith(".deb"):
                error("filename does not end with '.click', but '.deb' "
    "instead. See http://askubuntu.com/a/485544/94326 for how click packages are different.")
            error("filename does not end with '.click'")

        self.review_type = review_type
        self.click_report = dict()

        self.result_types = ['info', 'warn', 'error']
        for r in self.result_types:
            self.click_report[r] = dict()

        self.click_report_output = "json"

        self.unpack_dir = unpack_click(fn)
        global UNPACK_DIR
        UNPACK_DIR = self.unpack_dir

        # Get some basic information from the control file

        control_file = self._extract_control_file()
        tmp = list(Deb822.iter_paragraphs(control_file))
        if len(tmp) != 1:
            error("malformed control file: too many paragraphs")
        control = tmp[0]
        self.click_pkgname = control['Package']
        self.click_version = control['Version']
        self.click_arch = control['Architecture']

        # Parse and store the manifest
        manifest_json = self._extract_manifest_file()
        try:
            self.manifest = json.load(manifest_json)
        except Exception:
            error("Could not load manifest file. Is it properly formatted?")
        self._verify_manifest_structure()

        # Get a list of all unpacked files, except DEBIAN/
        self.pkg_files = []
        self._list_all_files()

        # Setup what is needed to get a list of all unpacked compiled binaries
        self.mime = magic.open(magic.MAGIC_MIME)
        self.mime.load()
        self.pkg_bin_files = []
        # Don't run this here since only cr_lint.py and cr_functional.py need
        # it now
        # self._list_all_compiled_binaries()

        self.valid_frameworks = self._extract_click_frameworks()

    def _extract_click_frameworks(self):
        '''Extract installed click frameworks'''
        # TODO: update to use libclick API when available
        valid_frameworks = []
        frameworks = sorted(
            glob.glob("/usr/share/click/frameworks/*.framework"))
        if len(frameworks) == 0:
            valid_frameworks.append('ubuntu-sdk-13.10')
        else:
            for f in frameworks:
                valid_frameworks.append(os.path.basename(
                                        os.path.splitext(f)[0]))
        return valid_frameworks

    def _extract_manifest_file(self):
        '''Extract and read the manifest file'''
        m = os.path.join(self.unpack_dir, "DEBIAN/manifest")
        if not os.path.isfile(m):
            error("Could not find manifest file")
        return open_file_read(m)

    def _check_path_exists(self):
        '''Check that the provided path exists'''
        if not os.path.exists(self.click_package):
            error("Could not find '%s'" % self.click_package)

    def _extract_control_file(self):
        '''Extract '''
        fh = open_file_read(os.path.join(self.unpack_dir, "DEBIAN/control"))
        return fh.readlines()

    def _list_all_files(self):
        '''List all files included in this click package.'''
        for root, dirnames, filenames in os.walk(self.unpack_dir):
            for f in filenames:
                self.pkg_files.append(os.path.join(root, f))

    def _list_all_compiled_binaries(self):
        '''List all compiled binaries in this click package.'''
        for i in self.pkg_files:
            res = self.mime.file(i)
            if res in ['application/x-executable; charset=binary',
                       'application/x-sharedlib; charset=binary']:
                self.pkg_bin_files.append(i)

    def _verify_manifest_structure(self):
        '''Verify manifest has the expected structure'''
        # lp:click doc/file-format.rst
        mp = pprint.pformat(self.manifest)
        if not isinstance(self.manifest, dict):
            error("manifest malformed:\n%s" % self.manifest)

        required = ["name", "version", "framework"]  # click required
        for f in required:
            if f not in self.manifest:
                error("could not find required '%s' in manifest:\n%s" % (f,
                                                                         mp))
            elif not isinstance(self.manifest[f], str):
                error("manifest malformed: '%s' is not str:\n%s" % (f, mp))

        # optional click fields here (may be required by appstore)
        # http://click.readthedocs.org/en/latest/file-format.html
        optional = ["title", "description", "maintainer", "architecture",
                    "installed-size", "icon"]

        for f in optional:
            if f in self.manifest:
                if f != "architecture" and \
                   not isinstance(self.manifest[f], str):
                    error("manifest malformed: '%s' is not str:\n%s" % (f, mp))
                elif f == "architecture" and not \
                    (isinstance(self.manifest[f], str) or
                     isinstance(self.manifest[f], list)):
                    error("manifest malformed: '%s' is not str or list:\n%s" %
                          (f, mp))

        # Not required by click, but required by appstore. 'hooks' is assumed
        # to be present in other checks
        if 'hooks' not in self.manifest:
            error("could not find required 'hooks' in manifest:\n%s" % mp)
        if not isinstance(self.manifest['hooks'], dict):
            error("manifest malformed: 'hooks' is not dict:\n%s" % mp)
        # 'hooks' is assumed to be present and non-empty in other checks
        if len(self.manifest['hooks']) < 1:
            error("manifest malformed: 'hooks' is empty:\n%s" % mp)
        for app in self.manifest['hooks']:
            if not isinstance(self.manifest['hooks'][app], dict):
                error("manifest malformed: hooks/%s is not dict:\n%s" % (app,
                                                                         mp))
            # let cr_lint.py handle required hooks
            if len(self.manifest['hooks'][app]) < 1:
                error("manifest malformed: hooks/%s is empty:\n%s" % (app, mp))

        for k in sorted(self.manifest):
            if k not in required + optional + ['hooks']:
                # click supports local extensions via 'x-...', ignore those
                # here but report in lint
                if k.startswith('x-'):
                    continue
                error("manifest malformed: unsupported field '%s':\n%s" % (k,
                                                                           mp))

    def set_review_type(self, name):
        '''Set review name'''
        self.review_type = name

    # click_report[<result_type>][<review_name>] = <result>
    #   result_type: info, warn, error
    #   review_name: name of the check (prefixed with self.review_type)
    #   result: contents of the review
    def _add_result(self, result_type, review_name, result, link=None):
        '''Add result to report'''
        if result_type not in self.result_types:
            error("Invalid result type '%s'" % result_type)

        name = "%s_%s" % (self.review_type, review_name)
        if name not in self.click_report[result_type]:
            self.click_report[result_type][name] = dict()

        self.click_report[result_type][name]["text"] = result
        if link is not None:
            self.click_report[result_type][name]["link"] = link

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
        click_pkg = os.path.abspath(click_pkg)

    if dest is not None and os.path.exists(dest):
        error("'%s' exists. Aborting." % dest)

    d = tempfile.mkdtemp(prefix='clickreview-')

    curdir = os.getcwd()
    os.chdir(d)
    (rc, out) = cmd(['dpkg-deb', '-R', click_pkg, d])
    os.chdir(curdir)

    if rc != 0:
        if os.path.isdir(d):
            recursive_rm(d)
        error("dpkg-deb -R failed with '%d':\n%s" % (rc, out))

    if dest is None:
        dest = d
    else:
        shutil.move(d, dest)

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
