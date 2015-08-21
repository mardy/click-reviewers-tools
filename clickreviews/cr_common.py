'''common.py: common classes and functions'''
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

from __future__ import print_function
import atexit
import codecs
from debian.deb822 import Deb822
import glob
import inspect
import json
import logging
import magic
import os
import pprint
import re
import shutil
import subprocess
import sys
import tempfile
import types
import yaml

DEBUGGING = False
UNPACK_DIR = None
RAW_UNPACK_DIR = None


def cleanup_unpack():
    global UNPACK_DIR
    if UNPACK_DIR is not None and os.path.isdir(UNPACK_DIR):
        recursive_rm(UNPACK_DIR)
    global RAW_UNPACK_DIR
    if RAW_UNPACK_DIR is not None and os.path.isdir(RAW_UNPACK_DIR):
        recursive_rm(RAW_UNPACK_DIR)
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
    # Convenience to break out common types of clicks (eg, app, scope,
    # click service)
    app_allowed_peer_hooks = ["account-application",
                              "account-service",
                              "account-provider",
                              "account-qml-plugin",
                              "apparmor",
                              "content-hub",
                              "desktop",
                              "push-helper",
                              "urls",
                              ]
    scope_allowed_peer_hooks = ["account-application",
                                "account-service",
                                "apparmor",
                                "scope",
                                ]
    # FIXME: when apparmor-policy is implemented, use this
    service_allowed_peer_hooks = ["apparmor",
                                  "bin-path",  # obsoleted, ignored
                                  "snappy-systemd",  # obsoleted, ignored
                                  ]

    snappy_required = ["name", "version"]
    # optional snappy fields here (may be required by appstore)
    snappy_optional = ["architecture",
                       "binaries",
                       "caps",
                       "config",
                       "frameworks",
                       "icon",
                       "immutable-config",
                       "oem",
                       "services",
                       "source",
                       "type",
                       "vendor",  # replaces maintainer
                       ]
    snappy_exe_security = ["caps",
                           "security-template",
                           "security-override",
                           "security-policy"]

    def __init__(self, fn, review_type, peer_hooks=None, overrides=None,
                 peer_hooks_link=None):
        self.click_package = fn
        self._check_path_exists()
        if not self.click_package.endswith(".click") and \
                not self.click_package.endswith(".snap"):
            if self.click_package.endswith(".deb"):
                error("filename does not end with '.click', but '.deb' "
                      "instead. See http://askubuntu.com/a/485544/94326 for "
                      "how click packages are different.")
            error("filename does not end with '.click'")

        self.review_type = review_type
        self.click_report = dict()

        self.result_types = ['info', 'warn', 'error']
        for r in self.result_types:
            self.click_report[r] = dict()

        self.click_report_output = "json"

        global UNPACK_DIR
        if UNPACK_DIR is None:
            UNPACK_DIR = unpack_click(fn)
        self.unpack_dir = UNPACK_DIR

        global RAW_UNPACK_DIR
        if RAW_UNPACK_DIR is None:
            RAW_UNPACK_DIR = raw_unpack_pkg(fn)
        self.raw_unpack_dir = RAW_UNPACK_DIR

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

        # Parse and store the package.yaml
        pkg_yaml = self._extract_package_yaml()
        self.is_snap = False
        if pkg_yaml is not None:
            try:
                self.pkg_yaml = yaml.safe_load(pkg_yaml)
            except Exception:
                error("Could not load package.yaml. Is it properly formatted?")
            self._verify_package_yaml_structure()
            self.is_snap = True

            #  default to 'app'
            if 'type' not in self.pkg_yaml:
                self.pkg_yaml['type'] = 'app'

        self.is_snap_oem = False
        if self.is_snap and 'type' in self.pkg_yaml and \
           self.pkg_yaml['type'] == 'oem':
            self.is_snap_oem = True

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

        self.peer_hooks = peer_hooks
        self.overrides = overrides if overrides is not None else {}
        self.peer_hooks_link = peer_hooks_link

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

    def _extract_package_yaml(self):
        '''Extract and read the snappy package.yaml'''
        y = os.path.join(self.unpack_dir, "meta/package.yaml")
        if not os.path.isfile(y):
            return None  # snappy packaging is still optional
        return open_file_read(y)

    def _extract_hashes_yaml(self):
        '''Extract and read the snappy hashes.yaml'''
        y = os.path.join(self.unpack_dir, "DEBIAN/hashes.yaml")
        return open_file_read(y)

    def _extract_statinfo(self, fn):
        '''Extract statinfo from file'''
        try:
            st = os.stat(fn)
        except Exception:
            return None
        return st

    def _path_join(self, dirname, rest):
        return os.path.join(dirname, rest)

    def _get_sha512sum(self, fn):
        '''Get sha512sum of file'''
        (rc, out) = cmd(['sha512sum', fn])
        if rc != 0:
            return None
        return out.split()[0]

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

        # https://developer.ubuntu.com/snappy/guides/packaging-format-apps/
        snappy_optional = ["ports", "source", "type"]

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

        # FIXME: this is kinda gross but the best we can do while we are trying
        # to support clicks and native snaps
        if 'type' in self.manifest and self.manifest['type'] == 'oem':
            if 'hooks' in self.manifest:
                error("'hooks' present in manifest with type 'oem'")
            # mock up something for other tests
            self.manifest['hooks'] = {'oem': {'reviewtools': True}}

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
            if k not in required + optional + snappy_optional + ['hooks']:
                # click supports local extensions via 'x-...', ignore those
                # here but report in lint
                if k.startswith('x-'):
                    continue
                error("manifest malformed: unsupported field '%s':\n%s" % (k,
                                                                           mp))

    def _verify_package_yaml_structure(self):
        '''Verify package.yaml has the expected structure'''
        # https://developer.ubuntu.com/en/snappy/guides/packaging-format-apps/
        # lp:click doc/file-format.rst
        yp = yaml.dump(self.pkg_yaml, default_flow_style=False, indent=4)
        if not isinstance(self.pkg_yaml, dict):
            error("package yaml malformed:\n%s" % self.pkg_yaml)

        for f in self.snappy_required:
            if f not in self.pkg_yaml:
                error("could not find required '%s' in package.yaml:\n%s" %
                      (f, yp))
            elif f in ['name', 'version']:
                # make sure this is a string for other tests since
                # yaml.safe_load may make it an int, float or str
                self.pkg_yaml[f] = str(self.pkg_yaml[f])

        for f in self.snappy_optional:
            if f in self.pkg_yaml:
                if f in ["architecture", "frameworks"] and not \
                    (isinstance(self.pkg_yaml[f], str) or
                     isinstance(self.pkg_yaml[f], list)):
                    error("yaml malformed: '%s' is not str or list:\n%s" %
                          (f, yp))
                elif f in ["binaries", "services"] and not \
                        isinstance(self.pkg_yaml[f], list):
                    error("yaml malformed: '%s' is not list:\n%s" % (f, yp))
                elif f in ["icon", "source", "type", "vendor"] and not \
                        isinstance(self.pkg_yaml[f], str):
                    error("yaml malformed: '%s' is not str:\n%s" % (f, yp))

    def _verify_peer_hooks(self, my_hook):
        '''Compare manifest for required and allowed hooks'''
        d = dict()
        if self.peer_hooks is None:
            return d

        for app in self.manifest["hooks"]:
            if my_hook not in self.manifest["hooks"][app]:
                continue
            for h in self.peer_hooks[my_hook]['required']:
                if h == my_hook:
                    continue
                if h not in self.manifest["hooks"][app]:
                    # Treat these as equivalent for satisfying peer hooks
                    if h == 'apparmor' and \
                       'apparmor-profile' in self.manifest["hooks"][app]:
                        continue

                    if 'missing' not in d:
                        d['missing'] = dict()
                    if app not in d['missing']:
                        d['missing'][app] = []
                    d['missing'][app].append(h)
            for h in self.manifest["hooks"][app]:
                if h == my_hook:
                    continue
                if h not in self.peer_hooks[my_hook]['allowed']:
                    # 'apparmor-profile' is allowed when 'apparmor' is, but
                    # they may not be used together
                    if h == 'apparmor-profile':
                        if 'apparmor' in self.peer_hooks[my_hook]['allowed'] \
                           and 'apparmor' not in self.manifest["hooks"][app]:
                            continue

                    if 'disallowed' not in d:
                        d['disallowed'] = dict()
                    if app not in d['disallowed']:
                        d['disallowed'][app] = []
                    d['disallowed'][app].append(h)

        return d

    def _verify_pkgname(self, n):
        '''Verify package name'''
        if self.is_snap:
            # snaps can't have '.' in the name
            pat = re.compile(r'^[a-z0-9][a-z0-9+-]+$')
        else:
            pat = re.compile(r'^[a-z0-9][a-z0-9+.-]+$')
        if pat.search(n):
            return True
        return False

    def _verify_pkgversion(self, v):
        '''Verify package name'''
        re_valid_version = re.compile(r'^((\d+):)?'              # epoch
                                      '([A-Za-z0-9.+:~-]+?)'     # upstream
                                      '(-([A-Za-z0-9+.~]+))?$')  # debian
        if re_valid_version.match(v):
            return True
        return False

    def _verify_maintainer(self, m):
        '''Verify maintainer email'''
        #  Simple regex as used by python3-debian. If we wanted to be more
        #  thorough we could use email_re from django.core.validators
        if re.search(r"^(.*)\s+<(.*@.*)>$", m):
            return True
        return False

    def _create_dict(self, lst, topkey='name'):
        '''Converts list of dicts into dict[topkey][<the rest>]. Useful for
           conversions from yaml list to json dict'''
        d = dict()
        for entry in lst:
            if topkey not in entry:
                error("required field '%s' not present: %s" % (topkey, entry))
            name = entry[topkey]
            d[name] = dict()
            for key in entry:
                if key == topkey:
                    continue
                d[name][key] = entry[key]
        return d

    def check_peer_hooks(self, hooks_sublist=[]):
        '''Check if peer hooks are valid'''
        # Nothing to verify
        if self.peer_hooks is None:
            return

        for hook in self.peer_hooks:
            if len(hooks_sublist) > 0 and hook not in hooks_sublist:
                continue
            d = self._verify_peer_hooks(hook)
            t = 'info'
            n = self._get_check_name("peer_hooks_required", extra=hook)
            s = "OK"

            if 'missing' in d and len(d['missing'].keys()) > 0:
                t = 'error'
                for app in d['missing']:
                    s = "Missing required hooks for '%s': %s" % (
                        app, ", ".join(d['missing'][app]))
                    self._add_result(t, n, s, manual_review=True,
                                     link=self.peer_hooks_link)
            else:
                self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name("peer_hooks_disallowed", extra=hook)
            s = "OK"

            if 'disallowed' in d and len(d['disallowed'].keys()) > 0:
                t = 'error'
                for app in d['disallowed']:
                    s = "Disallowed with %s (%s): %s" % (
                        hook, app, ", ".join(d['disallowed'][app]))
                    self._add_result(t, n, s, manual_review=True,
                                     link=self.peer_hooks_link)
            else:
                self._add_result(t, n, s)

    def set_review_type(self, name):
        '''Set review name'''
        self.review_type = name

    def _get_check_name(self, name, app='', extra=''):
        name = ':'.join([self.review_type, name])
        if app:
            name += ':' + app
        if extra:
            name += ':' + extra
        return name

    # click_report[<result_type>][<review_name>] = <result>
    #   result_type: info, warn, error
    #   review_name: name of the check (prefixed with self.review_type)
    #   result: contents of the review
    def _add_result(self, result_type, review_name, result, link=None,
                    manual_review=False):
        '''Add result to report'''
        if result_type not in self.result_types:
            error("Invalid result type '%s'" % result_type)

        if review_name not in self.click_report[result_type]:
            # log info about check so it can be collected into the
            # check-names.list file
            # format should be
            # CHECK|<review_type:check_name>|<link>
            msg = 'CHECK|{}|{}'
            name = ':'.join(review_name.split(':')[:2])
            link_text = link if link is not None else ""
            logging.debug(msg.format(name, link_text))
            self.click_report[result_type][review_name] = dict()

        self.click_report[result_type][review_name].update({
            'text': result,
            'manual_review': manual_review,
        })
        if link is not None:
            self.click_report[result_type][review_name]["link"] = link

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


def raw_unpack_pkg(fn, dest=None):
    '''Unpack raw package'''
    if not os.path.isfile(fn):
        error("Could not find '%s'" % fn)
    pkg = fn
    if not pkg.startswith('/'):
        pkg = os.path.abspath(pkg)

    if dest is not None and os.path.exists(dest):
        error("'%s' exists. Aborting." % dest)

    d = tempfile.mkdtemp(prefix='review-')

    curdir = os.getcwd()
    os.chdir(d)
    (rc, out) = cmd(['ar', 'x', pkg])
    os.chdir(curdir)

    if rc != 0:
        if os.path.isdir(d):
            recursive_rm(d)
        error("'ar x' failed with '%d':\n%s" % (rc, out))

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


def run_click_check(cls):
    if len(sys.argv) < 2:
        error("Must give path to click package")

    # extract args
    fn = sys.argv[1]
    if len(sys.argv) > 2:
        overrides = json.loads(sys.argv[2])
    else:
        overrides = None

    review = cls(fn, overrides=overrides)
    review.do_checks()
    rc = review.do_report()
    sys.exit(rc)
