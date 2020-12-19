'''cr_desktop.py: click desktop checks'''
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

from clickreviews.cr_common import ClickReview, error, open_file_read
import glob
import json
import os
import re
from urllib.parse import urlsplit
from xdg.DesktopEntry import DesktopEntry
from xdg.Exceptions import ParsingError as xdgParsingError


class ClickReviewDesktop(ClickReview):
    '''This class represents click lint reviews'''
    supported_versions = ("1.0", "1.1", "1.2", "1.3", "1.4", "1.5")

    def __init__(self, fn, overrides=None):
        peer_hooks = dict()
        my_hook = 'desktop'
        peer_hooks[my_hook] = dict()
        peer_hooks[my_hook]['allowed'] = ClickReview.app_allowed_peer_hooks
        peer_hooks[my_hook]['required'] = ["apparmor"]

        ClickReview.__init__(self, fn, "desktop", peer_hooks=peer_hooks,
                             overrides=overrides)
        if not self.is_click and not self.is_snap1:
            return

        self.desktop_files = dict()  # click-show-files and a couple tests
        self.desktop_entries = dict()
        self.desktop_hook_entries = 0

        if self.manifest is None:
            return

        for app in self.manifest['hooks']:
            if 'desktop' not in self.manifest['hooks'][app]:
                # msg("Skipped missing desktop hook for '%s'" % app)
                continue
            if not isinstance(self.manifest['hooks'][app]['desktop'], str):
                error("manifest malformed: hooks/%s/desktop is not str" % app)
            self.desktop_hook_entries += 1
            (de, full_fn) = self._extract_desktop_entry(app)
            self.desktop_entries[app] = de
            self.desktop_files[app] = full_fn

        self.required_keys = ['Name',
                              'Type',
                              'Icon',
                              'Exec',
                              'X-Ubuntu-Touch',
                              ]
        self.expected_execs = ['qmlscene',
                               'webbrowser-app',
                               'webapp-container',
                               'ubuntu-html5-app-launcher',
                               ]
        self.deprecated_execs = ['cordova-ubuntu-2.8',
                                 ]
        # TODO: the desktop hook will actually handle this correctly
        self.blacklisted_keys = ['Path']

    def _extract_desktop_entry(self, app):
        '''Get DesktopEntry for desktop file and verify it'''
        d = self.manifest['hooks'][app]['desktop']
        fn = os.path.join(self.unpack_dir, d)

        bn = os.path.basename(fn)
        if not os.path.exists(fn):
            error("Could not find '%s'" % bn)

        fh = open_file_read(fn)
        contents = ""
        for line in fh.readlines():
            contents += line
        fh.close()

        try:
            de = DesktopEntry(fn)
        except xdgParsingError as e:
            error("desktop file unparseable: %s (%s):\n%s" % (bn, str(e),
                                                              contents))
        try:
            de.parse(fn)
        except Exception as e:
            error("desktop file unparseable: %s (%s):\n%s" % (bn, str(e),
                                                              contents))
        return de, fn

    def _get_desktop_entry(self, app):
        '''Get DesktopEntry from parsed values'''
        return self.desktop_entries[app]

    def _get_desktop_files(self):
        '''Get desktop_files (abstracted out for mock)'''
        return self.desktop_files

    def _get_desktop_filename(self, app):
        '''Get desktop file filenames'''
        return self.desktop_files[app]

    def check_desktop_file(self):
        '''Check desktop file'''
        if not self.is_click and not self.is_snap1:
            return

        t = 'info'
        n = self._get_check_name('files_usable')
        s = 'OK'
        if len(self._get_desktop_files().keys()) != self.desktop_hook_entries:
            t = 'error'
            s = 'Could not use all specified .desktop files'
        elif self.desktop_hook_entries == 0:
            s = 'Skipped: could not find any desktop files'
        self._add_result(t, n, s)

    def check_desktop_file_valid(self):
        '''Check desktop file validates'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('validates', app=app)
            s = 'OK'
            link = None
            try:
                de.validate()
            except Exception as e:
                t = 'error'
                s = 'did not validate: (%s)' % str(e)
                link = ('http://askubuntu.com/questions/417377/'
                        'what-does-desktop-validates-mean/417378')
            self._add_result(t, n, s, link)

    def check_desktop_required_keys(self):
        '''Check for required keys'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('required_keys', app=app)
            s = "OK"
            missing = []
            for f in self.required_keys:
                if not de.hasKey(f):
                    missing.append(f)
            if len(missing) > 0:
                t = 'error'
                s = 'missing required keys: %s' % ",".join(missing)
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('required_fields_not_empty', app=app)
            s = "OK"
            empty = []
            for f in self.required_keys:
                if de.hasKey(f) and de.get(f) == "":
                    empty.append(f)
            if len(empty) > 0:
                t = 'error'
                s = 'Empty required keys: %s' % ",".join(empty)
            self._add_result(t, n, s)

    def check_desktop_blacklisted_keys(self):
        '''Check for blacklisted keys'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('blacklisted_keys', app=app)
            s = "OK"
            found = []
            for f in self.blacklisted_keys:
                if de.hasKey(f):
                    found.append(f)
            if len(found) > 0:
                t = 'error'
                s = 'found blacklisted keys: %s' % ",".join(found)
            self._add_result(t, n, s)

    def check_desktop_exec(self):
        '''Check Exec entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('Exec', app=app)
            s = 'OK'
            link = None
            if not de.hasKey('Exec'):
                t = 'error'
                s = "missing key 'Exec'"
            elif de.getExec().startswith('/'):
                t = 'error'
                s = "absolute path '%s' for Exec given in .desktop file." % \
                    de.getExec()
                link = ('http://askubuntu.com/questions/417381/'
                        'what-does-desktop-exec-mean/417382')
            elif de.getExec().split()[0] not in self.expected_execs:
                if self.pkg_arch[0] == "all":  # interpreted file
                    template = "found %s Exec with architecture '%s': %s"
                    if de.getExec().split()[0] not in self.deprecated_execs:
                        verb = 'unexpected'
                    else:
                        verb = 'deprecated'
                    s = template % \
                        (verb, self.pkg_arch[0], de.getExec().split()[0])
                    t = 'warn'
                else:                        # compiled
                    # TODO: this can be a lot smarter
                    s = "Non-standard Exec with architecture " + \
                        "'%s': %s (ok for compiled code)" % \
                        (self.pkg_arch[0], de.getExec().split()[0])
                    t = 'info'
            self._add_result(t, n, s, link)

    def check_desktop_exec_webapp_container(self):
        '''Check Exec=webapp-container entry'''
        if not self.is_click and not self.is_snap1:
            return

        if self.manifest is None:
            return

        fwk = self.manifest['framework']

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('Exec_webapp_container', app=app)
            s = 'OK'
            if not de.hasKey('Exec'):
                t = 'error'
                s = "missing key 'Exec'"
                self._add_result(t, n, s)
                continue
            elif de.getExec().split()[0] == "ubuntu-html5-app-launcher" and \
                    fwk.startswith('ubuntu-sdk') and not \
                    (fwk.startswith('ubuntu-sdk-13') or
                     fwk.startswith('ubuntu-sdk-14')):
                # ubuntu-html5-app-launcher only available in ubuntu-sdk-14.10
                # and lower
                t = 'error'
                s = "ubuntu-html5-app-launcher is obsoleted in 15.04 " + \
                    "frameworks and higher. Please use 'webapp-container' " + \
                    "instead and ensure your security policy uses the " + \
                    "'ubuntu-webapp' template"
                self._add_result(t, n, s)
                continue
            elif de.getExec().split()[0] != "webapp-container":
                s = "SKIPPED (not webapp-container)"
                self._add_result(t, n, s)
                continue

            t = 'info'
            n = self._get_check_name('Exec_webapp_container_webapp', app=app)
            s = 'OK'
            if '--webapp' in de.getExec().split():
                t = 'error'
                s = "should not use --webapp in '%s'" % \
                    (de.getExec())
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('Exec_webapp_container_13.10', app=app)
            s = 'OK'
            if self.manifest['framework'] == "ubuntu-sdk-13.10":
                t = 'info'
                s = "'webapp-container' not available in 13.10 release " \
                    "images (ok if targeting 14.04 images with %s " \
                    "framework" % self.manifest['framework']
            self._add_result(t, n, s)

    def check_desktop_exec_webbrowser(self):
        '''Check Exec=webbrowser-app entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('Exec_webbrowser', app=app)
            s = 'OK'
            if not de.hasKey('Exec'):
                t = 'error'
                s = "missing key 'Exec'"
                self._add_result(t, n, s)
                continue
            elif de.getExec().split()[0] != "webbrowser-app":
                s = "SKIPPED (not webbrowser-app)"
                self._add_result(t, n, s)
                continue

            t = 'info'
            n = self._get_check_name('Exec_webbrowser_webapp', app=app)
            s = 'OK'
            if '--webapp' not in de.getExec().split():
                t = 'error'
                s = "could not find --webapp in '%s'" % \
                    (de.getExec())
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('Exec_webbrowser_13.10', app=app)
            s = 'OK'
            if self.manifest['framework'] != "ubuntu-sdk-13.10":
                t = 'error'
                s = "may not use 'webbrowser-app' with framework '%s'" % \
                    self.manifest['framework']
            self._add_result(t, n, s)

    def check_desktop_exec_webapp_args(self):
        '''Check Exec=web* args'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('Exec_webapp_args', app=app)
            s = 'OK'
            if not de.hasKey('Exec'):
                t = 'error'
                s = "missing key 'Exec'"
                self._add_result(t, n, s)
                continue
            elif de.getExec().split()[0] != "webbrowser-app" and \
                    de.getExec().split()[0] != "webapp-container":
                s = "SKIPPED (not webapp-container or webbrowser-app)"
                self._add_result(t, n, s)
                continue

            t = 'info'
            n = self._get_check_name('Exec_webapp_args_minimal_chrome',
                                     app=app)
            s = 'OK'
            if '--enable-back-forward' not in de.getExec().split():
                s = "could not find --enable-back-forward in '%s'" % \
                    (de.getExec())
            self._add_result(t, n, s)

            # verify the presence of either webappUrlPatterns or
            # webappModelSearchPath
            t = 'info'
            n = self._get_check_name('Exec_webapp_args_required', app=app)
            s = 'OK'
            found_url_patterns = False
            found_model_search_path = False
            found_named_webapp = False
            urls = []
            for i in de.getExec().split():
                if i == "webbrowser-app" or i == "webapp-container":
                    continue
                if i.startswith('--webappUrlPatterns'):
                    found_url_patterns = True
                if i.startswith('--webappModelSearchPath'):
                    found_model_search_path = True
                if i.startswith('--webapp='):
                    found_model_search_path = True
                # consider potential Exec field codes as 'non urls'
                if not i.startswith('--') and not i.startswith('%'):
                    urls.append(i)
            is_launching_local_app = True
            if len(urls) == 0:
                is_launching_local_app = False
            for url in urls:
                parts = urlsplit(url)
                if parts.scheme in ['http', 'https']:
                    is_launching_local_app = False
                    break
            if is_launching_local_app and \
                    (found_url_patterns or found_model_search_path or
                     found_named_webapp):
                t = 'error'
                s = "should not specify --webappUrlPatterns, " + \
                    "--webappModelSearchPath or --webapp= when " + \
                    "running local application"
            elif not is_launching_local_app:
                if not found_url_patterns and not found_model_search_path:
                    t = 'error'
                    s = "must specify one of --webappUrlPatterns or " + \
                        "--webappModelSearchPath"
            self._add_result(t, n, s)

    def _check_patterns(self, app, patterns, args):
        pattern_count = 1
        for pattern in patterns:
            urlp_scheme_pat = pattern[:-1].split(':')[0]
            urlp_p = urlsplit(re.sub(r'\?', '', pattern[:-1]))
            target = args[-1]
            urlp_t = urlsplit(target)

            t = 'info'
            n = self._get_check_name(
                'Exec_webbrowser_webapp_url_patterns_has_https', app=app,
                extra=pattern)
            s = 'OK'
            if not pattern.startswith('https?://'):
                t = 'warn'
                s = "'https?://' not found in '%s'" % pattern + \
                    " (may cause needless redirect)"
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name(
                'Exec_webbrowser_webapp_url_patterns_uses_trailing_glob',
                app=app, extra=pattern)
            s = 'OK'
            if not pattern.endswith('*'):
                t = 'warn'
                s = "'%s' does not end with '*'" % pattern + \
                    " (may cause needless redirect) - %s" % urlp_p.path
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name(
                'Exec_webbrowser_webapp_url_patterns_uses_unsafe_glob',
                app=app, extra=pattern)
            s = 'OK'
            if len(urlp_p.path) == 0 and pattern.endswith('*'):
                t = 'error'
                s = "'%s' contains trailing glob in netloc" % pattern
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name(
                'Exec_webbrowser_webapp_url_patterns_uses_safe_glob',
                app=app, extra=pattern)
            s = 'OK'
            if '*' in pattern[:-1] and \
               (pattern[:-1].count('*') != 1 or
                    not pattern.startswith('https?://*')):
                t = 'warn'
                s = "'%s' contains nested '*'" % pattern + \
                    " (needs human review)"
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name('Exec_webbrowser_target_exists', app=app)
            s = 'OK'
            if urlp_t.scheme == "":
                t = 'error'
                s = 'Exec line does not end with parseable URL'
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name(
                'Exec_webbrowser_target_scheme_matches_patterns',
                app=app, extra=pattern)
            s = 'OK'
            if not re.match(r'^%s$' % urlp_scheme_pat, urlp_t.scheme):
                t = 'error'
                s = "'%s' doesn't match '%s' " % (urlp_t.scheme,
                                                  urlp_scheme_pat) + \
                    "(will likely cause needless redirect)"
            self._add_result(t, n, s)

            t = 'info'
            n = self._get_check_name(
                'Exec_webbrowser_target_netloc_matches_patterns',
                app=app, extra=pattern)
            s = 'OK'
            # TODO: this is admittedly simple, but matches Canonical
            #       webapps currently, so ok for now
            if urlp_p.netloc.startswith('*') and len(urlp_p.netloc) > 2 and \
               urlp_t.netloc.endswith(urlp_p.netloc[1:]):
                s = "OK ('%s' matches '%s')" % (urlp_t.netloc, urlp_p.netloc)
            elif urlp_t.netloc != urlp_p.netloc:
                if pattern_count == 1:
                    t = 'warn'
                    s = "'%s' != primary pattern '%s'" % \
                        (urlp_t.netloc, urlp_p.netloc) + \
                        " (may cause needless redirect)"
                else:
                    t = 'info'
                    s = "target '%s' != non-primary pattern '%s'" % \
                        (urlp_t.netloc, urlp_p.netloc)
            self._add_result(t, n, s)

            pattern_count += 1

    def check_desktop_exec_webbrowser_urlpatterns(self):
        '''Check Exec=webbrowser-app entry has valid --webappUrlPatterns'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            execline = de.getExec().split()
            if not de.hasKey('Exec'):
                continue
            elif execline[0] != "webbrowser-app":
                continue
            elif len(execline) < 2:
                continue

            args = execline[1:]
            t = 'info'
            n = self._get_check_name(
                'Exec_webbrowser_webappUrlPatterns', app=app)
            s = 'OK'
            pats = ""
            count = 0
            for a in args:
                if not a.startswith('--webappUrlPatterns='):
                    continue
                pats = a.split('=', maxsplit=1)[1]
                count += 1

            if count == 0:
                # one of --webappUrlPatterns or --webappModelSearchPath is a
                # required arg and generates an error so just make this info
                t = 'info'
                s = "SKIPPED (--webappUrlPatterns not specified)"
                self._add_result(t, n, s)
                continue
            elif count > 1:
                t = 'error'
                s = "found multiple '--webappUrlPatterns=' in '%s'" % \
                    " ".join(args)
                self._add_result(t, n, s)
                continue

            self._check_patterns(app, pats.split(','), args)

    def _extract_webapp_manifests(self):
        '''Extract webapp manifest file'''
        files = sorted(glob.glob("%s/unity-webapps-*/manifest.json" %
                       self.unpack_dir))

        manifests = dict()
        for fn in files:
            key = os.path.relpath(fn, self.unpack_dir)
            try:
                manifests[key] = json.load(open_file_read(fn))
            except Exception:
                manifests[key] = None
                error("Could not parse '%s'" % fn, do_exit=False)

        return manifests

    def check_desktop_exec_webbrowser_modelsearchpath(self):
        '''Check Exec=webbrowser-app entry has valid --webappModelSearchPath'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            execline = de.getExec().split()
            if not de.hasKey('Exec'):
                continue
            elif execline[0] != "webbrowser-app":
                continue
            elif len(execline) < 2:
                continue

            args = execline[1:]
            t = 'info'
            n = self._get_check_name(
                'Exec_webbrowser_webappModelSearchPath_present', app=app)
            s = 'OK'
            path = ""
            count = 0
            for a in args:
                if not a.startswith('--webappModelSearchPath='):
                    continue
                path = a.split('=', maxsplit=1)[1]
                count += 1

            if count == 0:
                # one of --webappUrlPatterns or --webappModelSearchPath is a
                # required arg and generates an error so just make this info
                t = 'info'
                s = "SKIPPED (--webappModelSearchPath not specified)"
                self._add_result(t, n, s)
                continue
            elif count > 1:
                t = 'error'
                s = "found multiple '--webappModelSearchPath=' in '%s'" % \
                    " ".join(args)
                self._add_result(t, n, s)
                continue

            if not path:
                t = 'error'
                s = 'empty arg to --webappModelSearchPath'
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            # if --webappModelSearchPath is specified, that means we should
            # look for webapp configuration in the manifest.json in
            # ubuntu-webapps-*/
            manifests = self._extract_webapp_manifests()
            t = 'info'
            n = self._get_check_name(
                'Exec_webbrowser_webapp_manifest', app=app)
            s = 'OK'
            if len(manifests) == 0:
                t = 'error'
                s = 'could not find unity-webaps-*/manifest.json'
                self._add_result(t, n, s)
                continue
            elif len(manifests) > 1:
                # for now error on this since having
                # multiple manifests is unknown
                t = 'error'
                fns = []
                for f in manifests.keys():
                    fns.append(f)
                s = 'found multiple webapp manifest files: %s' % ",".join(fns)
                self._add_result(t, n, s)
                continue
            self._add_result(t, n, s)

            for k in manifests.keys():
                m = manifests[k]

                t = 'info'
                n = self._get_check_name(
                    'Exec_webbrowser_webapp_manifest_wellformed', app=app,
                    extra=k)
                s = 'OK'
                if m is None or m == 'null':  # 'null' is for testsuite
                    t = 'error'
                    s = 'could not load webapp manifest file. Is it ' + \
                        'properly formatted?'
                    self._add_result(t, n, s)
                    continue
                self._add_result(t, n, s)

                # 'includes' contains the patterns
                t = 'info'
                n = self._get_check_name(
                    'Exec_webbrowser_webapp_manifest_includes_present',
                    app=app, extra=k)
                s = 'OK'
                if 'includes' not in m:
                    t = 'error'
                    s = "could not find 'includes' in webapp manifest"
                elif not isinstance(m['includes'], list):
                    t = 'error'
                    s = "'includes' in webapp manifest is not list"
                self._add_result(t, n, s)
                if t == 'error':
                    continue

                self._check_patterns(app, m['includes'], args)

    def check_desktop_groups(self):
        '''Check Desktop Entry entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('groups', app=app)
            s = "OK"
            if len(de.groups()) != 1:
                t = 'error'
                s = 'too many desktop groups'
            elif "Desktop Entry" not in de.groups():
                t = 'error'
                s = "'[Desktop Entry]' group not found"
            self._add_result(t, n, s)

    def check_desktop_type(self):
        '''Check Type entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('Type', app=app)
            s = "OK"
            if not de.hasKey('Type'):
                t = 'error'
                s = "missing key 'Type'"
            elif de.getType() != "Application":
                t = 'error'
                s = 'does not use Type=Application'
            self._add_result(t, n, s)

    def check_desktop_x_ubuntu_touch(self):
        '''Check X-Ubuntu-Touch entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('X-Ubuntu-Touch', app=app)
            s = "OK"
            if not de.hasKey('X-Ubuntu-Touch'):
                t = 'error'
                s = "missing key 'X-Ubuntu-Touch'"
            elif de.get("X-Ubuntu-Touch") != "true" and \
                    de.get("X-Ubuntu-Touch") != "True":
                t = 'error'
                s = 'does not use X-Ubuntu-Touch=true'
            self._add_result(t, n, s)

    def check_desktop_x_ubuntu_stagehint(self):
        '''Check X-Ubuntu-StageHint entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('X-Ubuntu-StageHint', app=app)
            s = "OK"
            if not de.hasKey('X-Ubuntu-StageHint'):
                t = 'info'
                s = "OK (not specified)"
            elif de.get("X-Ubuntu-StageHint") != "SideStage":
                t = 'error'
                s = "unsupported X-Ubuntu-StageHint=%s " % \
                    de.get("X-Ubuntu-StageHint") + \
                    "(should be for example, 'SideStage')"
            self._add_result(t, n, s)

    def check_desktop_x_ubuntu_gettext_domain(self):
        '''Check X-Ubuntu-Gettext-Domain entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('X-Ubuntu-Gettext-Domain', app=app)
            s = "OK"
            if not de.hasKey('X-Ubuntu-Gettext-Domain'):
                t = 'info'
                s = "OK (not specified)"
            elif de.get("X-Ubuntu-Gettext-Domain") == "":
                t = 'error'
                s = "X-Ubuntu-Gettext-Domain is empty"
            elif de.get("X-Ubuntu-Gettext-Domain") != self.click_pkgname:
                t = 'warn'
                s = "'%s' != '%s'" % (de.get("X-Ubuntu-Gettext-Domain"),
                                      self.click_pkgname)
                s += " (ok if app uses i18n.domain('%s')" % \
                     de.get("X-Ubuntu-Gettext-Domain") + \
                     " or uses organizationName"
            self._add_result(t, n, s)

    def check_desktop_terminal(self):
        '''Check Terminal entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('Terminal', app=app)
            s = "OK"
            if not de.hasKey('Terminal'):
                s = "OK (not specified)"
            elif de.getTerminal() is not False:
                t = 'error'
                s = 'does not use Terminal=false (%s)' % de.getTerminal()
            self._add_result(t, n, s)

    def check_desktop_version(self):
        '''Check Version entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('Version', app=app)
            s = "OK"
            link = None
            if not de.hasKey('Version'):
                s = "OK (not specified)"
            elif de.getVersionString() not in self.supported_versions:
                # http://standards.freedesktop.org/desktop-entry-spec/latest
                t = 'error'
                s = "'%s' does not match any freedesktop.org version %s" % \
                    (de.getVersionString(), self.supported_versions)
                link = ('http://askubuntu.com/questions/419907/'
                        'what-does-version-mean-in-the-desktop-file/419908')
            self._add_result(t, n, s, link)

    def check_desktop_comment(self):
        '''Check Comment entry'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('Comment_boilerplate', app=app)
            s = "OK"
            link = None
            if de.hasKey('Comment') and \
                    de.getComment() == "My project description":
                t = 'warn'
                s = "Comment uses SDK boilerplate '%s'" % de.getComment()
                link = ('http://askubuntu.com/questions/417359/'
                        'what-does-desktop-comment-boilerplate-mean/417360')
            self._add_result(t, n, s, link)

    def check_desktop_icon(self):
        '''Check Icon entry'''
        if not self.is_click and not self.is_snap1:
            return

        ICON_SUFFIXES = ['.svg',
                         '.png',
                         '.jpg',
                         ]
        for app in sorted(self.desktop_entries):
            de = self._get_desktop_entry(app)
            t = 'info'
            n = self._get_check_name('Icon', app=app)
            s = 'OK'
            link = None
            if not de.hasKey('Icon'):
                t = 'error'
                s = "missing key 'Icon'"
                link = ('http://askubuntu.com/questions/417369/'
                        'what-does-desktop-icon-mean/417370')
            elif de.getIcon().startswith('/'):
                t = 'error'
                s = "absolute path '%s' for icon given in .desktop file." % \
                    de.getIcon()
                link = ('http://askubuntu.com/questions/417369/'
                        'what-does-desktop-icon-mean/417370')
            elif not os.path.exists(os.path.join(self.unpack_dir,
                                                 de.getIcon())) and \
                    not any(map(lambda a:
                                os.path.exists(os.path.join(
                                               self.unpack_dir,
                                               de.getIcon() + a)),
                                ICON_SUFFIXES)):
                t = 'error'
                s = "'%s' specified as icon in .desktop file for app '%s', " \
                    "which is not available in the click package." % \
                    (de.getIcon(), app)
                link = ('http://askubuntu.com/questions/417369/'
                        'what-does-desktop-icon-mean/417370')
            self._add_result(t, n, s, link)

    def check_desktop_duplicate_entries(self):
        '''Check desktop for duplicate entries'''
        if not self.is_click and not self.is_snap1:
            return

        for app in sorted(self.desktop_entries):
            found = []
            dupes = []
            t = 'info'
            n = self._get_check_name('duplicate_keys', app=app)
            s = 'OK'
            fn = self._get_desktop_filename(app)
            content = open_file_read(fn).readlines()
            for line in content:
                tmp = line.split('=')
                if len(tmp) < 2:
                    continue
                if tmp[0] in found:
                    dupes.append(tmp[0])
                else:
                    found.append(tmp[0])
            if len(dupes) > 0:
                t = 'error'
                s = 'found duplicate keys: %s' % ",".join(dupes)
            self._add_result(t, n, s)
