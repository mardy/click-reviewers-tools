'''sr_security.py: snap security checks'''
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

from __future__ import print_function

from clickreviews.sr_common import (
    SnapReview,
)
from clickreviews.common import (
    cmd,
    create_tempdir,
    ReviewException,
    AA_PROFILE_NAME_MAXLEN,
    AA_PROFILE_NAME_ADVLEN,
    MKSQUASHFS_OPTS,
)
import os


class SnapReviewSecurity(SnapReview):
    '''This class represents snap security reviews'''
    def __init__(self, fn, overrides=None):
        SnapReview.__init__(self, fn, "security-snap-v2", overrides=overrides)

        if not self.is_snap2:
            return

        self.sec_skipped_types = ['oem',
                                  'os',
                                  'kernel']  # these don't need security items

        self.sec_safe_slots = ['mpris']

    def check_security_policy_vendor(self):
        '''Check policy-vendor'''
        if not self.is_snap2:
            return

        t = 'info'
        n = self._get_check_name('policy-vendor')
        s = 'OK'
        if self.policy_vendor not in self.aa_policy:
            t = 'error'
            s = "unknown policy-vendor '%s'" % self.policy_vendor
        self._add_result(t, n, s)

    def check_security_policy_version(self):
        '''Check policy-version'''
        if not self.is_snap2 or self.policy_vendor not in self.aa_policy:
            return

        t = 'info'
        n = self._get_check_name('policy-version')
        s = 'OK'
        if self.policy_version not in self.aa_policy[self.policy_vendor]:
            t = 'error'
            s = "unknown policy-version '%s'" % self.policy_version
        self._add_result(t, n, s)

    def _verify_iface(self, name, iface, interface):
        sec_type = self._get_policy_group_type(self.policy_vendor,
                                               self.policy_version,
                                               interface)
        if sec_type is None:
            return  # not in aa_policy

        o = self._devmode_override()
        if name.endswith('slot') and interface not in self.sec_safe_slots:
            t = 'warn'
            n = self._get_check_name('is_slot', app=iface,
                                     extra=interface)
            s = "(NEEDS REVIEW) slots requires approval"
            m = False
            if o is None:
                m = True
            self._add_result(t, n, s, manual_review=m, override_result_type=o)

        t = 'info'
        n = self._get_check_name('%s_safe' % name, app=iface, extra=interface)
        s = "OK"
        m = False
        l = None
        if interface == "debug":
            t = 'error'
            s = "'%s' not for production use" % interface
            l = 'http://askubuntu.com/a/562123/94326'
            if o is None:
                m = True
        elif sec_type == "reserved":
            t = 'error'
            s = "%s interface '%s' for vetted applications only" % (sec_type,
                                                                    interface)
            if o is None:
                m = True
        elif sec_type != "common":
            t = 'error'
            s = "unknown type '%s' for interface '%s'" % (sec_type, interface)
            o = None
        self._add_result(t, n, s, l, manual_review=m, override_result_type=o)

    def check_security_plugs(self):
        '''Check security plugs'''
        if not self.is_snap2 or 'plugs' not in self.snap_yaml:
            return

        for plug in self.snap_yaml['plugs']:
            # If the 'interface' name is the same as the 'plug' name, then
            # 'interface' is optional since the interface name and the plug
            # name are the same
            interface = plug
            if 'interface' in self.snap_yaml['plugs'][plug]:
                interface = self.snap_yaml['plugs'][plug]['interface']

            self._verify_iface('plug', plug, interface)

    def check_security_apps_plugs(self):
        '''Check security app plugs'''
        if not self.is_snap2 or 'apps' not in self.snap_yaml:
            return

        for app in self.snap_yaml['apps']:
            if 'plugs' not in self.snap_yaml['apps'][app]:
                continue

            # The interface referenced in the app's 'plugs' field can either be
            # a known interface (when the interface name reference and the
            # interface is the same) or can reference a name in the snap's
            # toplevel 'plugs' mapping
            for plug_ref in self.snap_yaml['apps'][app]['plugs']:
                if not isinstance(plug_ref, str):
                    continue  # checked elsewhere
                elif plug_ref not in self.interfaces:
                    continue  # check_security_plugs() verifies these

                self._verify_iface('app_plug', app, plug_ref)

    def check_security_slots(self):
        '''Check security slots'''
        if not self.is_snap2 or 'slots' not in self.snap_yaml:
            return

        for slot in self.snap_yaml['slots']:
            # If the 'interface' name is the same as the 'slot' name, then
            # 'interface' is optional since the interface name and the slot
            # name are the same
            interface = slot
            if 'interface' in self.snap_yaml['slots'][slot]:
                interface = self.snap_yaml['slots'][slot]['interface']

            self._verify_iface('slot', slot, interface)

    def check_security_apps_slots(self):
        '''Check security app slots'''
        if not self.is_snap2 or 'apps' not in self.snap_yaml:
            return

        for app in self.snap_yaml['apps']:
            if 'slots' not in self.snap_yaml['apps'][app]:
                continue

            # The interface referenced in the app's 'slots' field can either be
            # a known interface (when the interface name reference and the
            # interface is the same) or can reference a name in the snap's
            # toplevel 'slots' mapping
            for slot_ref in self.snap_yaml['apps'][app]['slots']:
                if not isinstance(slot_ref, str):
                    continue  # checked elsewhere
                elif slot_ref not in self.interfaces:
                    continue  # check_security_slots() verifies these

                self._verify_iface('app_slot', app, slot_ref)

    def check_apparmor_profile_name_length(self):
        '''Check AppArmor profile name length'''
        if not self.is_snap2 or 'apps' not in self.snap_yaml:
            return

        maxlen = AA_PROFILE_NAME_MAXLEN
        advlen = AA_PROFILE_NAME_ADVLEN

        for app in self.snap_yaml['apps']:
            t = 'info'
            n = self._get_check_name('profile_name_length', app=app)
            s = "OK"
            profile = "%s_%s_%s" % (self.snap_yaml['name'],
                                    app,
                                    self.snap_yaml['version'])
            if len(profile) > maxlen:
                t = 'error'
                s = ("'%s' too long (exceeds %d characters). Please shorten "
                     "'%s', '%s' and/or '%s'" % (profile, maxlen,
                                                 self.snap_yaml['name'],
                                                 app,
                                                 self.snap_yaml['version']))
            elif len(profile) > advlen:
                t = 'warn'
                s = ("'%s' is long (exceeds %d characters) and thus could be "
                     "problematic in certain environments. Please consider "
                     "shortening '%s', '%s' and/or '%s'" % (profile, advlen,
                                                            self.snap_yaml['name'],
                                                            app,
                                                            self.snap_yaml['version']))
            self._add_result(t, n, s)

    def check_squashfs_resquash(self):
        '''Check resquash of squashfs'''
        if not self.is_snap2:
            return

        fn = os.path.abspath(self.pkg_filename)

        # Verify squashfs supports the -fstime option, if not, warn (which
        # blocks in store)
        (rc, out) = cmd(['unsquashfs', '-fstime', fn])
        if rc != 0:
            t = 'warn'
            n = self._get_check_name('squashfs_supports_fstime')
            s = 'could not determine fstime of squashfs'
            self._add_result(t, n, s)
            return
        fstime = out.strip()

        # For now, skip the checks on if have symlinks due to LP: #1555305
        (rc, out) = cmd(['unsquashfs', '-lls', fn])
        if rc != 0:
            t = 'error'
            n = self._get_check_name('squashfs_lls')
            s = 'could not list contents of squashfs'
            self._add_result(t, n, s)
            return
        elif 'lrwxrwxrwx' in out:
            t = 'info'
            n = self._get_check_name('squashfs_resquash_1555305')
            s = 'cannot reproduce squashfs'
            l = 'https://launchpad.net/bugs/1555305'
            self._add_result(t, n, s, link=l)
            return
        # end LP: #1555305 workaround

        tmpdir = create_tempdir()  # this is autocleaned
        tmp_unpack = os.path.join(tmpdir, 'squashfs-root')
        tmp_repack = os.path.join(tmpdir, 'repack.snap')

        curdir = os.getcwd()
        os.chdir(tmpdir)
        # ensure we don't alter the permissions from the unsquashfs
        old_umask = os.umask(000)

        try:
            (rc, out) = cmd(['unsquashfs', '-d', tmp_unpack, fn])
            if rc != 0:
                raise ReviewException("could not unsquash '%s': %s" %
                                      (os.path.basename(fn), out))
            (rc, out) = cmd(['mksquashfs', tmp_unpack, tmp_repack,
                             '-fstime', fstime] + MKSQUASHFS_OPTS)
            if rc != 0:
                raise ReviewException("could not mksquashfs '%s': %s" %
                                      (os.path.relpath(tmp_unpack, tmpdir),
                                       out))
        except ReviewException as e:
            t = 'error'
            n = self._get_check_name('squashfs_resquash')
            self._add_result(t, n, str(e))
            return
        finally:
            os.umask(old_umask)
            os.chdir(curdir)

        # Now calculate the hashes
        t = 'info'
        n = self._get_check_name('squashfs_repack_checksum')
        s = "OK"

        (rc, out) = cmd(['sha512sum', fn])
        if rc != 0:
            t = 'error'
            s = "could not determine checksum of '%s'" % os.path.basename(fn)
            self._add_result(t, n, s)
            return
        orig_sum = out.split()[0]

        (rc, out) = cmd(['sha512sum', tmp_repack])
        if rc != 0:
            t = 'error'
            s = "could not determine checksum of '%s'" % \
                os.path.relpath(tmp_repack, tmpdir)
            self._add_result(t, n, s)
            return
        repack_sum = out.split()[0]

        if orig_sum != repack_sum:
            if 'type' in self.snap_yaml and self.snap_yaml['type'] == 'os':
                t = 'info'
                s = 'checksums do not match (expected for os snap)'
            else:
                # FIXME: turn this into an error once the squashfs-tools bugs
                # are fixed
                # t = 'error'
                t = 'info'
                s = "checksums do not match. Please ensure the snap is " + \
                    "created with either 'snapcraft snap <DIR>' or " + \
                    "'mksquashfs <dir> <snap> %s'" % " ".join(MKSQUASHFS_OPTS)
        self._add_result(t, n, s)
