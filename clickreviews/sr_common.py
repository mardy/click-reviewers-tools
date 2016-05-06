'''sr_common.py: common classes and functions'''
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
import os
import re
import yaml


from clickreviews.common import(
    Review,
    ReviewException,
    error,
    open_file_read,
)

import clickreviews.apparmor_policy as apparmor_policy


#
# Utility classes
#
class SnapReviewException(ReviewException):
    '''This class represents SnapReview exceptions'''


class SnapReview(Review):
    '''This class represents snap reviews'''
    snappy_required = ["name",
                       "version",
                       ]
    # optional snappy fields here (may be required by appstore)
    snappy_optional = ["apps",
                       "architectures",
                       "description",
                       "license-agreement",
                       "license-version",
                       "summary",
                       "type",
                       "plugs",
                       "slots",
                       ]

    apps_required = ['command']
    apps_optional = ['daemon',
                     'stop-command',
                     'stop-timeout',
                     'restart-condition',
                     'post-stop-command',
                     'plugs',
                     'slots',
                     'ports',
                     'socket',
                     'listen-stream',
                     'socket-user',
                     'socket-group',
                     ]

    # https://docs.google.com/document/d/1Q5_T00yTq0wobm_nHzCV-KV8R4jdk-PXcrtm80ETTLU/edit#
    # 'plugs':
    #    'interface': name
    #    'attrib-name': <type>
    # interfaces lists interfaces and the valid attribute names for the
    # interface with the valid python type for the attribute (eg, [], '', {},
    # etc). These interfaces are likely going to change based on release, but
    # for now, this is fine. Interfaces with no attributes should specify an
    # empty dictionary.
    #
    # Interfaces from apparmor-easyprof-ubuntu.json in __init__() so they don't
    # have to be added here
    interfaces = {'bool-file': {'path': ""},
                  }

    def __init__(self, fn, review_type, overrides=None):
        Review.__init__(self, fn, review_type, overrides=overrides)

        if not self.is_snap2:
            return

        snap_yaml = self._extract_snap_yaml()
        try:
            self.snap_yaml = yaml.safe_load(snap_yaml)
        except Exception:  # pragma: nocover
            error("Could not load snap.yaml. Is it properly formatted?")

        # If local_copy is None, then this will check the server to see if
        # we are up to date. However, if we are working within the development
        # tree, use it unconditionally.
        local_copy = None
        branch_fn = os.path.join(os.path.dirname(__file__),
                                 '../data/apparmor-easyprof-ubuntu.json')
        if os.path.exists(branch_fn):
            local_copy = branch_fn
        p = apparmor_policy.ApparmorPolicy(local_copy)
        self.aa_policy = p.policy

        # TODO: may need updating for ubuntu-personal, etc
        self.policy_vendor = "ubuntu-core"
        self.policy_version = str(self._pkgfmt_version())

        if self.policy_vendor in self.aa_policy and \
                self.policy_version in self.aa_policy[self.policy_vendor] and \
                'policy_groups' in self.aa_policy[self.policy_vendor][self.policy_version]:
            for t in ['common', 'reserved']:
                if t not in self.aa_policy[self.policy_vendor][self.policy_version]['policy_groups']:
                    continue
                for p in self.aa_policy[self.policy_vendor][self.policy_version]['policy_groups'][t]:
                    self.interfaces[p] = {}

        # default to 'app'
        if 'type' not in self.snap_yaml:
            self.snap_yaml['type'] = 'app'

        if 'architectures' in self.snap_yaml:
            self.pkg_arch = self.snap_yaml['architectures']
        else:
            self.pkg_arch = ['all']

        self.is_snap_gadget = False
        if 'type' in self.snap_yaml and self.snap_yaml['type'] == 'gadget':
            self.is_snap_gadget = True

        # snapd understands:
        #   plugs:
        #     foo: null
        # but yaml.safe_load() treats 'null' as 'None', but we need a {}, so
        # we need to account for that.
        for k in ['plugs', 'slots']:
            if k not in self.snap_yaml:
                continue
            for iface in self.snap_yaml[k]:
                if self.snap_yaml[k][iface] is None:
                    self.snap_yaml[k][iface] = {}

    # Since coverage is looked at via the testsuite and the testsuite mocks
    # this out, don't cover this
    def _extract_snap_yaml(self):  # pragma: nocover
        '''Extract and read the snappy 16.04 snap.yaml'''
        y = os.path.join(self.unpack_dir, "meta/snap.yaml")
        if not os.path.isfile(y):
            error("Could not find snap.yaml.")
        return open_file_read(y)

    # Since coverage is looked at via the testsuite and the testsuite mocks
    # this out, don't cover this
    def _get_unpack_dir(self):  # pragma: nocover
        '''Get unpack directory'''
        return self.unpack_dir

    def _verify_pkgname(self, n):
        '''Verify package name'''
        pat = re.compile(r'^[a-z0-9][a-z0-9+-]+$')

        if pat.search(n):
            return True
        return False

    def _verify_appname(self, n):
        '''Verify app name'''
        pat = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9+-]+$')

        if pat.search(n):
            return True
        return False
