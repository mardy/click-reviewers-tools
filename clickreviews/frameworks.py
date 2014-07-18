"""
This file defines all known frameworks and their current status.
Frameworks are currenly tracked in: http://goo.gl/z9ohJ3
"""

import os
import clickreviews.remote

USER_DATA_FILE = os.path.join(clickreviews.remote.DATA_DIR, 'frameworks.json')

# XXX: This is a hack and will be gone, as soon as myapps has an API for this.
FRAMEWORKS_DATA_URL = \
    "http://bazaar.launchpad.net/~ubuntu-core-dev/+junk/frameworks/view/head:/frameworks.json"


def get_frameworks_file(fn):
    if fn is None:
        fn = USER_DATA_FILE
    clickreviews.remote.get_remote_file(fn, FRAMEWORKS_DATA_URL)


class Frameworks(object):
    DEPRECATED_FRAMEWORKS = []
    OBSOLETE_FRAMEWORKS = []
    AVAILABLE_FRAMEWORKS = []

    def __init__(self, local_copy_fn=None):
        self.FRAMEWORKS = clickreviews.remote.read_cr_file(USER_DATA_FILE,
                                                           FRAMEWORKS_DATA_URL,
                                                           local_copy_fn)

        for k, v in self.FRAMEWORKS.items():
            if v == 'deprecated':
                self.DEPRECATED_FRAMEWORKS.append(k)
            elif v == 'obsolete':
                self.OBSOLETE_FRAMEWORKS.append(k)
            elif v == 'available':
                self.AVAILABLE_FRAMEWORKS.append(k)
