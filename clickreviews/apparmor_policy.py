import os
import clickreviews.remote

USER_DATA_FILE = os.path.join(clickreviews.remote.DATA_DIR,
                              'apparmor-easyprof-ubuntu.json')

# XXX: This is a hack and will be gone, as soon as myapps has an API for this.
AA_POLICY_DATA_URL = \
    "http://bazaar.launchpad.net/~click-reviewers/click-reviewers-tools/trunk/view/head:/data/apparmor-easyprof-ubuntu.json"


def get_policy_file(fn):
    if fn is None:
        fn = USER_DATA_FILE
    clickreviews.remote.get_remote_file(fn, AA_POLICY_DATA_URL)


class ApparmorPolicy(object):
    def __init__(self, local_copy_fn=None):
        self.policy = clickreviews.remote.read_cr_file(USER_DATA_FILE,
                                                       AA_POLICY_DATA_URL,
                                                       local_copy_fn)
