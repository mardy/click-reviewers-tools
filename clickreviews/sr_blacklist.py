import pkgutil

from clickreviews.sr_common import SnapReview


def _load_blacklisted_names():
    blacklisted_names = pkgutil.get_data(
        'clickreviews', 'data/blacklist-snap-names')
    return set(blacklisted_names.decode('utf-8').splitlines())


class SnapReviewBlacklist(SnapReview):

    blacklisted_names = _load_blacklisted_names()

    def __init__(self, fn, overrides=None):
        SnapReview.__init__(self, fn, 'blacklist-snap', overrides=overrides)

    def check_package_name(self):
        '''Trigger a manual review if the package name is blacklisted'''
        if not self.is_snap2:
            return

        t = 'info'
        n = self._get_check_name('name')
        s = 'OK'
        m = False
        snap_name = self.snap_yaml['name']
        if snap_name in self.blacklisted_names:
            t = 'error'
            s = "blacklisted name: '{}'".format(snap_name)
            m = True
        self._add_result(t, n, s, manual_review=m)
