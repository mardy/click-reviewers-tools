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
        # TODO(matt): is this correct?
        if not self.is_snap2:
            return

        n = self._get_check_name('name')
        snap_name = self.snap_yaml['name']
        if snap_name in self.blacklisted_names:
            # TODO(matt): is this correct?
            s = "blacklisted name: '{}'".format(snap_name)
            self._add_result('error', n, s, manual_review=True)
        else:
            # TODO(matt): should I emit this or do we want to hide it for most people?
            self._add_result('info', n, 'OK')
