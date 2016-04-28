from clickreviews.sr_common import SnapReview

# TODO(matt): where shall I load this list from? is it going to take a long
# time and use a lot of memory?
blacklist = set([
    'blacklisted-name',
])

class SnapReviewBlacklist(SnapReview):

    def __init__(self, fn, overrides=None):
        # TODO(matt): is this a good name?
        SnapReview.__init__(self, fn, 'blacklist-snap', overrides=overrides)

    def check_package_name(self):
        '''Trigger a manual review if the package name is blacklisted'''
        # TODO(matt): is this correct?
        if not self.is_snap2:
            return

        n = self._get_check_name('name')
        snap_name = self.snap_yaml['name']
        if snap_name in blacklist:
            # TODO(matt): is this correct?
            s = "blacklisted name: '{}'".format(snap_name)
            self._add_result('error', n, s, manual_review=True)
        else:
            # TODO(matt): should I emit this or do we want to hide it for most people?
            self._add_result('info', n, 'OK')
