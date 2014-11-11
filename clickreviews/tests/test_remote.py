import time
from unittest import TestCase
from unittest.mock import patch

from clickreviews.remote import UPDATE_INTERVAL, _update_is_necessary


class RemoteTestCase(TestCase):
    def patch_path(self):
        p = patch('clickreviews.remote.os.path')
        self.mock_path = p.start()
        self.addCleanup(p.stop)

    def patch_time(self, now):
        p = patch('clickreviews.remote.time.time')
        self.mock_time = p.start()
        self.mock_time.return_value = now
        self.addCleanup(p.stop)

    def test_no_update_needed(self):
        now = time.time()
        self.patch_time(now)
        self.patch_path()

        # last update was 10 seconds ago
        self.mock_path.getmtime.return_value = now - 10

        self.assertFalse(_update_is_necessary('some-file'))

    def test_update_needed(self):
        now = time.time()
        self.patch_time(now)
        self.patch_path()

        # last update was UPDATE_INTERVAL + 10 seconds ago
        self.mock_path.getmtime.return_value = now - UPDATE_INTERVAL - 10

        self.assertTrue(_update_is_necessary('some-file'))
