import clickreviews.sr_tests as sr_tests
from clickreviews.sr_blacklist import SnapReviewBlacklist


class TestSnapReviewLint(sr_tests.TestSnapReview):

    def test_all_checks_as_click(self):
        '''Test click format has no checks'''
        self.set_test_pkgfmt("click", "0.4")
        c = SnapReviewBlacklist(self.test_name)
        c.do_checks()
        self.assert_report_has_results(c.click_report, False)

    def test_all_checks_as_v1(self):
        '''Test snap v1 has no checks'''
        self.set_test_pkgfmt("snap", "15.04")
        c = SnapReviewBlacklist(self.test_name)
        c.do_checks()
        self.assert_report_has_results(c.click_report, False)

    def test_all_checks_as_v2(self):
        '''Test snap v2 has checks'''
        self.set_test_pkgfmt("snap", "16.04")
        c = SnapReviewBlacklist(self.test_name)
        c.do_checks()
        self.assert_report_has_results(c.click_report, True)

    def test_package_name_blacklisted(self):
        # TODO(matt): fix this name once we have a proper blacklist.
        self.set_test_snap_yaml("name", "blacklisted-name")
        c = SnapReviewBlacklist(self.test_name)
        c.check_package_name()
        self.check_results(c.click_report, {'error': 1})
        self.assertEqual(
            c.click_report['error']['blacklist-snap:name']['text'],
            "blacklisted name: 'blacklisted-name'",
        )

    def test_package_name_manual_review(self):
        # TODO(matt): fix this name once we have a proper blacklist.
        self.set_test_snap_yaml("name", "blacklisted-name")
        c = SnapReviewBlacklist(self.test_name)
        c.check_package_name()
        self.check_manual_review(c.click_report, 'blacklist-snap:name')

    def test_package_name_whitelisted(self):
        self.set_test_snap_yaml("name", "not-blacklisted")
        c = SnapReviewBlacklist(self.test_name)
        c.check_package_name()
        self.check_results(c.click_report, {'info': 1})

    def assert_report_has_results(self, report, expected):
        sum = 0
        for i in report:
            sum += len(report[i])
        self.assertEqual(sum != 0, expected)
