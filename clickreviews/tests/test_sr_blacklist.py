import clickreviews.sr_tests as sr_tests
from clickreviews.sr_blacklist import SnapReviewBlacklist


class TestSnapReviewLint(sr_tests.TestSnapReview):

    def make_patched_checker(self, test_name, blacklisted_names):
        c = SnapReviewBlacklist(test_name)
        c.blacklisted_names = blacklisted_names
        return c

    def test_loads_default_list(self):
        c = SnapReviewBlacklist(self.test_name)
        self.assertNotEqual(len(c.blacklisted_names), 0)

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
        blacklisted_names = ['blacklisted-1', 'blacklisted-2']
        for test_name in ['blacklisted-1', 'blacklisted-2']:
            self.set_test_snap_yaml("name", test_name)
            c = self.make_patched_checker(self.test_name, blacklisted_names)
            c.check_package_name()
            self.check_results(c.click_report, {'error': 1})
            self.assertEqual(
                c.click_report['error']['blacklist-snap:name']['text'],
                "blacklisted name: '{}'".format(test_name),
            )

    def test_package_name_manual_review(self):
        self.set_test_snap_yaml("name", "blacklisted-1")
        c = self.make_patched_checker(self.test_name, ['blacklisted-1'])
        c.check_package_name()
        self.check_manual_review(c.click_report, 'blacklist-snap:name')

    def test_package_name_whitelisted(self):
        self.set_test_snap_yaml("name", "not-blacklisted")
        c = self.make_patched_checker(self.test_name, ['blacklisted-1'])
        c.check_package_name()
        self.check_results(c.click_report, {'info': 1})

    def assert_report_has_results(self, report, expected):
        sum = 0
        for i in report:
            sum += len(report[i])
        self.assertEqual(sum != 0, expected)
