from clickreviews.cr_common import ClickReview
from clickreviews import cr_tests


class ClickReviewTestCase(cr_tests.TestClickReview):

    def setUp(self):
        # Monkey patch various file access classes. stop() is handled with
        # addCleanup in super()
        cr_tests.mock_patch()
        super()
        self.review = ClickReview('app.click', 'review_type')

    def test_add_result_default_manual_review(self):
        self.review._add_result('info', 'some-check', 'OK')
        self.assertEqual(self.review.click_report, {
            'info': {
                'review_type_some-check': {
                    'text': 'OK',
                    'manual_review': False,
                }
            },
            'warn': {},
            'error': {},
        })

    def test_add_result_custom_manual_review(self):
        self.review._add_result('info', 'some-check', 'OK',
                                manual_review=True)
        self.assertEqual(self.review.click_report, {
            'info': {
                'review_type_some-check': {
                    'text': 'OK',
                    'manual_review': True,
                }
            },
            'warn': {},
            'error': {},
        })
