from clickreviews import modules, cr_tests
import clickreviews
import glob


class TestModules(cr_tests.TestClickReview):
    '''Tests for the modules module.'''
    def setUp(self):
        self.modules = modules.get_modules()
        super().setUp()

    def test_number_of_suitable_modules(self):
        path = clickreviews.__path__[0]
        module_files = glob.glob(path + '/*.py')
        relevant_module_files = modules.narrow_down_modules(module_files)
        self.assertEqual(len(relevant_module_files),
                         len(self.modules))

    def test_number_of_suitable_modules_greater0(self):
        self.assertTrue(len(self.modules) > 0)

    def test_number_of_available_review_classes(self):
        count = 0
        for module_name in self.modules:
            review = modules.find_main_class(module_name)
            if review:
                count += 1
        self.assertEqual(count, len(self.modules),
                         'Not all files in clickreviews/[cs]r_*.py contain '
                         'classes named Click|Snap*Review.')
