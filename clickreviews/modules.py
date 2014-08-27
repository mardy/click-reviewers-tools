import clickreviews
import imp
import inspect
import pkgutil

IRRELEVANT_MODULES = ['cr_common', 'cr_tests', 'cr_skeleton']


def get_modules():
    '''
    Here we have a look at all the modules in the
    clickreviews package and filter out a few which
    are not relevant.

    Basically we look at all the ones which are
    derived from cr_common, where we can later on
    instantiate a *Review* object and run the
    necessary checks.
    '''

    all_modules = [name for _, name, _ in
                   pkgutil.iter_modules(clickreviews.__path__)]
    narrow_down_modules = \
        lambda a: a.startswith('cr_') and \
        a not in IRRELEVANT_MODULES
    return list(filter(narrow_down_modules, all_modules))


def find_main_class(module_name):
    '''
    This function will find the Click*Review class in
    the specified module.
    '''
    module = imp.load_source(module_name,
                             '%s/%s.py' % (clickreviews.__path__[0],
                                           module_name))

    classes = inspect.getmembers(module, inspect.isclass)
    find_main_class = lambda a: a[0].startswith('Click') and \
        not a[0].endswith('Exception') and \
        a[1].__module__ == module_name
    main_class = list(filter(find_main_class, classes))
    init_object = getattr(module, main_class[0][0])
    return init_object


def init_main_class(module_name, click_file):
    '''
    This function will instantiate the main Click*Review
    class of a given module and instantiate it with the
    location of the .click file we want to inspect.
    '''

    init_object = find_main_class(module_name)
    return init_object(click_file)
